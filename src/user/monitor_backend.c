#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <time.h>
#include <fcntl.h>        
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sqlite3.h>

#define POLL_INTERVAL_SEC 2
#define COMM_MAX_LEN 16
#define KERNEL_4_1_0_THRESHOLD 262400
#define DB_NAME "data/system_monitor.db"

#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_DIM     "\033[2m"
#define CLR_CRIT    "\033[1;31m" 
#define CLR_WARN    "\033[1;33m" 

struct flow_key_t { __u32 saddr; __u32 daddr; __u16 sport; __u16 dport; __u32 pid; };
struct flow_stats_t { char comm[16]; __u64 first_seen_ns; __u64 last_seen_ns; __u64 tx_packets; __u64 rx_packets; };
struct priv_esc_key_t { __u32 pid; };
struct priv_esc_stats_t { char comm[16]; __u32 old_uid; __u32 new_uid; __u64 first_seen_ns; __u64 last_seen_ns; __u64 escalation_count; };
struct write_key_t { __u32 pid; __u32 fd; };
struct write_stats_t { char comm[16]; __u64 first_seen_ns; __u64 last_seen_ns; __u64 write_calls; __u64 bytes_written; };

static unsigned long long boot_time_ns = 0; 
static volatile bool exiting = false;

void sig_handler(int sig) { exiting = true; }

static void int_to_ip(__u32 ip_int, char *buffer) {
    struct in_addr ip_addr; ip_addr.s_addr = ip_int;
    inet_ntop(AF_INET, &ip_addr, buffer, INET_ADDRSTRLEN);
}

sqlite3* init_database() {
    sqlite3 *db;
    if (sqlite3_open(DB_NAME, &db) != SQLITE_OK) return NULL;

    const char *sql_pragma = 
        "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; "
        "PRAGMA temp_store = MEMORY; PRAGMA mmap_size = 268435456; "
        "PRAGMA cache_size = -64000;";
    sqlite3_exec(db, sql_pragma, 0, 0, NULL);

    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS udp_flows (pid INTEGER, comm TEXT, local_ip TEXT, local_port INTEGER, remote_ip TEXT, remote_port INTEGER, tx_packets INTEGER, rx_packets INTEGER, first_seen INTEGER, last_seen INTEGER, PRIMARY KEY (pid, local_ip, local_port, remote_ip, remote_port)) WITHOUT ROWID;", 0, 0, NULL);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS priv_esc (pid INTEGER PRIMARY KEY, comm TEXT, old_uid INTEGER, new_uid INTEGER, escalation_count INTEGER, first_seen INTEGER, last_seen INTEGER) WITHOUT ROWID;", 0, 0, NULL);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS file_writes (pid INTEGER, comm TEXT, fd INTEGER, write_calls INTEGER, bytes_written INTEGER, first_seen INTEGER, last_seen INTEGER, PRIMARY KEY (pid, fd)) WITHOUT ROWID;", 0, 0, NULL);
    
    return db;
}

void process_data(struct bpf_object *obj, sqlite3 *db) {
    sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    // 1. Process UDP Flows
    int map_fd = bpf_object__find_map_fd_by_name(obj, "flow_stats");
    if (map_fd >= 0) {
        struct flow_key_t f_key = {}, f_next; struct flow_stats_t f_val;
        sqlite3_stmt *stmt;
        const char *udp_sql = "INSERT INTO udp_flows (pid, comm, local_ip, local_port, remote_ip, remote_port, tx_packets, rx_packets, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(pid, local_ip, local_port, remote_ip, remote_port) DO UPDATE SET tx_packets=udp_flows.tx_packets + excluded.tx_packets, rx_packets=udp_flows.rx_packets + excluded.rx_packets, last_seen=excluded.last_seen;";
        
        if (sqlite3_prepare_v2(db, udp_sql, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "[SQL ERR] UDP Flows: %s\n", sqlite3_errmsg(db));
        } else {
            while (bpf_map_get_next_key(map_fd, &f_key, &f_next) == 0) {
                if (bpf_map_lookup_elem(map_fd, &f_next, &f_val) == 0) {
                    bpf_map_delete_elem(map_fd, &f_next);
                    f_val.comm[COMM_MAX_LEN - 1] = '\0';
                    sqlite3_bind_int(stmt, 1, f_next.pid); sqlite3_bind_text(stmt, 2, f_val.comm, -1, SQLITE_TRANSIENT);
                    char l_ip[INET_ADDRSTRLEN], r_ip[INET_ADDRSTRLEN];
                    int_to_ip(f_next.saddr, l_ip); int_to_ip(f_next.daddr, r_ip);
                    sqlite3_bind_text(stmt, 3, l_ip, -1, SQLITE_TRANSIENT); sqlite3_bind_int(stmt, 4, f_next.sport);
                    sqlite3_bind_text(stmt, 5, r_ip, -1, SQLITE_TRANSIENT); sqlite3_bind_int(stmt, 6, f_next.dport);
                    sqlite3_bind_int64(stmt, 7, f_val.tx_packets); sqlite3_bind_int64(stmt, 8, f_val.rx_packets);
                    sqlite3_bind_int64(stmt, 9, (boot_time_ns + f_val.first_seen_ns) / 1000000ULL); sqlite3_bind_int64(stmt, 10, (boot_time_ns + f_val.last_seen_ns) / 1000000ULL);
                    sqlite3_step(stmt); sqlite3_reset(stmt);
                }
                f_key = f_next;
            }
            sqlite3_finalize(stmt);
        }
    }

    // 2. Process File Writes
    map_fd = bpf_object__find_map_fd_by_name(obj, "write_stats");
    if (map_fd >= 0) {
        struct write_key_t w_key = {}, w_next; struct write_stats_t w_val;
        sqlite3_stmt *stmt;
        const char *wr_sql = "INSERT INTO file_writes (pid, comm, fd, write_calls, bytes_written, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(pid, fd) DO UPDATE SET write_calls=file_writes.write_calls + excluded.write_calls, bytes_written=file_writes.bytes_written + excluded.bytes_written, last_seen=excluded.last_seen;";
        
        if (sqlite3_prepare_v2(db, wr_sql, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "[SQL ERR] File Writes: %s\n", sqlite3_errmsg(db));
        } else {
            while (bpf_map_get_next_key(map_fd, &w_key, &w_next) == 0) {
                if (bpf_map_lookup_elem(map_fd, &w_next, &w_val) == 0) {
                    bpf_map_delete_elem(map_fd, &w_next);
                    w_val.comm[COMM_MAX_LEN - 1] = '\0';
                    sqlite3_bind_int(stmt, 1, w_next.pid); sqlite3_bind_text(stmt, 2, w_val.comm, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int(stmt, 3, w_next.fd); sqlite3_bind_int64(stmt, 4, w_val.write_calls);
                    sqlite3_bind_int64(stmt, 5, w_val.bytes_written);
                    sqlite3_bind_int64(stmt, 6, (boot_time_ns + w_val.first_seen_ns) / 1000000ULL); sqlite3_bind_int64(stmt, 7, (boot_time_ns + w_val.last_seen_ns) / 1000000ULL);
                    sqlite3_step(stmt); sqlite3_reset(stmt);
                }
                w_key = w_next;
            }
            sqlite3_finalize(stmt);
        }
    }

    // 3. Process Priv Escalations
    map_fd = bpf_object__find_map_fd_by_name(obj, "priv_stats");
    if (map_fd >= 0) {
        struct priv_esc_key_t p_key = {}, p_next; struct priv_esc_stats_t p_val;
        sqlite3_stmt *stmt;
        const char *pr_sql = "INSERT INTO priv_esc (pid, comm, old_uid, new_uid, escalation_count, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(pid) DO UPDATE SET escalation_count=priv_esc.escalation_count + excluded.escalation_count, new_uid=excluded.new_uid, last_seen=excluded.last_seen;";
        
        if (sqlite3_prepare_v2(db, pr_sql, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "[SQL ERR] Priv Esc: %s\n", sqlite3_errmsg(db));
        } else {
            while (bpf_map_get_next_key(map_fd, &p_key, &p_next) == 0) {
                if (bpf_map_lookup_elem(map_fd, &p_next, &p_val) == 0) {
                    bpf_map_delete_elem(map_fd, &p_next);
                    p_val.comm[COMM_MAX_LEN - 1] = '\0';
                    
                    time_t curr = time(NULL); char t_str[26]; strftime(t_str, 26, "%H:%M:%S", localtime(&curr));
                    if (p_val.new_uid == 0) printf("%s[%s] ROOT ESCALATION%s PID: %u | %s | UID: %u->%u\n", CLR_CRIT, t_str, CLR_RESET, p_next.pid, p_val.comm, p_val.old_uid, p_val.new_uid);
                    
                    sqlite3_bind_int(stmt, 1, p_next.pid); sqlite3_bind_text(stmt, 2, p_val.comm, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int(stmt, 3, p_val.old_uid); sqlite3_bind_int(stmt, 4, p_val.new_uid);
                    sqlite3_bind_int64(stmt, 5, p_val.escalation_count);
                    sqlite3_bind_int64(stmt, 6, (boot_time_ns + p_val.first_seen_ns) / 1000000ULL); sqlite3_bind_int64(stmt, 7, (boot_time_ns + p_val.last_seen_ns) / 1000000ULL);
                    sqlite3_step(stmt); sqlite3_reset(stmt);
                }
                p_key = p_next;
            }
            sqlite3_finalize(stmt);
        }
    }
    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
}
int main() {
    setenv("TZ", "Asia/Kolkata", 1); tzset();
    struct bpf_object *obj; struct bpf_link *links[6] = {NULL}; 
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    
    sqlite3 *db = init_database(); if (!db) return 1;

    struct timespec ts_real, ts_mono;
    clock_gettime(CLOCK_REALTIME, &ts_real); clock_gettime(CLOCK_MONOTONIC, &ts_mono);
    boot_time_ns = ((unsigned long long)ts_real.tv_sec * 1000000000ULL + ts_real.tv_nsec) - ((unsigned long long)ts_mono.tv_sec * 1000000000ULL + ts_mono.tv_nsec); 

    struct rlimit rlim = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY }; setrlimit(RLIMIT_MEMLOCK, &rlim);

    struct utsname buf; uname(&buf); int maj = 0, min = 0, patch = 0; sscanf(buf.release, "%d.%d.%d", &maj, &min, &patch);
    bool is_legacy = ((maj << 16) + (min << 8) + patch) < KERNEL_4_1_0_THRESHOLD;
    
    obj = (access("/sys/kernel/btf/vmlinux", F_OK) == 0) ? bpf_object__open_file("bin/monitor_kern.o", NULL) : NULL; // Add custom BTF logic if needed here
    if (!obj || bpf_object__load(obj)) { sqlite3_close(db); return 1; }

    printf("%s[INFO]%s Unified eBPF System Monitor Loading...\n", CLR_BOLD, CLR_RESET);

    // Attach Networking Probes with strict error checking
    const char *tx_n = is_legacy ? "kprobe_udp_sendmsg_legacy" : "kprobe_udp_sendmsg";
    const char *rx_n = is_legacy ? "kprobe_udp_recvmsg_legacy" : "kprobe_udp_recvmsg";
    
    links[0] = bpf_program__attach_kprobe(bpf_object__find_program_by_name(obj, tx_n), false, "udp_sendmsg");
    if (libbpf_get_error(links[0])) fprintf(stderr, "[ERR] Failed to attach: %s\n", tx_n);

    links[1] = bpf_program__attach_kprobe(bpf_object__find_program_by_name(obj, rx_n), false, "udp_recvmsg");
    if (libbpf_get_error(links[1])) fprintf(stderr, "[ERR] Failed to attach: %s\n", rx_n);

    links[2] = bpf_program__attach_kprobe(bpf_object__find_program_by_name(obj, "kretprobe_udp_recvmsg"), true, "udp_recvmsg");
    if (libbpf_get_error(links[2])) fprintf(stderr, "[ERR] Failed to attach: kretprobe_udp_recvmsg\n");

    links[3] = bpf_program__attach_kprobe(bpf_object__find_program_by_name(obj, "kprobe_dev_queue_xmit"), false, "__dev_queue_xmit");
    if (libbpf_get_error(links[3])) fprintf(stderr, "[ERR] Failed to attach: __dev_queue_xmit\n");
    
    // Attach Security & IO Probes with strict error checking
    links[4] = bpf_program__attach_kprobe(bpf_object__find_program_by_name(obj, "kprobe_commit_creds"), false, "commit_creds");
    if (libbpf_get_error(links[4])) fprintf(stderr, "[ERR] Failed to attach: commit_creds\n");

    links[5] = bpf_program__attach(bpf_object__find_program_by_name(obj, "tp_sys_enter_write"));
    if (libbpf_get_error(links[5])) fprintf(stderr, "[ERR] Failed to attach tracepoint: sys_enter_write\n");


    printf("%s>>> SUCCESS: MONITOR RUNNING (Press Ctrl+C to exit) <<<%s\n\n", CLR_BOLD, CLR_RESET);

    while (!exiting) {
        process_data(obj, db);
        sleep(POLL_INTERVAL_SEC); 
    }

    printf("\nCleaning up...\n");
    for (int i = 0; i < 6; i++) if (links[i]) bpf_link__destroy(links[i]);
    if (obj) bpf_object__close(obj);
    if (db) sqlite3_close(db); 
    return 0;
}