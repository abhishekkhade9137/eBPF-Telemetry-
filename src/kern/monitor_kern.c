#include "../../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define MAX_TRACKED_FLOWS 10240
#define MAX_TRACKED_PROCS 10240

/* ==================== 1. NETWORK FLOW DATA ==================== */
struct flow_key_t {
    __u32 saddr; __u32 daddr;
    __u16 sport; __u16 dport;
    __u32 pid; 
};

struct flow_stats_t {
    char comm[16];
    __u64 first_seen_ns; __u64 last_seen_ns;
    __u64 tx_packets; __u64 rx_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_FLOWS);
    __type(key, struct flow_key_t);
    __type(value, struct flow_stats_t);
} flow_stats SEC(".maps");

struct rx_args_t {
    struct sock *sk; struct msghdr *msg; __u64 ts_ns; 
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_FLOWS);
    __type(key, __u32);
    __type(value, struct rx_args_t);
} rx_tracking SEC(".maps");

/* ==================== 2. PRIVILEGE DATA ==================== */
struct priv_esc_key_t { __u32 pid; };

struct priv_esc_stats_t {
    char comm[16];
    __u32 old_uid; __u32 new_uid;
    __u64 first_seen_ns; __u64 last_seen_ns;
    __u64 escalation_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_PROCS);
    __type(key, struct priv_esc_key_t);
    __type(value, struct priv_esc_stats_t);
} priv_stats SEC(".maps");

/* ==================== 3. FILE I/O DATA ==================== */
struct write_key_t { __u32 pid; __u32 fd; };

struct write_stats_t {
    char comm[16];
    __u64 first_seen_ns; __u64 last_seen_ns;
    __u64 write_calls; __u64 bytes_written;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_FLOWS);
    __type(key, struct write_key_t);
    __type(value, struct write_stats_t);
} write_stats SEC(".maps");


/* ==================== NETWORK HELPERS & PROBES ==================== */
static __always_inline void update_flow_stats(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport, __u64 packet_ts, int is_tx) {
    __u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    struct flow_key_t key = { .saddr = saddr, .daddr = daddr, .sport = sport, .dport = dport, .pid = current_pid };
    struct flow_stats_t *val = bpf_map_lookup_elem(&flow_stats, &key);
    
    if (val) {
        val->last_seen_ns = packet_ts;
        if (is_tx) __sync_fetch_and_add(&val->tx_packets, 1);
        else __sync_fetch_and_add(&val->rx_packets, 1);
    } else {
        struct flow_stats_t new_val = {};
        new_val.first_seen_ns = packet_ts; new_val.last_seen_ns = packet_ts;
        if (is_tx) new_val.tx_packets = 1; else new_val.rx_packets = 1;
        bpf_get_current_comm(new_val.comm, sizeof(new_val.comm));
        bpf_map_update_elem(&flow_stats, &key, &new_val, BPF_ANY);
    }
}

static __always_inline int handle_tx(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    if (!sk) return 0;
    __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u32 daddr; __u16 dport;

    void *msg_name = BPF_CORE_READ(msg, msg_name);
    if (msg_name) {
        struct sockaddr_in *sa = (struct sockaddr_in *)msg_name;
        daddr = BPF_CORE_READ(sa, sin_addr.s_addr);
        dport = bpf_ntohs(BPF_CORE_READ(sa, sin_port));
    } else {
        daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    }
    update_flow_stats(saddr, sport, daddr, dport, bpf_ktime_get_ns(), 1);
    return 0;
}

SEC("kprobe/udp_sendmsg_legacy")
int kprobe_udp_sendmsg_legacy(struct pt_regs *ctx) { return handle_tx(ctx, (struct sock *)PT_REGS_PARM2_CORE(ctx), (struct msghdr *)PT_REGS_PARM3_CORE(ctx)); }

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) { return handle_tx(ctx, (struct sock *)PT_REGS_PARM1_CORE(ctx), (struct msghdr *)PT_REGS_PARM2_CORE(ctx)); }

SEC("kprobe/__dev_queue_xmit") 
int kprobe_dev_queue_xmit(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1_CORE(ctx);
    if (!skb) return 0;
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 network_header = BPF_CORE_READ(skb, network_header);
    struct iphdr iph;
    if (bpf_core_read(&iph, sizeof(iph), head + network_header) < 0) return 0;
    if (iph.protocol != IPPROTO_UDP) return 0;
    struct udphdr udph;
    if (bpf_core_read(&udph, sizeof(udph), head + network_header + (iph.ihl * 4)) < 0) return 0;
    
    __u16 sport = bpf_ntohs(udph.source);
    __u16 dport = bpf_ntohs(udph.dest);
    update_flow_stats(iph.saddr, sport, iph.daddr, dport, bpf_ktime_get_ns(), 1);
    return 0;
}

static __always_inline int handle_rx_entry(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid(); 
    struct rx_args_t args = { .sk = sk, .msg = msg, .ts_ns = bpf_ktime_get_ns() };
    bpf_map_update_elem(&rx_tracking, &tid, &args, BPF_ANY);
    return 0;
}

SEC("kprobe/udp_recvmsg_legacy")
int kprobe_udp_recvmsg_legacy(struct pt_regs *ctx) { return handle_rx_entry(ctx, (struct sock *)PT_REGS_PARM2_CORE(ctx), (struct msghdr *)PT_REGS_PARM3_CORE(ctx)); }

SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(struct pt_regs *ctx) { return handle_rx_entry(ctx, (struct sock *)PT_REGS_PARM1_CORE(ctx), (struct msghdr *)PT_REGS_PARM2_CORE(ctx)); }

SEC("kretprobe/udp_recvmsg")
int kretprobe_udp_recvmsg(struct pt_regs *ctx) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct rx_args_t *args = bpf_map_lookup_elem(&rx_tracking, &tid);
    if (!args) return 0;
    struct sock *sk = args->sk; struct msghdr *msg = args->msg; __u64 arrival_ts = args->ts_ns; 
    bpf_map_delete_elem(&rx_tracking, &tid);

    if ((int)PT_REGS_RC_CORE(ctx) < 0 || !sk) return 0;
    __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u32 daddr; __u16 dport;
    void *msg_name = BPF_CORE_READ(msg, msg_name);
    if (msg_name) {
        struct sockaddr_in *sa = (struct sockaddr_in *)msg_name;
        daddr = BPF_CORE_READ(sa, sin_addr.s_addr); dport = bpf_ntohs(BPF_CORE_READ(sa, sin_port));
    } else {
        daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr); dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    }
    update_flow_stats(saddr, sport, daddr, dport, arrival_ts, 0);
    return 0;
}

/* ==================== PRIVILEGE PROBE ==================== */
SEC("kprobe/commit_creds")
int kprobe_commit_creds(struct pt_regs *ctx) {
    struct cred *new_cred = (struct cred *)PT_REGS_PARM1_CORE(ctx);
    if (!new_cred) return 0;
    __u32 old_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 new_uid = BPF_CORE_READ(new_cred, uid.val);
    if (old_uid == new_uid) return 0;

    struct priv_esc_key_t key = { .pid = bpf_get_current_pid_tgid() >> 32 };
    struct priv_esc_stats_t *val = bpf_map_lookup_elem(&priv_stats, &key);
    __u64 now = bpf_ktime_get_ns();

    if (val) {
        val->last_seen_ns = now; val->new_uid = new_uid; 
        __sync_fetch_and_add(&val->escalation_count, 1);
    } else {
        struct priv_esc_stats_t new_val = { .old_uid = old_uid, .new_uid = new_uid, .first_seen_ns = now, .last_seen_ns = now, .escalation_count = 1 };
        bpf_get_current_comm(new_val.comm, sizeof(new_val.comm));
        bpf_map_update_elem(&priv_stats, &key, &new_val, BPF_ANY);
    }
    return 0;
}

/* ==================== FILE I/O PROBE ==================== */
SEC("tracepoint/syscalls/sys_enter_write")
int tp_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    struct write_key_t key = { .pid = bpf_get_current_pid_tgid() >> 32, .fd = (unsigned int)ctx->args[0] };
    struct write_stats_t *val = bpf_map_lookup_elem(&write_stats, &key);
    __u64 now = bpf_ktime_get_ns();
    
    if (val) {
        val->last_seen_ns = now;
        __sync_fetch_and_add(&val->write_calls, 1);
        __sync_fetch_and_add(&val->bytes_written, (size_t)ctx->args[2]);
    } else {
        struct write_stats_t new_val = { .first_seen_ns = now, .last_seen_ns = now, .write_calls = 1, .bytes_written = (size_t)ctx->args[2] };
        bpf_get_current_comm(new_val.comm, sizeof(new_val.comm));
        bpf_map_update_elem(&write_stats, &key, &new_val, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";