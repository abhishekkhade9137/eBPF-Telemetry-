CLANG    ?= clang
GCC      ?= gcc
PKG_CONF ?= pkg-config

UNAME_ARCH := $(shell uname -m)

ifeq ($(UNAME_ARCH),x86_64)
    BPF_ARCH := x86
else ifeq ($(UNAME_ARCH),aarch64)
    BPF_ARCH := arm64
else
    BPF_ARCH := $(UNAME_ARCH)
endif

MULTIARCH := $(shell $(GCC) -print-multiarch 2>/dev/null)
ifneq ($(MULTIARCH),)
    KERN_INC := -I/usr/include/$(MULTIARCH)
else
    KERN_INC := -I/usr/include
endif

# ==========================================
# LINKAGE SELECTOR (Dynamic vs Full Static)
# ==========================================
LINK ?= dynamic

ifeq ($(LINK),static)
    STATIC_FLAG    := -static
    LIBBPF_LDFLAGS := -lbpf -lelf -lz
    SQLITE_LDFLAGS := -lsqlite3 -lpthread -ldl -lm 
    LINK_MODE_MSG  := [FULL STATIC] Baked glibc and all dependencies directly into binary.
else
    STATIC_FLAG    := 
    LIBBPF_LDFLAGS := $(shell $(PKG_CONF) --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")
    SQLITE_LDFLAGS := -lsqlite3
    LINK_MODE_MSG  := [DYNAMIC] Linked against system .so libraries.
endif

# --- eBPF & User Loader Flags ---
LIBBPF_CFLAGS := $(shell $(PKG_CONF) --cflags libbpf 2>/dev/null || echo "")

BPF_CFLAGS := \
    -O2 -g \
    -target bpf \
    -D__TARGET_ARCH_$(BPF_ARCH) \
    -I/usr/include \
    $(KERN_INC)

USR_CFLAGS := -O2 -Wall -Wextra -Wno-unused-parameter $(LIBBPF_CFLAGS)
USR_LDFLAGS := $(STATIC_FLAG) $(LIBBPF_LDFLAGS) $(SQLITE_LDFLAGS)

# --- File Targets ---
BPF_OBJ     := bin/monitor_kern.o
USER_BIN    := bin/monitor_backend
DB_FILE     := data/system_monitor.db

.PHONY: all clean run check-deps app cleardb viewdb trace export vmlinux static dirs

all: check-deps dirs $(BPF_OBJ) $(USER_BIN)

static:
	@echo "[BUILD] Initiating FULL STATIC build sequence..."
	$(MAKE) LINK=static all

dirs:
	@mkdir -p bin data

check-deps:
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "[error] clang not found."; exit 1; }
	@$(PKG_CONF) libbpf >/dev/null 2>&1 || { echo "[error] libbpf not found."; exit 1; }
	@echo "[ok] All dependencies found."

# --- Build Rules ---
$(BPF_OBJ): src/kern/monitor_kern.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[ok] Compiled kernel payload: $(BPF_OBJ)"

$(USER_BIN): src/user/monitor_backend.c
	$(GCC) $(USR_CFLAGS) $< -o $@ $(USR_LDFLAGS)
	@echo "[ok] Compiled eBPF loader: $(USER_BIN) -> $(LINK_MODE_MSG)"

# --- Execution Commands ---
run: all
	@echo "[INIT] Executing eBPF backend as root..."
	sudo ./$(USER_BIN)

app:
	@echo "[LAUNCH] Starting Standalone Desktop App (direct SQLite access)..."
	@command -v npm >/dev/null 2>&1 || { echo "[ERROR] npm not found. Run: sudo apt install -y nodejs npm"; exit 1; }
	@cd src/ui/desktop_app && npm install && npx @electron/rebuild -f -w better-sqlite3 && npx electron . --no-sandbox

cleardb:
	@echo "[CLEAN] Wiping SQLite database and WAL files..."
	rm -f $(DB_FILE) $(DB_FILE)-journal $(DB_FILE)-wal $(DB_FILE)-shm
	@echo "[ok] Database erased. It will be recreated automatically."

viewdb:
	@if [ -f $(DB_FILE) ]; then \
	sqlite3 -header -column $(DB_FILE) \
	"SELECT pid, comm, tx_packets, rx_packets FROM udp_flows ORDER BY (tx_packets + rx_packets) DESC LIMIT 15;"; \
	else \
	echo "[error] Database does not exist yet."; \
	fi

export:
	@if [ -f $(DB_FILE) ]; then \
	sqlite3 -header -csv $(DB_FILE) "SELECT * FROM udp_flows;" > udp_flows_dump.csv; \
	sqlite3 -header -csv $(DB_FILE) "SELECT * FROM file_writes;" > file_writes_dump.csv; \
	sqlite3 -header -csv $(DB_FILE) "SELECT * FROM priv_esc;" > priv_esc_dump.csv; \
	echo "[ok] Exported all tables to CSV files."; \
	fi

trace:
	@echo "[DEBUG] Tailing live kernel trace pipe. Press Ctrl+C to stop..."
	@sudo cat /sys/kernel/debug/tracing/trace_pipe

vmlinux: dirs
	@echo "[BTF] Generating local vmlinux.h from current kernel..."
	@command -v bpftool >/dev/null 2>&1 || { echo "[error] bpftool not found. Run: sudo apt install linux-tools-common linux-tools-generic"; exit 1; }
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
	@echo "[ok] Local vmlinux.h generated successfully."

clean:
	@echo "[CLEAN] Removing compiled binaries..."
	rm -rf bin/*
	@echo "[ok] Workspace cleaned. (Note: Run 'make cleardb' to erase database)"
