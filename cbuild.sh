#!/bin/sh
set -e

CC="${CC:-cc}"
STRIP="${STRIP:-strip}"
CFLAGS="${CFLAGS:=-O2 -Wall -Wextra -pedantic -static-pie -static}"
BASE="$(cd "$(dirname "$0")" && pwd)"
BIN="$BASE/build"
SRC="$BASE/src"

export CFLAGS

# Parse verbosity flag
VERBOSITY=0
case "${1:-}" in
    -vvv) VERBOSITY=3; shift ;;
    -vv)  VERBOSITY=2; shift ;;
    -v)   VERBOSITY=1; shift ;;
esac

# Temp directory for intermediate files
TMPDIR="$BASE/.build_tmp.$$"
mkdir -p "$TMPDIR"

# Cleanup trap
cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

# Simple log functions
log() { printf "\033[34m->\033[0m %s\n" "$@"; }
ok() { printf "\033[32m=>\033[0m %s\n" "$@"; }
die() { printf "\033[31m!>\033[0m %s\n" "$@"; exit 1; }

# Execute command with verbosity handling
exec_filtered() {
    if [ $VERBOSITY -eq 0 ]; then
        "$@" >/dev/null 2>&1
    elif [ $VERBOSITY -eq 1 ]; then
        "$@" 2>&1 | grep -v -e ': warning:' -e ': note:' || true
    elif [ $VERBOSITY -eq 2 ]; then
        "$@" 2>&1 | grep -v -e ': note:' || true
    else
        "$@"
    fi
}

# SUID Manifest
MANIFEST_SUID="
/bin/login:ubase
/bin/su:ubase
/bin/ping:busybox
/bin/ping6:busybox
/bin/traceroute:busybox
/bin/traceroute6:busybox
/bin/passwd:toybox
"

# Tool manifest: path[:alias_path]...:category
MANIFEST="
# ===== Core POSIX =====
/bin/cat:sbase
/bin/cp:sbase
/bin/mv:sbase
/bin/rm:sbase
/bin/mkdir:sbase
/bin/ln:busybox
/bin/rmdir:sbase
/bin/echo:sbase
/bin/printf:sbase
/bin/ls:toybox
/bin/pwd:sbase
/bin/chmod:sbase
/bin/chown:sbase
/bin/date:sbase
/bin/touch:sbase
/bin/du:sbase
/bin/basename:sbase
/bin/dirname:sbase
/bin/tee:sbase
/bin/test:/bin/[:sbase
/bin/true:sbase
/bin/false:sbase
/bin/env:sbase
/bin/which:sbase
/bin/yes:sbase
/bin/wc:sbase
/bin/tr:sbase
/bin/uniq:sbase
/bin/nl:sbase
/bin/paste:sbase
/bin/join:sbase
/bin/fold:sbase
/bin/expand:sbase
/bin/unexpand:sbase
# ===== System / Privileged =====
/bin/mount:ubase
/bin/umount:ubase
/bin/dmesg:ubase
/bin/login:ubase
/bin/su:ubase
/bin/pivot_root:ubase
/bin/switch_root:ubase
/bin/halt:ubase
/bin/getty:busybox
# ===== Cron / users =====
/bin/crond:toybox
/bin/crontab:toybox
/bin/chsh:toybox
/bin/useradd:toybox
/bin/userdel:toybox
/bin/groupadd:toybox
/bin/groupdel:toybox
# ===== Shell / Core OS =====
/bin/ash:/bin/sh:busybox
/bin/vi:busybox
/bin/depmod:busybox
/bin/poweroff:busybox
/bin/ps:toybox
/bin/kill:toybox
/bin/top:toybox
/bin/watch:toybox
/bin/df:toybox
/bin/free:toybox
/bin/uptime:toybox
/bin/clear:toybox
/bin/reset:toybox
/bin/sync:toybox
/bin/sleep:toybox
/bin/timeout:toybox
/bin/stat:toybox
/bin/tty:toybox
/bin/setsid:toybox
/bin/reboot:busybox
/bin/modprobe:toybox
/bin/insmod:toybox
/bin/rmmod:toybox
/bin/lsmod:toybox
# ===== Networking =====
/bin/ip:busybox
/bin/ifconfig:busybox
/bin/route:busybox
/bin/ping:busybox
/bin/netstat:busybox
/bin/nc:busybox
/bin/ftpget:busybox
/bin/ftpput:busybox
/bin/hostname:toybox
/bin/wget:busybox
/bin/udhcpd:busybox
/bin/udhcpc:busybox
/bin/udhcpc6:busybox
/bin/dhcprelay:busybox
# ===== Build / Text / Archive / FS =====
/bin/grep:toybox
/bin/awk:toybox
/bin/sed:toybox
/bin/find:toybox
/bin/cut:toybox
/bin/sort:toybox
/bin/head:toybox
/bin/tail:toybox
/bin/xargs:toybox
/bin/patch:toybox
/bin/diff:busybox
/bin/file:toybox
/bin/strings:toybox
/bin/time:toybox
/bin/realpath:toybox
/bin/readlink:toybox
/bin/install:toybox
/bin/cksum:sbase
/bin/md5sum:sbase
/bin/sha1sum:sbase
/bin/sha224sum:sbase
/bin/sha256sum:sbase
/bin/sha384sum:sbase
/bin/sha512-224sum:sbase
/bin/sha512-256sum:sbase
/bin/sha512sum:sbase
# ===== Archive / Compression =====
# - archivers -
/bin/cpio:toybox
/bin/tar:busybox
#/bin/ar:busybox
# - gz -
/bin/gzip:busybox
/bin/gunzip:busybox
/bin/zcat:busybox
# - bz -
/bin/bzip2:busybox
/bin/bunzip2:busybox
/bin/bzcat:busybox
# - xz -
/bin/xz:busybox
/bin/unxz:busybox
/bin/xzcat:busybox
# - lz -
/bin/lzma:busybox
/bin/unlzma:busybox
/bin/lzcat:busybox
/bin/lzop:busybox
# - zip -
/bin/unzip:busybox
"

get_tools() {
    echo "$MANIFEST" | awk -F: -v cat="$1" '$NF == cat {print $1}'
}

check_collisions() {
    log "Checking for duplicate tool names"
    seen=""
    echo "$MANIFEST" | while IFS=: read -r path rest; do
        [ -z "$path" ] && continue
        case "$path" in \#*|" "*) continue ;; esac
        name=$(basename "$path")
        case " $seen " in *" $name "*) die "Collision detected: $name" ;; esac
        seen="$seen $name"
        remaining="$rest"
        while echo "$remaining" | grep -q "/"; do
            alias_path=$(echo "$remaining" | cut -d: -f1)
            alias_name=$(basename "$alias_path")
            case " $seen " in *" $alias_name "*) die "Collision detected: $alias_name" ;; esac
            seen="$seen $alias_name"
            remaining=$(echo "$remaining" | cut -d: -f2-)
        done
    done
    ok "No name collisions detected"
}

build_suckless() {
    proj="$1"
    log "Building $proj"
    cd "$SRC/$proj"
    [ -f .built ] && return 0
    [ -f config.def.h ] && [ ! -f config.h ] && cp config.def.h config.h

    for lib in libutil libutf; do
        [ ! -d "$lib" ] && continue
        for src in "$lib"/*.c; do
            [ ! -f "$src" ] && continue
            obj="lib_$(basename "${src%.c}").o"
            exec_filtered $CC -c "$src" -o "$obj" $CFLAGS -I.
        done
    done

    tools=$(get_tools "$proj")
    for path in $tools; do
        tool=$(basename "$path")
        [ ! -f "$tool.c" ] && continue
        func=$(echo "$tool" | sed 's/[-.]/_/g')
        sed "s/^main(/${func}_main(/" "$tool.c" > "$TMPDIR/${tool}_tmp.c"
        exec_filtered $CC -c "$TMPDIR/${tool}_tmp.c" -o "tool_$tool.o" $CFLAGS -I.
    done

    touch .built
    ok "$proj built"
}

cfg() {
    case $1 in
        *=*) k=${1%%=*}; v=${1#*=} ;;
        *)   k=$1; v=y ;;
    esac
    case $v in
        \"*\") ;;
        */*) v=\""$v"\" ;;
    esac
    sed -i "
        s|^# CONFIG_$k is not set\$|CONFIG_$k=$v|
        s|^CONFIG_$k=.*|CONFIG_$k=$v|
    " .config
}

build_busybox() {
    log "Building Busybox"
    cd "$SRC/busybox"
    [ -f .built ] && return 0
    exec_filtered make allnoconfig

    export HOSTLDFLAGS="-static -static-pie"
    # This forces HOSTLDFLAGS into the host-csingle rule used by fixdep
    sed -i 's|\(cmd_host-csingle[[:space:]]*=[[:space:]]*$(HOSTCC) $(hostc_flags) -o \$@ \$<\)|\1 $(HOSTLDFLAGS)|' \
    	scripts/Makefile.host || exit 1

    cfg STATIC
    # --- Core / usability ---
    for opt in \
        SHOW_USAGE FEATURE_VERBOSE_USAGE FEATURE_COMPRESS_USAGE \
        LONG_OPTS FEATURE_DEVPTS PLATFORM_LINUX \
        FEATURE_IPV6 FEATURE_UNIX_LOCAL FEATURE_PREFER_IPV4_ADDRESS; do
        cfg "$opt"
    done

    # --- Shell ---
    for opt in \
        SH_IS_ASH BASH_IS_NONE SHELL_ASH ASH ASH_OPTIMIZE_FOR_SIZE \
        ASH_INTERNAL_GLOB ASH_BASH_COMPAT ASH_BASH_NOT_FOUND_HOOK \
        ASH_JOB_CONTROL ASH_ALIAS ASH_RANDOM_SUPPORT ASH_EXPAND_PRMT \
        ASH_IDLE_TIMEOUT ASH_MAIL ASH_ECHO ASH_PRINTF ASH_TEST \
        ASH_HELP ASH_GETOPTS ASH_CMDCMD FEATURE_SH_MATH \
        FEATURE_SH_MATH_64 FEATURE_SH_MATH_BASE FEATURE_SH_EXTRA_QUIET \
        FEATURE_SH_READ_FRAC FEATURE_SH_EMBEDDED_SCRIPTS; do
        cfg "$opt"
    done

    # --- Editors ---
    for opt in \
        VI FEATURE_VI_8BIT FEATURE_VI_COLON FEATURE_VI_COLON_EXPAND \
        FEATURE_VI_YANKMARK FEATURE_VI_SEARCH FEATURE_VI_USE_SIGNALS \
        FEATURE_VI_DOT_CMD FEATURE_VI_READONLY FEATURE_VI_SETOPTS \
        FEATURE_VI_SET FEATURE_VI_WIN_RESIZE FEATURE_VI_ASK_TERMINAL \
        FEATURE_VI_UNDO FEATURE_VI_UNDO_QUEUE FEATURE_VI_VERBOSE_STATUS \
        FEATURE_ALLOW_EXEC XXD; do
        cfg "$opt"
    done
    cfg "FEATURE_VI_MAX_LEN=4096"
    cfg "FEATURE_VI_UNDO_QUEUE_MAX=256"

    # --- Build / Text ---
    for opt in \
        DIFF FEATURE_DIFF_LONG_OPTIONS FEATURE_DIFF_DIR; do
        cfg "$opt"
    done

    # --- Networking ---
    for opt in \
        IP FEATURE_IP_ADDRESS FEATURE_IP_LINK FEATURE_IP_ROUTE \
        FEATURE_IP_TUNNEL FEATURE_IP_NEIGH FEATURE_IP_RULE \
        FEATURE_IP_SHORT_FORMS IFCONFIG FEATURE_IFCONFIG_STATUS \
        FEATURE_IFCONFIG_SLIP FEATURE_IFCONFIG_HW FEATURE_IFCONFIG_BROADCAST_PLUS \
        ROUTE NETSTAT NC FTPGET FTPPUT WGET \
        FEATURE_NETSTAT_WIDE FEATURE_NETSTAT_PRG FEATURE_FANCY_PING \
        FEATURE_PING_LONG_OPTIONS PING PING6 TRACEROUTE TRACEROUTE6 \
        UDHCPD FEATURE_UDHCPD_BOOTP FEATURE_UDHCPD_BASE_IP_ON_MAC \
        FEATURE_UDHCPD_WRITE_LEASES_EARLY DHCPRELAY \
        UDHCPC FEATURE_UDHCPC_ARPING FEATURE_UDHCPC_SANITIZEOPT \
        UDHCPC6 FEATURE_UDHCPC6_RFC3646 FEATURE_UDHCPC6_RFC4704 \
        FEATURE_UDHCPC6_RFC4833 FEATURE_UDHCPC6_RFC5970 \
        FEATURE_UDHCP_RFC3397 FEATURE_UDHCP_8021Q \
        FEATURE_WGET_LONG_OPTIONS FEATURE_WGET_STATUSBAR FEATURE_WGET_FTP \
        FEATURE_WGET_AUTHENTICATION FEATURE_WGET_TIMEOUT FEATURE_WGET_HTTPS; do
        cfg "$opt"
    done
    cfg 'FEATURE_IP_ROUTE_DIR="/etc/iproute2"'
    cfg 'UDHCPC_DEFAULT_INTERFACE="eth0"'

    for opt in \
        LN GETTY HALT REBOOT DEPMOD POWEROFF; do
        cfg "$opt"
    done

    # --- Compression ---
    for opt in \
        GZIP GUNZIP ZCAT FEATURE_GZIP_DECOMPRESS FEATURE_GZIP_LONG_OPTIONS \
        BZIP2 BUNZIP2 BZCAT FEATURE_BZIP2_DECOMPRESS \
        XZ UNXZ XZCAT \
        LZMA UNLZMA LZCAT LZOP UNLZOP LZOPCAT \
        ZSTD UNZSTD ZSTDCAT \
        UNZIP FEATURE_UNZIP_CDF \
        FEATURE_UNZIP_BZIP2 FEATURE_UNZIP_LZMA FEATURE_UNZIP_XZ \
        FEATURE_LZMA_FAST FEATURE_SEAMLESS_Z FEATURE_SEAMLESS_GZ \
        FEATURE_SEAMLESS_BZ2 FEATURE_SEAMLESS_LZMA FEATURE_SEAMLESS_XZ \
        FEATURE_SEAMLESS_ZSTD; do
        cfg "$opt"
    done

    # --- Archives ---
    for opt in \
        TAR \
        FEATURE_TAR_AUTODETECT \
        FEATURE_TAR_CREATE \
        FEATURE_TAR_FROM \
        FEATURE_TAR_OLDGNU_COMPATIBILITY \
        FEATURE_TAR_OLDSUN_COMPATIBILITY \
        FEATURE_TAR_GNU_EXTENSIONS \
        FEATURE_TAR_LONG_OPTIONS \
        FEATURE_TAR_TO_COMMAND \
        FEATURE_TAR_UNAME_GNAME \
        FEATURE_TAR_NOPRESERVE_TIME \
        FEATURE_TAR_SELINUX \
        FEATURE_TAR_GZIP \
        FEATURE_TAR_BZIP2 \
        FEATURE_TAR_LZMA \
        FEATURE_TAR_XZ \
        FEATURE_TAR_ZSTD; do
        cfg "$opt"
    done
    # ar
    #for opt in \
    #    AR FEATURE_AR_LONG_FILENAMES FEATURE_AR_CREATE \
    #    UNCOMPRESS; do
    #    cfg "$opt"
    #done
    cfg "FEATURE_PATH_TRAVERSAL_PROTECTION"

    tools=$(get_tools busybox)
    for path in $tools; do
        tool=$(basename "$path" | tr 'a-z' 'A-Z')
        cfg "$tool"
    done

    exec_filtered make -j"$(nproc)" SKIP_STRIP=y CFLAGS_busybox="-fvisibility=default"
    find . -name "*.o" -type f ! -path "./scripts/*" -exec mv {} . \; 2>/dev/null || true
    touch .built
    ok "Busybox built"
}

build_toybox() {
    log "Building Toybox"
    cd "$SRC/toybox"
    [ -f .built ] && return 0
    exec_filtered make clean
    exec_filtered env KCONFIG_ALLCONFIG=/dev/null make allnoconfig

    for opt in \
        TOYBOX_HELP TOYBOX_HELP_DASHDASH TOYBOX_I18N \
        TOYBOX_FLOAT TOYBOX_PEDANTIC_ARGS; do
        cfg "$opt"
    done

    tools=$(get_tools toybox)
    for path in $tools; do
        tool=$(basename "$path" | tr 'a-z' 'A-Z')
        cfg "$tool"
    done

    if [ $VERBOSITY -eq 0 ]; then
        CFLAGS="-U_FORTIFY_SOURCE $CFLAGS" env -u POSIXLY_CORRECT \
            make -j"$(nproc)" >/dev/null 2>&1
    elif [ $VERBOSITY -eq 1 ]; then
        CFLAGS="-U_FORTIFY_SOURCE $CFLAGS" env -u POSIXLY_CORRECT \
            make -j"$(nproc)" 2>&1 | grep -v -e ': warning:' -e ': note:' || true
    elif [ $VERBOSITY -eq 2 ]; then
        CFLAGS="-U_FORTIFY_SOURCE $CFLAGS" env -u POSIXLY_CORRECT \
            make -j"$(nproc)" 2>&1 | grep -v -e ': note:' || true
    else
        CFLAGS="-U_FORTIFY_SOURCE $CFLAGS" env -u POSIXLY_CORRECT \
            make -j"$(nproc)"
    fi
    find generated/obj -name "*.o" -type f -exec mv {} . \; 2>/dev/null || true
    touch .built
    ok "Toybox built"
}

collect_objects() {
    proj="$1"
    find "$SRC/$proj" -maxdepth 1 -name "*.o" -type f 2>/dev/null
}

prefix_objects() {
    proj="$1"
    prefix="$2"
    cd "$SRC/$proj"
    [ -f .prefixed ] && return 0
    log "Prefixing symbols in $proj"

    # Create symbol list - avoid any variable confusion
    nm -g --defined-only *.o 2>/dev/null | awk '{print $3}' > "$TMPDIR/${proj}_all.txt"
    grep -v '^_' "$TMPDIR/${proj}_all.txt" | grep -v "^${prefix}_" | sort -u > "$TMPDIR/${proj}_sym.list"

    [ ! -s "$TMPDIR/${proj}_sym.list" ] && {
        touch .prefixed
        return 0
    }

    awk -v pfx="${prefix}_" '{ printf "%s %s%s\n", $1, pfx, $1 }' "$TMPDIR/${proj}_sym.list" > "$TMPDIR/${proj}_sym.map"
    for o in *.o; do
        objcopy --redefine-syms="$TMPDIR/${proj}_sym.map" "$o"
    done
    touch .prefixed
    ok "$proj prefixed"
}

gen_dispatch() {
    is_suid="$1"
    manifest_data="$2"

    cat <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
EOF

    for proj in sbase ubase; do
        case "$proj" in sbase) pfx="sb" ;; ubase) pfx="ub" ;; esac
        tools=$(get_tools "$proj")
        for path in $tools; do
            tool=$(basename "$path")
            func=$(echo "$tool" | sed 's/[-.]/_/g')
            echo "int ${pfx}_${func}_main(int, char **);"
        done
    done

    cat <<'EOF'

extern void bb_lbb_prepare(const char *);
extern int bb_find_applet_by_name(const char *);
extern void bb_run_applet_no_and_exit(int, const char *, char **) __attribute__((noreturn));
extern void tb_toy_exec(char **) __attribute__((noreturn));

struct Tool {
    const char *name;
    const char *path;
    int (*func)(int, char **);
    const char *category;
};

struct Tool tools[] = {
EOF

    echo "$manifest_data" | while IFS=: read -r path rest; do
        [ -z "$path" ] && continue
        case "$path" in \#*|" "*) continue ;; esac
        cat=$(echo "$rest" | awk -F: '{print $NF}')
        tool=$(basename "$path")
        case "$cat" in
            sbase) func="sb_$(echo "$tool" | sed 's/[-.]/_/g')_main" ;;
            ubase) func="ub_$(echo "$tool" | sed 's/[-.]/_/g')_main" ;;
            *)     func="NULL" ;;
        esac
        printf '\t{"%s", "%s", %s, "%s"},\n' "$tool" "$path" "$func" "$cat"

        remaining="$rest"
        while echo "$remaining" | grep -q "/" && [ "$remaining" != "$cat" ]; do
            alias_path=$(echo "$remaining" | cut -d: -f1)
            alias_name=$(basename "$alias_path")
            printf '\t{"%s", "%s", %s, "%s"},\n' "$alias_name" "$alias_path" "$func" "$cat"
            remaining=$(echo "$remaining" | sed 's/^[^:]*://')
        done
    done

    cat <<EOF
    {NULL, NULL, NULL, NULL}
};

void usage(char *self) {
EOF
    if [ "$is_suid" -eq 1 ]; then
        echo '    fprintf(stderr, "SECURITY WARNING: %s contains tools requiring SUID/Root privileges.\n\n", self);'
    fi
    cat <<'EOF'
    fprintf(stderr, "Usage: %s [tool] [args...]\n", self);
    fprintf(stderr, " or: %s --list | --list-full | --install\n\n", self);

    // Only print category headers if they have tools
    int has_sbase = 0, has_ubase = 0, has_busybox = 0, has_toybox = 0;
    for (int i = 0; tools[i].name; i++) {
        if (strcmp(tools[i].category, "sbase") == 0) has_sbase = 1;
        else if (strcmp(tools[i].category, "ubase") == 0) has_ubase = 1;
        else if (strcmp(tools[i].category, "busybox") == 0) has_busybox = 1;
        else if (strcmp(tools[i].category, "toybox") == 0) has_toybox = 1;
    }

    if (has_sbase) {
        fprintf(stderr, "sbase:\n\t");
        for (int i = 0; tools[i].name; i++)
            if (strcmp(tools[i].category, "sbase") == 0)
                fprintf(stderr, "%s ", tools[i].name);
        fprintf(stderr, "\n");
    }
    if (has_ubase) {
        fprintf(stderr, "ubase:\n\t");
        for (int i = 0; tools[i].name; i++)
            if (strcmp(tools[i].category, "ubase") == 0)
                fprintf(stderr, "%s ", tools[i].name);
        fprintf(stderr, "\n");
    }
    if (has_busybox) {
        fprintf(stderr, "busybox:\n\t");
        for (int i = 0; tools[i].name; i++)
            if (strcmp(tools[i].category, "busybox") == 0)
                fprintf(stderr, "%s ", tools[i].name);
        fprintf(stderr, "\n");
    }
    if (has_toybox) {
        fprintf(stderr, "toybox:\n\t");
        for (int i = 0; tools[i].name; i++)
            if (strcmp(tools[i].category, "toybox") == 0)
                fprintf(stderr, "%s ", tools[i].name);
        fprintf(stderr, "\n");
    }
    exit(1);
}

void install_script(const char *self) {
    printf("#!/bin/sh\n");
    printf("set -x\n");
    for (int i = 0; tools[i].name; i++) printf("ln -sf %s %s\n", self, tools[i].path);
EOF
    if [ "$is_suid" -eq 1 ]; then
        echo '    for (int i = 0; tools[i].name; i++) {'
        echo '        printf("chown root:root %s\n", tools[i].path);'
        echo '        printf("chmod 4755 %s\n", tools[i].path);'
        echo '    }'
    else
        echo '    printf("command -v baseutils-suid && echo \"For a complete setup, execute: baseutils-suid --install | sh -s --\"\\n");'
    fi
    cat <<'EOF'
}

int main(int argc, char **argv) {
    char *name = basename(argv[0]);
    char *base = basename(argv[0]);

    // Check if invoked as the binary itself (not symlink)
    int is_direct = 0;
    if (strstr(base, "baseutils")) is_direct = 1;

    if (is_direct) {
        if (argc < 2) usage(argv[0]);
        if (!strcmp(argv[1], "--list")) { for (int i = 0; tools[i].name; i++) printf("%s\n", tools[i].name); return 0; }
        if (!strcmp(argv[1], "--list-full")) { for (int i = 0; tools[i].name; i++) printf("%s\n", tools[i].path); return 0; }
        if (!strcmp(argv[1], "--install")) {
            char buf[PATH_MAX];
            ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
            if (len != -1) { buf[len] = '\0'; install_script(buf); }
            return 0;
        }
        name = argv[1]; argv++; argc--;
    }
    for (int i = 0; tools[i].name; i++) {
        if (strcmp(name, tools[i].name)) continue;
        argv[0] = (char *)tools[i].name;
        if (tools[i].func) return tools[i].func(argc, argv);
        if (strcmp(tools[i].category, "busybox") == 0) {
            bb_lbb_prepare(tools[i].name);
            int no = bb_find_applet_by_name(tools[i].name);
            if (no >= 0) bb_run_applet_no_and_exit(no, tools[i].name, argv);
            fprintf(stderr, "%s: busybox applet not found\n", tools[i].name);
            return 127;
        }
        if (strcmp(tools[i].category, "toybox") == 0) tb_toy_exec(argv);
    }
    fprintf(stderr, "%s: not found\n", name);
    return 127;
}
EOF
}

link_binaries() {
    log "Linking binaries"
    mkdir -p "$BIN/bin"
    cd "$BIN"

    objs=""
    for proj in sbase ubase busybox toybox; do
        objs="$objs $(collect_objects "$proj")"
    done
    incs="-I$SRC/sbase -I$SRC/ubase -I$SRC/busybox/include -I$SRC/toybox"

    # Link baseutils (Non-SUID)
    log "Linking baseutils (standard)..."
    gen_dispatch 0 "$MANIFEST" > "$TMPDIR/main_base.c"
    exec_filtered $CC -o "$BIN/bin/baseutils" "$TMPDIR/main_base.c" $objs $CFLAGS $incs -lm -lcrypt
    $STRIP "$BIN/bin/baseutils"
    size=$(du -h "$BIN/bin/baseutils" | cut -f1)
    ok "baseutils linked ($size)"

    # Link baseutils-suid (SUID tools only)
    log "Linking baseutils-suid (privileged)..."
    gen_dispatch 1 "$MANIFEST_SUID" > "$TMPDIR/main_suid.c"
    exec_filtered $CC -o "$BIN/bin/baseutils-suid" "$TMPDIR/main_suid.c" $objs $CFLAGS $incs -lm -lcrypt
    $STRIP "$BIN/bin/baseutils-suid"
    size=$(du -h "$BIN/bin/baseutils-suid" | cut -f1)
    ok "baseutils-suid linked ($size)"
}

build_all() {
    log "Starting build"
    check_collisions
    build_busybox
    prefix_objects busybox bb
    build_toybox
    prefix_objects toybox tb
    build_suckless sbase
    prefix_objects sbase sb
    build_suckless ubase
    prefix_objects ubase ub
    link_binaries
    ok "Build complete"
}

clean_all() {
    log "Cleaning"
    rm -rf "$BIN"
    for sub in busybox toybox sbase ubase; do
        [ -d "$SRC/$sub" ] || continue
        cd "$SRC/$sub"
        git clean -fdx >/dev/null 2>&1 || true
        git reset --hard >/dev/null 2>&1 || true
    done
    ok "Clean complete"
}

case "${1:-build}" in
    build) build_all ;;
    clean) clean_all ;;
    fetch) git submodule update --init --recursive --remote ;;
    *)     die "Usage: $0 [-v|-vv|-vvv] {build|clean|fetch}" ;;
esac
