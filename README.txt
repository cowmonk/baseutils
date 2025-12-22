1. `./cbuild.sh fetch` -> To fetch the submodules
2. `./cbuild.sh -vvv` -> to build with full verbosity
3. Profit

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
/bin/diff:toybox
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
