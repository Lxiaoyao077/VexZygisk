#!/system/bin/sh

set -e

MODDIR=${0%/*}
if [ "$ZYGISK_ENABLED" ]; then
  exit 0
fi

cd "$MODDIR"

create_sys_perm() {
  mkdir -p $1
  chmod 555 $1
  chcon u:object_r:system_file:s0 $1
}

export TMP_PATH=/data/adb/rezygisk
rm -rf "$TMP_PATH"

create_sys_perm $TMP_PATH

sh /data/adb/post-fs-data.d/rezygisk.sh

# INFO: A single monitor is started, and it matches the bitness of what got installed. The
#         64-bit build is preferred whenever present, since it is the one shipped to every
#         64-bit device. 32-bit only devices fall back to the 32-bit build.
if [ -f "$MODDIR/bin/zygisk-ptrace64" ]; then
  "$MODDIR/bin/zygisk-ptrace64" monitor &
elif [ -f "$MODDIR/bin/zygisk-ptrace32" ]; then
  "$MODDIR/bin/zygisk-ptrace32" monitor &
fi

exit 0
