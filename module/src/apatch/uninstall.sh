#!/system/bin/sh

set -e

export TMP_PATH=/data/adb/rezygisk
rm -rf "$TMP_PATH"

rm -f /data/adb/post-fs-data.d/rezygisk.sh

# INFO: Only removes if dir is empty
rmdir /data/adb/post-fs-data.d

exit 0
