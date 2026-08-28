# shellcheck disable=SC2034
SKIPUNZIP=1

MIN_KSU_VERSION=@MIN_KSU_VERSION@
MIN_KSUD_VERSION=@MIN_KSUD_VERSION@

if [ "$BOOTMODE" ] && [ "$KSU" ]; then
  ui_print "- Installing from KernelSU app"
  ui_print "- KernelSU version: $KSU_KERNEL_VER_CODE (kernel) + $KSU_VER_CODE (ksud)"
  if ! [ "$KSU_KERNEL_VER_CODE" ] || [ "$KSU_KERNEL_VER_CODE" -lt "$MIN_KSU_VERSION" ]; then
    ui_print "*********************************************************"
    ui_print "! KernelSU version is too old!"
    ui_print "! Please update KernelSU to latest version"
    abort    "*********************************************************"
  fi
  if ! [ "$KSU_VER_CODE" ] || [ "$KSU_VER_CODE" -lt "$MIN_KSUD_VERSION" ]; then
    ui_print "*********************************************************"
    ui_print "! ksud version is too old!"
    ui_print "! Please update KernelSU Manager to latest version"
    abort    "*********************************************************"
  fi
else
  ui_print "*********************************************************"
  ui_print "! Install from recovery is not supported"
  ui_print "! Please install from KernelSU"
  abort    "*********************************************************"
fi

VERSION=$(grep_prop version "${TMPDIR}/module.prop")
ui_print "- Installing VexZygisk $VERSION"

# check android
if [ "$API" -lt 25 ]; then
  ui_print "! Unsupported sdk: $API"
  abort "! Minimal supported sdk is 25 (Android 7.1)"
else
  ui_print "- Device sdk: $API"
fi

# check architecture
if [ "$ARCH" = "x86" ] || [ "$ARCH" = "x64" ]; then
  abort "! x86 / x86_64 devices are not supported by VexZygisk"
fi

if [ "$ARCH" != "arm" ] && [ "$ARCH" != "arm64" ]; then
  abort "! Unsupported platform: $ARCH"
fi

ui_print "- Device platform: $ARCH"

ui_print "- Extracting verify.sh"
unzip -o "$ZIPFILE" 'verify.sh' -d "$TMPDIR" >&2
if [ ! -f "$TMPDIR/verify.sh" ]; then
  ui_print "*********************************************************"
  ui_print "! Unable to extract verify.sh!"
  ui_print "! This zip may be corrupted, please try downloading again"
  abort    "*********************************************************"
fi
. "$TMPDIR/verify.sh"
extract "$ZIPFILE" 'customize.sh'  "$TMPDIR/.vunzip"
extract "$ZIPFILE" 'verify.sh'     "$TMPDIR/.vunzip"
extract "$ZIPFILE" 'sepolicy.rule' "$TMPDIR"

if [ "$KSU" ]; then
  ui_print "- Checking SELinux patches"
  if ! check_sepolicy "$TMPDIR/sepolicy.rule"; then
    ui_print "*********************************************************"
    ui_print "! Unable to apply SELinux patches!"
    ui_print "! Your kernel may not support SELinux patch fully"
    abort    "*********************************************************"
  fi
fi

ui_print "- Extracting module files"
extract "$ZIPFILE" 'module.prop'     "$MODPATH"
extract "$ZIPFILE" 'post-fs-data.sh' "$MODPATH"
extract "$ZIPFILE" 'uninstall.sh'    "$MODPATH"
extract "$ZIPFILE" 'rezygisk.sh' "/data/adb/post-fs-data.d/"

# INFO: KernelSU 2.x.x and below runs post-fs-data.d before mounting
#         the modules. This disallows us to clean our own module.prop.
#         To work around this, we utilize post-mount.d which runs after
#         mounting, and copy our post-fs-data.d script there.
#
# SOURCES:
#  - https://github.com/tiann/KernelSU/blob/6615068a987a12bbc6a3ad272b285cec7f594964/userspace/ksud/src/init_event.rs#L123
#  - https://github.com/tiann/KernelSU/blob/6615068a987a12bbc6a3ad272b285cec7f594964/userspace/ksud/src/init_event.rs#L161
#  - https://github.com/tiann/KernelSU/blob/6615068a987a12bbc6a3ad272b285cec7f594964/userspace/ksud/src/init_event.rs#L212-L217
mkdir -p /data/adb/post-mount.d
cp "/data/adb/post-fs-data.d/rezygisk.sh" "/data/adb/post-mount.d/rezygisk.sh"

cp "$MODPATH/module.prop" "$MODPATH/module.prop.bak"

chmod +x "$MODPATH/uninstall.sh"

mv "$TMPDIR/sepolicy.rule" "$MODPATH"

mkdir "$MODPATH/bin"
mkdir "$MODPATH/webroot"

ui_print "- Extracting webroot"
unzip -o "$ZIPFILE" "webroot/*" -x "*.sha256" -d "$MODPATH"

# INFO: Only the Zygote matching the device's primary ABI gets injected. Practically every
#         modern device is 64-bit and ships a secondary 32-bit Zygote that barely sees any
#         use, so injecting it only costs performance and stability for no real gain. The
#         32-bit binaries are therefore installed on 32-bit only devices solely.
case "$ARCH" in
  arm)
    ARCH_BITS=32
    ARCH_LIB_DIR=lib
    ARCH_ABI=armeabi-v7a
    ;;
  *)
    ARCH_BITS=64
    ARCH_LIB_DIR=lib64
    ARCH_ABI=arm64-v8a
    ;;
esac

if [ "$ARCH_BITS" = 32 ]; then
  ui_print "- Device is 32-bit only"
else
  ui_print "- Device is 64-bit, 32-bit Zygote will not be injected"
fi

ui_print "- Extracting $ARCH_ABI libraries"
mkdir "$MODPATH/$ARCH_LIB_DIR"

extract "$ZIPFILE" "bin/$ARCH_ABI/zygiskd" "$MODPATH/bin" true
mv "$MODPATH/bin/zygiskd" "$MODPATH/bin/zygiskd$ARCH_BITS"
extract "$ZIPFILE" "lib/$ARCH_ABI/libzygisk.so" "$MODPATH/$ARCH_LIB_DIR" true
extract "$ZIPFILE" "lib/$ARCH_ABI/libzygisk_ptrace.so" "$MODPATH/bin" true
mv "$MODPATH/bin/libzygisk_ptrace.so" "$MODPATH/bin/zygisk-ptrace$ARCH_BITS"

ui_print "- Setting permissions"
set_perm_recursive "$MODPATH/bin" 0 0 0755 0755
set_perm_recursive "$MODPATH/$ARCH_LIB_DIR" 0 0 0755 0644 u:object_r:system_lib_file:s0

# If Huawei's Maple is enabled, system_server is created with a special way which is out of Zygisk's control
HUAWEI_MAPLE_ENABLED=$(grep_prop ro.maple.enable)
if [ "$HUAWEI_MAPLE_ENABLED" == "1" ]; then
  ui_print "- Add ro.maple.enable=0"
  echo "ro.maple.enable=0" >>"$MODPATH/system.prop"
fi
