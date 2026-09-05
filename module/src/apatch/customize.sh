# shellcheck disable=SC2034
SKIPUNZIP=1

MIN_APATCH_VERSION=@MIN_APATCH_VERSION@

if [ "$BOOTMODE" ] && [ "$APATCH" ]; then
  ui_print "- Installing from APatch app"
  if ! [ "$APATCH_VER_CODE" ] || [ "$APATCH_VER_CODE" -lt "$MIN_APATCH_VERSION" ]; then
    ui_print "*********************************************************"
    ui_print "! APatch version is too old!"
    ui_print "! Please update APatch to the latest version"
    abort    "*********************************************************"
  fi
else
  ui_print "*********************************************************"
  ui_print "! Install from recovery is not supported"
  ui_print "! Please install from APatch"
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

ui_print "- Extracting module files"
extract "$ZIPFILE" 'module.prop'     "$MODPATH"
extract "$ZIPFILE" 'post-fs-data.sh' "$MODPATH"
extract "$ZIPFILE" 'uninstall.sh'    "$MODPATH"
extract "$ZIPFILE" 'rezygisk.sh' "/data/adb/post-fs-data.d/"

# INFO: APatch resolves module sepolicy.rule on the next boot through its own
#         boot stage, so there is no install-time policy check as KernelSU
#         does; the rule simply ships with the module.
mv "$TMPDIR/sepolicy.rule" "$MODPATH"

# INFO: rezygisk.sh (moved to post-fs-data.d) resets this module's module.prop
#         to its pristine state whenever it runs, so the pristine copy is kept
#         at install time exactly like the KernelSU flavour does.
cp "$MODPATH/module.prop" "$MODPATH/module.prop.bak"

chmod +x "$MODPATH/uninstall.sh"

mkdir "$MODPATH/bin"

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
