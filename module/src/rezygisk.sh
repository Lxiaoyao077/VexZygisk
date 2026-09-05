#!/system/bin/sh

set -e

# INFO: This script is installed to /data/adb/post-fs-data.d/rezygisk.sh, and
#         the KernelSU flavour additionally copies it to
#         /data/adb/post-mount.d/rezygisk.sh: KernelSU 2.x runs post-fs-data.d
#         before the modules are mounted, where the module directory is not
#         reachable yet, so the post-mount.d copy is the one that actually
#         runs there. The module's own post-fs-data.sh invokes this script as
#         well, which is the run that is guaranteed to come after mounting on
#         every root solution.
#
# INFO: The monitor rewrites module.prop with live status while VexZygisk
#         runs. This script restores the pristine copy kept at install time,
#         so no status trace survives into the next boot — including boots
#         where the module is disabled and the monitor never starts.

MODDIR=/data/adb/modules/rezygisk

# INFO: Resets VexZygisk's module.prop to its default state which is saved upon installation.
cp "$MODDIR/module.prop.bak" "$MODDIR/module.prop"

exit 0
