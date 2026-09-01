#!/system/bin/sh

printf "Status of VexZygisk\n\n"

# INFO: The monitor rewrites this description with the state of the daemons
#       every time it refreshes, so it doubles as the status report.
cat /data/adb/modules/rezygisk/module.prop

# INFO: The KernelSU manager closes the dialog as soon as the script returns,
#       so hold it open long enough to be read. MMRL keeps it open on its own.
if [ -z "$MMRL" ] && [ -n "$KSU" ]; then
	sleep 5
fi
