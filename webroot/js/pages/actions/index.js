import { whichCurrentPage } from '../navbar.js'
import { getStrings } from '../pageLoader.js'
import { exec, toast } from '../../kernelsu.js'

async function _getVexZygiskState() {
  const stateCmd = await exec('/system/bin/cat /data/adb/rezygisk/state.json')
  if (stateCmd.errno !== 0) {
    toast('Error getting state of VexZygisk!')

    return null;
  }

  try {
    return JSON.parse(stateCmd.stdout)
  } catch {
    return null;
  }
}

async function _updateMonitorStatus(strings) {
  const monitor_status = document.getElementById('monitor_status')
  const VexZygiskState = await _getVexZygiskState()

  if (VexZygiskState == null) return;

  switch (VexZygiskState.monitor.state) {
    case '0': monitor_status.innerHTML = strings.monitor.status.tracing; break;
    case '1': monitor_status.innerHTML = strings.monitor.status.stopping; break;
    case '2': monitor_status.innerHTML = strings.monitor.status.stopped; break;
    case '3': monitor_status.innerHTML = strings.monitor.status.exiting; break;
    default: monitor_status.innerHTML = strings.monitor.status.unknown;
  }
}

export async function loadOnce() {

}

export async function loadOnceView() {

}

export async function load() {
  const strings = await getStrings(whichCurrentPage())

  await _updateMonitorStatus(strings)
}
