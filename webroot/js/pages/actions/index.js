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
    const VexZygiskState = JSON.parse(stateCmd.stdout)
    return VexZygiskState
  } catch {
    return null;
  }
}

async function _updateDynamicElement() {
  const monitor_status = document.getElementById('monitor_status')
  const strings = await getStrings(whichCurrentPage())
  const VexZygiskState = await _getVexZygiskState()

  if (VexZygiskState == null) return;

  const monitorState = VexZygiskState.monitor.state

  switch (monitorState) {
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
  _updateDynamicElement()
}

export async function onceViewAfterUpdate() {
  _updateDynamicElement()
}

export async function load() {
  const monitor_start = document.getElementById('monitor_start_button')
  const monitor_stop = document.getElementById('monitor_stop_button')
  const monitor_pause = document.getElementById('monitor_pause_button')
  const monitor_status = document.getElementById('monitor_status')
  const strings = await getStrings(whichCurrentPage())

  const VexZygiskState = await _getVexZygiskState()
  /* INFO: A single monitor is ever installed, so its bitness comes from the daemon key */
  const ptracer = VexZygiskState && VexZygiskState.rezygiskd
    ? `zygisk-ptrace${Object.keys(VexZygiskState.rezygiskd)[0]}`
    : null

  if (ptracer == null) {
    toast('Monitor is not running!')
    return;
  }

  const ctl = (action) => exec(`/data/adb/modules/rezygisk/bin/${ptracer} ctl ${action}`)

  monitor_start.addEventListener('click', () => {
    if (![ strings.monitor.status.tracing, strings.monitor.status.stopping, strings.monitor.status.stopped ].includes(monitor_status.innerHTML)) return;
    monitor_status.innerHTML = strings.monitor.status.tracing
    ctl('start')
  })

  monitor_stop.addEventListener('click', () => {
    monitor_status.innerHTML = strings.monitor.status.exiting
    ctl('exit')
  })

  monitor_pause.addEventListener('click', () => {
    if (![ strings.monitor.status.tracing, strings.monitor.status.stopping, strings.monitor.status.stopped ].includes(monitor_status.innerHTML)) return;
    monitor_status.innerHTML = strings.monitor.status.stopped
    ctl('stop')
  })

  return;
}