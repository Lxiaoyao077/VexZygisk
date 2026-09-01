import { exec, toast } from '../../kernelsu.js'

import { whichCurrentPage } from '../navbar.js'
import { getStrings } from '../pageLoader.js'
import { getVexZygiskState } from '../state.js'

const rzState = {
  actuallyWorking: 0,
  expectedWorking: 0
}

function setZygoteMetric(el, state, strings) {
  if (!el) return
  if (state === 1) {
    el.textContent = strings.info.zygote.injected
  } else if (state === 0) {
    el.textContent = strings.info.zygote.notInjected
  } else {
    el.textContent = strings.info.zygote.unknown
  }
}

function setMonitorPill(state, strings) {
  const pill = document.getElementById('monitor_pill')
  if (!pill) return

  const status = strings.monitor?.status ?? {}
  let text
  switch (state) {
    case '0': text = status.tracing; break
    case '1': text = status.stopping; break
    case '2': text = status.stopped; break
    case '3': text = status.exiting; break
    default: text = status.unknown ?? strings.unknown
  }

  pill.textContent = text
  pill.classList.remove('zygisk', 'next', 'companion')
  pill.classList.add(state === '0' ? 'zygisk' : 'companion')
}

async function _getVersion() {
  const moduleProp = await exec('cat /data/adb/modules/rezygisk/module.prop')
  if (moduleProp.errno !== 0) return '???'

  let version = '???'
  moduleProp.stdout.split('\n').forEach((line) => {
    if (line.startsWith('version=')) version = line.split('=')[1]
  })

  return version
}

async function _getKernelString() {
  const unameCmd = await exec('/system/bin/uname -r')
  if (unameCmd.errno !== 0 || !unameCmd.stdout) return '???'
  return unameCmd.stdout.trim()
}

async function _getAndroidVersion() {
  const androidVersionCmd = await exec('/system/bin/getprop ro.build.version.release')
  if (androidVersionCmd.errno !== 0 || !androidVersionCmd.stdout) return '???'
  return androidVersionCmd.stdout.trim()
}

function _updateDynamicElement(firstRun, VexZygiskState, strings) {
  const rz_state = document.getElementById('rz_state')

  if (VexZygiskState == null) {
    if (rz_state) rz_state.textContent = strings.unknown
    document.getElementById('loading_screen').style.display = 'none'
    return
  }

  if (firstRun) {
    rzState.expectedWorking =
      VexZygiskState.zygote === undefined
        ? 0
        : (VexZygiskState.zygote['64'] !== undefined ? 1 : 0) +
          (VexZygiskState.zygote['32'] !== undefined ? 1 : 0)
  }

  if (VexZygiskState.zygote !== undefined && VexZygiskState.zygote['64'] !== undefined) {
    if (VexZygiskState.zygote['64'] === 1 && firstRun) rzState.actuallyWorking++
    setZygoteMetric(document.getElementById('zygote64_state'), VexZygiskState.zygote['64'], strings)
  }

  if (VexZygiskState.zygote && VexZygiskState.zygote['32'] !== undefined) {
    if (VexZygiskState.zygote['32'] === 1 && firstRun) rzState.actuallyWorking++
    setZygoteMetric(document.getElementById('zygote32_state'), VexZygiskState.zygote['32'], strings)
  }

  if (rz_state) {
    if (rzState.expectedWorking === 0 || rzState.actuallyWorking === 0) {
      rz_state.textContent = strings.status.notWorking
    } else if (rzState.expectedWorking === rzState.actuallyWorking) {
      rz_state.textContent = strings.status.ok
    } else {
      rz_state.textContent = strings.status.partially
    }
  }
}

export async function loadOnce() {

}

export async function loadOnceView() {
  document.getElementById('version_code').innerHTML = await _getVersion()
  document.getElementById('kernel_version_div').innerHTML = await _getKernelString()
  document.getElementById('android_version_div').innerHTML = await _getAndroidVersion()

  const VexZygiskState = await getVexZygiskState()
  const strings = await getStrings(whichCurrentPage())

  if (VexZygiskState === null) toast('Error getting state of VexZygisk!')

  const root_impl = VexZygiskState?.root ?? strings.unknown
  document.getElementById('root_impl').innerHTML = root_impl

  _updateDynamicElement(true, VexZygiskState, strings)
  setMonitorPill(VexZygiskState?.monitor?.state, strings)

  document.getElementById('loading_screen').style.display = 'none'
}

export async function load() {
  const VexZygiskState = await getVexZygiskState()
  const strings = await getStrings(whichCurrentPage())

  document.getElementById('monitor_status').innerHTML =
    VexZygiskState?.monitor?.state === undefined
      ? strings.unknown
      : (strings.monitor?.status ?? {})[VexZygiskState.monitor.state] ?? strings.unknown

  setMonitorPill(VexZygiskState?.monitor?.state, strings)
}
