import { exec } from '../kernelsu.js'

export async function getVexZygiskState() {
  const stateCmd = await exec('/system/bin/cat /data/adb/rezygisk/state.json')
  if (stateCmd.errno !== 0) return null

  try {
    return JSON.parse(stateCmd.stdout)
  } catch {
    return null
  }
}
