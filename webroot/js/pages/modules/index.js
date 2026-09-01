import { exec, toast } from '../../kernelsu.js'

import { whichCurrentPage } from '../navbar.js'
import { getStrings } from '../pageLoader.js'
import { getVexZygiskState } from '../state.js'

async function _getModuleNames(modules) {
  const fullCommand = modules.map((mod) => {
    const propPath = `/data/adb/modules/${mod.id}/module.prop`

    return `if test -f "${propPath}"; then /system/bin/grep '^name=' "${propPath}" | /system/bin/cut -d '=' -f 2- 2>/dev/null || true; else true; fi ; printf "\\n"`
  }).join(' ; ')

  const result = await exec(fullCommand)
  if (result.errno !== 0) {
    toast('Failed to retrieve the module names')

    return null
  }

  return result.stdout.split('\n\n')
}

async function _updateDynamicElement() {
  const VexZygiskState = await getVexZygiskState()
  if (VexZygiskState === null) {
    toast('Error getting state of VexZygisk!')

    return;
  }

  const all_modules = []
  const strings = await getStrings(whichCurrentPage())

  if (VexZygiskState.rezygiskd) Object.keys(VexZygiskState.rezygiskd).forEach((daemon_bit) => {
    const daemon = VexZygiskState.rezygiskd[daemon_bit]

    if (daemon.modules && daemon.modules.length > 0) {
      daemon.modules.forEach((module_id) => {
        const module = all_modules.find((mod) => mod.id === module_id)
        if (module) {
          module.bitsUsed.push(daemon_bit)
        } else {
          all_modules.push({
            id: module_id,
            name: null,
            bitsUsed: [ daemon_bit ]
          })
        }
      })
    }
  })

  if (all_modules.length === 0) return;

  const module_names = await _getModuleNames(all_modules)
  if (module_names) module_names.forEach((module_name, i) => {
    if (all_modules[i]) all_modules[i].name = module_name
  })

  const module_cards = all_modules.map((module) =>
    `<div class="dim card" style="padding: 25px 15px; cursor: pointer;">
      <div class="dimc" style="font-size: 1.1em;">${module.name || module.id}</div>
      <div class="dimc desc" style="font-size: 0.9em; margin-top: 3px; white-space: nowrap; align-items: center; display: flex;">
        <div class="dimc arch_desc">${strings.arch}</div>
        <div class="dimc" style="margin-left: 5px;">${module.bitsUsed.join(' / ')}</div>
      </div>
    </div>`)

  document.getElementById('modules_list').innerHTML = `
    <div id="modules_list_not_avaliable" class="not_avaliable" style="display: none;">
      ${strings.notAvaliable}
    </div>
    ${module_cards.join('')}
  `
}

export async function loadOnce() {

}

export async function loadOnceView() {
  _updateDynamicElement()
}

export async function load() {

}
