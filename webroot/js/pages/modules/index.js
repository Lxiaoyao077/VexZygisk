import { exec, toast } from '../../kernelsu.js'

import { whichCurrentPage } from '../navbar.js'
import { getStrings } from '../pageLoader.js'
import { getVexZygiskState } from '../state.js'

let cachedModules = []
let cachedStrings = null

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[c])
}

async function _getModuleProps(modules) {
  const fullCommand = modules.map((mod) => {
    const propPath = `/data/adb/modules/${mod.id}/module.prop`
    return `if test -f "${propPath}"; then /system/bin/grep -E '^(name|version)=' "${propPath}" | /system/bin/cut -d '=' -f 2- | /system/bin/tr '\\n' '\\t' 2>/dev/null || true; else true; fi ; printf "\\n"`
  }).join(' ; ')

  const result = await exec(fullCommand)
  if (result.errno !== 0) {
    toast('Failed to retrieve the module names')
    return null
  }

  return result.stdout.split('\n')
}

function modeIndicators(module, strings) {
  const pills = []
  if (module.next) {
    pills.push(`<span class="mode-indicator next">${escapeHtml(strings.modeNext || 'Next')}</span>`)
  } else {
    pills.push(`<span class="mode-indicator zygisk">${escapeHtml(strings.active || 'Zygisk')}</span>`)
  }
  if (module.companion) {
    pills.push(`<span class="mode-indicator companion">${escapeHtml(strings.modeCompanion || 'Companion')}</span>`)
  }
  return pills.join('')
}

function renderCard(module, strings) {
  const bits = module.bitsUsed.join(' / ')

  const details = []
  details.push(`
    <div class="detail-row">
      <span class="detail-label">${escapeHtml(strings.arch || '架构')}</span>
      <span class="detail-value">${escapeHtml(bits)}</span>
    </div>
  `)
  if (module.targets && module.targets.length > 0) {
    details.push(`
      <div class="detail-row">
        <span class="detail-label">${escapeHtml(strings.targets || 'Target')}</span>
        <span class="detail-value">${escapeHtml(module.targets.join(', '))}</span>
      </div>
    `)
  }

  return `
    <div class="module-card" data-id="${escapeHtml(module.id)}">
      <button class="module-header" type="button">
        <div class="module-info">
          <div class="module-name">${escapeHtml(module.name || module.id)}</div>
          <div class="module-meta">
            <span class="module-id">${escapeHtml(module.id)}</span>
            ${module.version ? `<span class="version-badge">${escapeHtml(module.version)}</span>` : ''}
          </div>
        </div>
        <div class="mode-group">${modeIndicators(module, strings)}</div>
      </button>
      <div class="module-details">
        ${details.join('')}
      </div>
    </div>
  `
}

function renderList() {
  const list = document.getElementById('modules_list')
  if (!list) return

  const query = (document.getElementById('module_search')?.value || '').trim().toLowerCase()
  const filtered = cachedModules.filter((m) =>
    (m.name || m.id).toLowerCase().includes(query) || m.id.toLowerCase().includes(query)
  )

  const empty = document.getElementById('modules_list_empty')

  if (filtered.length === 0) {
    if (empty) empty.style.display = 'flex'
    list.querySelectorAll('.module-card').forEach((c) => c.remove())
    return
  }

  if (empty) empty.style.display = 'none'
  list.querySelectorAll('.module-card').forEach((c) => c.remove())

  const fragment = document.createRange().createContextualFragment(filtered.map((m) => renderCard(m, cachedStrings)).join(''))
  list.appendChild(fragment)

  list.querySelectorAll('.module-card .module-header').forEach((header) => {
    header.addEventListener('click', () => {
      header.closest('.module-card').classList.toggle('expanded')
    })
  })
}

async function _updateDynamicElement() {
  const VexZygiskState = await getVexZygiskState()
  if (VexZygiskState === null) {
    toast('Error getting state of VexZygisk!')
    return
  }

  cachedStrings = await getStrings(whichCurrentPage())
  cachedModules = []

  if (VexZygiskState.rezygiskd) {
    Object.keys(VexZygiskState.rezygiskd).forEach((daemon_bit) => {
      const daemon = VexZygiskState.rezygiskd[daemon_bit]
      if (!daemon.modules || daemon.modules.length === 0) return

      daemon.modules.forEach((entry) => {
        const module_id = typeof entry === 'object' && entry !== null ? entry.id : entry
        if (!module_id) return
        const is_next = typeof entry === 'object' && entry !== null && entry.next === true
        const has_companion = typeof entry === 'object' && entry !== null && entry.companion === true
        const targets = typeof entry === 'object' && entry !== null && Array.isArray(entry.targets) ? entry.targets : []

        const module = cachedModules.find((m) => m.id === module_id)
        if (module) {
          module.bitsUsed.push(daemon_bit)
          module.next = module.next || is_next
          module.companion = module.companion || has_companion
          targets.forEach((t) => { if (!module.targets.includes(t)) module.targets.push(t) })
        } else {
          cachedModules.push({
            id: module_id,
            name: null,
            version: null,
            next: is_next,
            companion: has_companion,
            targets: [...targets],
            bitsUsed: [daemon_bit]
          })
        }
      })
    })
  }

  if (cachedModules.length > 0) {
    const lines = await _getModuleProps(cachedModules)
    if (lines) lines.forEach((line, i) => {
      if (!cachedModules[i]) return
      const [name, version] = (line || '').split('\t')
      if (name) cachedModules[i].name = name
      if (version) cachedModules[i].version = version
    })
  }

  renderList()
}

export async function loadOnce() {

}

export async function loadOnceView() {
  _updateDynamicElement()
}

export async function load() {
  /* INFO: Re-render when returning to the page, e.g. after modules changed. */
  if (cachedStrings !== null) _updateDynamicElement()
}
