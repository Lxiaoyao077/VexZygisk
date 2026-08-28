import { exec, toast } from '../kernelsu.js'

import { loadNavbar, setNavbar, whichCurrentPage } from './navbar.js'
import { runMainPageTransition } from './animator.js'

const head = document.getElementsByTagName('head')[0]

export const allPages = [
  'home',
  'modules'
]

const loadedPageView = []
/* INFO: Prevent overlapping page transitions when users tap navigation rapidly. */
let isPageTransitioning = false

const availableLanguages = [
  'ar_EG', 'de_DE', 'en_US', 'es_AR', 'id_ID', 'it_IT', 'ja_JP', 'ko_KR',
  'pl_PL', 'pt_BR', 'ru_RU', 'tr_TR', 'uk_UA', 'vi_VN', 'zh_CN'
]

const languageFallbacks = {
  ar: 'ar_EG',
  es: 'es_AR',
  pt: 'pt_BR',
  zh: 'zh_CN'
}

function detectLanguage() {
  const locales = [ ...(navigator.languages || []), navigator.language ]

  for (const locale of locales) {
    if (typeof locale !== 'string') continue;

    const parts = locale.split(/[-_]/)
    const normalized = `${parts[0]}_${parts[parts.length - 1].toUpperCase()}`

    if (availableLanguages.includes(normalized)) return normalized
    if (availableLanguages.includes(parts[0])) return parts[0]
    if (languageFallbacks[parts[0]]) return languageFallbacks[parts[0]]
  }

  return 'en_US'
}

export const detectedLanguage = detectLanguage()

async function loadHTML(pageId) {
  return fetch(`js/pages/${pageId}/index.html`)
    .then((response) => response.text())
    .then((data) => {
      return data
    })
    .catch(() => false)
}

async function solveStrings(html, pageId) {
  const strings = await getStrings(pageId)
  if (!strings) return html

  const regex = /{{(.*?)}}/g
  const matches = html.match(regex)

  if (!matches) return html

  try {
    matches.forEach((match) => {
      const key = match.slice(2, -2)

      const split = key.split('.')
      if (split.length === 1) return html = html.replace(match, strings[key]);

      let value = strings
      split.forEach((key) => {
        value = value[key]
      })

      html = html.replace(match, value)
    })
  } catch (e) {
    toast(`Failed to load ${detectedLanguage} strings. Entering safe mode.`)
  }

  /* INFO: Perform navbar string replacement */
  allPages.forEach((page) => document.getElementById(`nav_${page}_title`).innerText = strings.navbar[page])

  return html
}

async function getPageScripts(pageId) {
  return fetch(`js/pages/${pageId}/pageScripts`)
    .then((response) => response.text())
    .then((data) => {
      return data
    })
    .catch(() => false)
}

async function getPageCSS(pageId) {
  return await fetch(`js/pages/${pageId}/index.css`)
    .then((response) => response.text())
    .then((data) => {
      return data
    })
    .catch(() => false)
}

function importPageJS(pageId) {
  return import(`./${pageId}/index.js`)
}

function isHTMLUnused(page, pageId) {
  /* INFO: Detect whether this page DOM is currently in the prefixed/inactive state. */
  if (!page || !page.childNodes) return false

  for (const child of page.childNodes) {
    if (child.id && child.id.startsWith(`page_${pageId}:`)) return true

    if (child.classList) {
      for (const className of child.classList) {
        if (className.startsWith(`page_${pageId}:`)) return true
      }
    }
  }

  return false
}

async function initializePage(pageId, pageSpecificContent, shouldApplyHTMLChanges = true) {
  const module = await importPageJS(pageId)

  if (!loadedPageView.includes(pageId)) {
    pageSpecificContent.innerHTML = await solveStrings(pageSpecificContent.innerHTML, pageId)
    if (shouldApplyHTMLChanges) applyHTMLChanges(pageSpecificContent, pageId)

    module.loadOnceView()

    loadedPageView.push(pageId)
  } else if (shouldApplyHTMLChanges) {
    applyHTMLChanges(pageSpecificContent, pageId)
  }

  module.load()
}

function unuseHTML(page, pageId) {
  const pagePrefix = `page_${pageId}:`

  if (page.childNodes) page.childNodes.forEach((child) => {
    /* INFO: Append pageId to id and classes */
    if (child.id && !child.id.startsWith(pagePrefix)) child.id = `${pagePrefix}${child.id}`
    if (child.classList) {
      const newClasses = []
      if (child.checked) child.classList.add(`--page_loader:checked=true`)

      for (const className of child.classList) {
        if (className.startsWith(pagePrefix)) {
          newClasses.push(className)
          continue;
        }

        newClasses.push(`${pagePrefix}${className}`)
      }

      child.classList = []
      for (const className of newClasses) {
        child.classList.add(className)
      }
    }

    unuseHTML(child, pageId)
  })
}

async function loadPages() {
  return new Promise((resolve) => {
    /*
      INFO: Usually dynamic HTML leads to a lot of visual problems, which
              can vary from missing CSS for an extremely brief moment to
              a full page re-rendering. This is why we load all pages at
              once and then we just switch between them.
    */

    let amountLoaded = 0
    allPages.forEach(async (page) => {
      const pageHTML = await loadHTML(page)
      if (pageHTML === false) {
        toast('Error loading page')

        return;
      }

      const pageJSScripts = await getPageScripts(page)
      if (pageJSScripts === false) {
        toast(`Error while loading ${page} scripts`)

        return;
      }

      const pageContent = document.getElementById('page_content')
      const pageSpecificContent = document.createElement('div')
      pageSpecificContent.id = `${page}_content`
      pageSpecificContent.innerHTML = pageHTML
      pageSpecificContent.style.display = 'none'

      pageContent.appendChild(pageSpecificContent)
      unuseHTML(pageSpecificContent, page)

      const cssData = await getPageCSS(page)
      if (cssData) {
        const cssCode = document.createElement('style')
        cssCode.id = `${page}_css`
        cssCode.innerHTML = cssData
        cssCode.media = 'not all'

        head.appendChild(cssCode)
      }

      pageJSScripts.split('\n').forEach((line) => {
        if (line.length === 0) return;

        const jsCode = document.createElement('script')
        jsCode.src = line
        jsCode.type = 'module'
        jsCode.id = `${page}_js`

        const first = document.getElementsByTagName('script')[0]
        if (!first) {
          head.appendChild(jsCode)

          return;
        }

        first.parentNode.insertBefore(jsCode, first)
      })

      const pageJS = importPageJS(page)
      pageJS.then((module) => module.loadOnce())

      amountLoaded++
      if (amountLoaded === allPages.length) resolve()
    })
  })
}

function revertHTMLUnuse(page, pageId) {
  const pagePrefix = `page_${pageId}:`

  if (page.childNodes) page.childNodes.forEach((child) => {
    /* INFO: Remove pageId from id and classes */
    if (child.id && child.id.startsWith(pagePrefix)) {
      while (child.id.startsWith(pagePrefix)) {
        child.id = child.id.slice(pagePrefix.length)
      }
    }

    if (child.classList) {
      const newClasses = []

      for (const className of child.classList) {
        let normalizedClassName = className

        while (normalizedClassName.startsWith(pagePrefix)) {
          normalizedClassName = normalizedClassName.slice(pagePrefix.length)
        }

        if (normalizedClassName.length > 0) {
          newClasses.push(normalizedClassName)
        }
      }

      child.classList = []
      for (const className of newClasses) {
        child.classList.add(className)
      }
    }

    revertHTMLUnuse(child, pageId)
  })
}

function applyHTMLChanges(page, pageId) {
  if (page.childNodes) page.childNodes.forEach((child) => {
    /* INFO: Remove pageId from id and classes */
    if (child.classList) {
      const newClasses = []

      for (const className of child.classList) {
        if (className.startsWith(`--page_loader:checked=true`)) {
          child.checked = true
        }

        newClasses.push(className)
      }

      child.classList = []
      for (const className of newClasses) {
        child.classList.add(className)
      }
    }

    applyHTMLChanges(child, pageId)
  })
}

export async function loadPage(pageId) {
  /* INFO: Ignore navigation to the same page or while another transition is still running. */
  const currentPage = whichCurrentPage()

  if (currentPage === pageId) return false
  if (isPageTransitioning) return false

  isPageTransitioning = true

  try {
    setNavbar(pageId)

    const pageSpecificContent = document.getElementById(`${pageId}_content`)
    const targetNeedsRevert = isHTMLUnused(pageSpecificContent, pageId)

    if (targetNeedsRevert) revertHTMLUnuse(pageSpecificContent, pageId)

    document.getElementById(`${pageId}_css`).media = 'all'

    if (!currentPage) {
      await initializePage(pageId, pageSpecificContent, targetNeedsRevert)
      pageSpecificContent.style.display = 'block'

      return true
    }

    const currentPageContent = document.getElementById(`${currentPage}_content`)
    const transitionDirection = allPages.indexOf(pageId) > allPages.indexOf(currentPage) ? 1 : -1

    await initializePage(pageId, pageSpecificContent, targetNeedsRevert)

    await runMainPageTransition(currentPageContent, pageSpecificContent, transitionDirection)

    unuseHTML(currentPageContent, currentPage)
    document.getElementById(`${currentPage}_css`).media = 'not all'

    return true
  } catch (error) {
    /* INFO: Keep transition errors visible without breaking future navigation attempts. */
    console.error('Page transition failed:', error)
    toast('Error while changing page.')

    return false
  } finally {
    isPageTransitioning = false

    if (pageId === 'home' && currentPage !== 'home')
      history.back()
    else if (pageId !== 'home' && currentPage === 'home')
      history.pushState(true, '', location.pathname)
  }
}

async function fetchStrings(pageId, language) {
  return fetch(`lang/${language}.json`)
    .then((response) => response.json())
    .then((data) => {
      return {
        ...data.pages[pageId],
        ...data.globals,
        navbar: Object.fromEntries(allPages.map((page) => [page, data.pages[page].title]))
      }
    })
}

export function getStrings(pageId) {
  return fetchStrings(pageId, detectedLanguage)
    .catch(() => {
      if (detectedLanguage === 'en_US') {
        toast('Error loading default strings!')

        return false
      }

      toast(`Error loading ${detectedLanguage} strings, loading default (en_US) strings.`)

      return fetchStrings(pageId, 'en_US')
        .catch(() => {
          toast('Error loading default strings!')

          return false
        })
    })
}

(async () => {
  await loadPages()

  loadPage('home')
  loadNavbar()
})()

/* INFO: Global error handling to catch any unhandled errors and log them to a file for debugging purposes. */
window.addEventListener('error', function (event) {
  toast('An error occurred. See log file.')

  console.error('Unhandled error:', event.error)

  exec(`echo "Error: ${event.message}\n\n${event.error.stack}" > /data/adb/rezygisk/webui_error.log`)
})

window.addEventListener('unhandledrejection', function (event) {
  toast('An error occurred. See log file.')

  console.error('Unhandled promise rejection:', event.reason)

  exec(`echo "Error (Unhandled Rejection): ${event.reason}\n\n${event.reason.stack}" > /data/adb/rezygisk/webui_error.log`)
})

window.addEventListener('popstate', async () => {
  if (history.state !== null) return;

  await loadPage('home')
})
