import { loadPage, allPages } from './pageLoader.js'

/* INFO: M3 navigation bar: active tab gets the .active class, which widens the
         icon container into a secondary-container pill.

         loadNavbar only wires up the click handlers; the active state is set
         later by loadPage('home') -> setNavbar('home'). Setting it here would
         make whichCurrentPage() return 'home' before loadPage runs, so
         loadPage('home') would short-circuit as "already on home" and never
         initialize the page, leaving the loading screen up forever. */
export function loadNavbar() {
  document.querySelectorAll('.nav-tab').forEach((tab) => {
    tab.addEventListener('click', async (event) => {
      event.preventDefault()
      await loadPage(tab.dataset.page)
    })
  })
}

function setActive(page) {
  allPages.forEach((p) => {
    document.querySelector(`.nav-tab[data-page="${p}"]`)?.classList.toggle('active', p === page)
  })
}

export function setNavbar(page) {
  setActive(page)
}

export function whichCurrentPage() {
  return allPages.find((page) => document.querySelector(`.nav-tab[data-page="${page}"]`)?.classList.contains('active')) ?? null
}
