import { fullScreen } from './kernelsu.js'
import { detectedLanguage } from './pages/pageLoader.js'

document.documentElement.setAttribute('dir', detectedLanguage === 'ar_EG' ? 'rtl' : 'ltr')

fullScreen(true)
