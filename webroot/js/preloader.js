import { fullScreen } from './kernelsu.js'
import { setAmoled } from './themes/amoled.js'
import { detectedLanguage } from './pages/pageLoader.js'

setAmoled()

document.getElementById('main_html').setAttribute('dir', detectedLanguage === 'ar_EG' ? 'rtl' : 'ltr')

fullScreen(true)
