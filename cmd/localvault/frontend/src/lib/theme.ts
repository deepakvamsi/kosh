// applyTheme sets the document theme so the CSS variables in style.css switch. "light"
// activates the light palette via <html data-theme="light">; anything else is the default
// dark palette (attribute removed). Purely local — no network, no storage side effects.
export function applyTheme(theme: string) {
  const root = document.documentElement
  if (theme === 'light') {
    root.setAttribute('data-theme', 'light')
  } else {
    root.removeAttribute('data-theme')
  }
}
