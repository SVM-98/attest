export function initApp(doc: Document): void {
  const app = doc.getElementById('app')
  if (app) app.querySelector('p')!.textContent = 'Verifier ready.'
}

if (typeof document !== 'undefined') initApp(document)
