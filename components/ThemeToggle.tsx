'use client'

import { useSyncExternalStore } from 'react'
import { Moon, Sun } from 'lucide-react'

type Theme = 'light' | 'dark'

export const THEME_STORAGE_KEY = 'triage24:theme'

function subscribe(onChange: () => void): () => void {
  const observer = new MutationObserver(onChange)
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
  return () => observer.disconnect()
}

function currentTheme(): Theme {
  return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light'
}

/** Switches between light and dark; the choice is remembered in this browser. */
export default function ThemeToggle() {
  // null on the server: the theme is only known once the page runs in the browser.
  const theme = useSyncExternalStore(subscribe, currentTheme, () => null)
  if (theme === null) return <span className="h-8 w-8" aria-hidden="true" />

  const next: Theme = theme === 'dark' ? 'light' : 'dark'
  const Icon = theme === 'dark' ? Sun : Moon

  return (
    <button
      type="button"
      onClick={() => {
        document.documentElement.dataset.theme = next
        try {
          localStorage.setItem(THEME_STORAGE_KEY, next)
        } catch {
          // Storage disabled: the choice lasts until the page is reloaded.
        }
      }}
      className="flex h-8 w-8 items-center justify-center text-ink-inverse/80 hover:bg-white/10 hover:text-ink-inverse"
      aria-label={`Switch to ${next} mode`}
      title={`Switch to ${next} mode`}
    >
      <Icon className="h-4 w-4" aria-hidden="true" />
    </button>
  )
}
