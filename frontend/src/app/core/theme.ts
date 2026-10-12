import { Injectable, signal } from '@angular/core';

export type ThemeMode = 'system' | 'light' | 'dark';

/** Key shared with the inline script in index.html - keep the two in step. */
const STORAGE_KEY = 'rapi-theme';
const ORDER: ThemeMode[] = ['system', 'light', 'dark'];

/** Light/dark selection.
 *
 *  "system" is a real third state, not a default that disappears once you touch
 *  the switch: someone who wants the panel to follow the machine at sunset has
 *  to be able to say so and get back to it.
 *
 *  The resolved value is written to data-theme on <html>; the stylesheet only
 *  ever looks at that attribute. index.html does the same thing in an inline
 *  script before first paint, so the page never flashes the wrong palette.
 */
@Injectable({ providedIn: 'root' })
export class Theme {
  private readonly media = window.matchMedia('(prefers-color-scheme: light)');

  readonly mode = signal<ThemeMode>(readStoredMode());
  /** What is actually on screen - "system" resolved against the OS setting. */
  readonly resolved = signal<'light' | 'dark'>('dark');

  constructor() {
    this.apply();
    // Following the OS means following it while the panel is open, not only at
    // load: this fires when the machine flips theme on a schedule.
    this.media.addEventListener('change', () => {
      if (this.mode() === 'system') this.apply();
    });
  }

  set(mode: ThemeMode): void {
    this.mode.set(mode);
    try {
      localStorage.setItem(STORAGE_KEY, mode);
    } catch {
      // Private mode or a full quota: the choice just will not survive a reload.
    }
    this.apply();
  }

  /** Cycles system -> light -> dark -> system. */
  next(): void {
    this.set(ORDER[(ORDER.indexOf(this.mode()) + 1) % ORDER.length]);
  }

  private apply(): void {
    const mode = this.mode();
    const resolved = mode === 'system' ? (this.media.matches ? 'light' : 'dark') : mode;
    this.resolved.set(resolved);
    document.documentElement.dataset['theme'] = resolved;
  }
}

function readStoredMode(): ThemeMode {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'light' || stored === 'dark' || stored === 'system') return stored;
  } catch {
    // Storage unavailable - fall back to following the machine.
  }
  return 'system';
}
