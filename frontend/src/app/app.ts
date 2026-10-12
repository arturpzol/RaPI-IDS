import { Component, OnDestroy, OnInit, computed, effect, inject, signal, untracked } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { Api } from './core/api';
import { Auth } from './core/auth';
import { Live } from './core/live';
import { Theme, ThemeMode } from './core/theme';
import { ModuleInfo } from './core/models';

/** Icons as inline SVG - no external dependencies and no web fonts. */
const ICON_PATHS: Record<string, string> = {
  shield: 'M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z',
  // Drawn across the filled shield of the brand mark: watching the traffic.
  pulse: 'M7 12.5h2.4l1.4-3.2 2.4 6 1.4-2.8H17',
  cpu: 'M6 6h12v12H6zM9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3',
  gauge: 'M12 21a9 9 0 1 0-9-9 9 9 0 0 0 9 9ZM12 12l4-4',
  network: 'M5 3h6v6H5zM13 15h6v6h-6zM8 9v6h8',
  menu: 'M3 6h18M3 12h18M3 18h18',
  pause: 'M9 4v16M15 4v16',
  play: 'M6 3.5 20 12 6 20.5V3.5Z',
  sun: 'M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10ZM12 1v3M12 20v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M1 12h3M20 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1',
  moon: 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z',
  monitor: 'M3 4h18v12H3zM8 20h8M12 16v4',
  logout: 'M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h5M16 8l4 4-4 4M20 12H9',
};

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App implements OnInit, OnDestroy {
  private api = inject(Api);
  private router = inject(Router);
  protected live = inject(Live);
  protected auth = inject(Auth);
  protected theme = inject(Theme);

  protected readonly modules = signal<ModuleInfo[]>([]);
  protected readonly version = signal<string>('');
  protected readonly sidebarOpen = signal(false);

  /** Badge with the number of new alerts next to the IDS module. */
  protected readonly newAlerts = computed(() => this.live.newAlertCount());

  /** Navigation, version and the live stream all need a session; asking for them
   *  before one exists would only produce 401s on the sign-in page. Declared as
   *  a field because effect() needs an injection context, which ngOnInit is not. */
  private readonly shellLoader = effect(() => {
    if (!this.auth.signedIn()) {
      this.modules.set([]);
      this.live.disconnect();
      return;
    }
    // untracked, or reading the signals inside loadShell would re-subscribe the
    // effect to them and re-run it on every stream update.
    untracked(() => this.loadShell());
  });

  ngOnInit(): void {
    // The route guards resolve the session; nothing to do here but wait.
  }

  private loadShell(): void {
    this.api.modules().subscribe({
      next: (res) => this.modules.set(res.modules),
      error: () => this.modules.set([]),
    });
    this.api.health().subscribe({
      next: (res) => this.version.set(res.version),
      error: () => {},
    });
    this.live.connect();
  }

  /** One word in the top bar, on every page.
   *
   *  "live" is the only one that means the sensor is doing its job. The other
   *  four each name a different reason it is not, because "not live" covers a
   *  browser that lost its socket, a paused view, a stopped engine and an
   *  engine that is running and seeing nothing - and only the last two are
   *  worth waking up for.
   */
  protected sensorLabel(): string {
    // A restart the operator asked for is not a fault, and for half a minute it
    // looks exactly like one.
    if (this.live.restarting() && this.live.sensor() !== 'live') return 'restarting';
    switch (this.live.sensor()) {
      case 'disconnected': return 'disconnected';
      case 'paused':       return 'paused';
      case 'stopped':      return 'engine stopped';
      case 'idle':         return 'no traffic';
      default:             return 'live';
    }
  }

  protected sensorHint(): string {
    if (this.live.restarting() && this.live.sensor() !== 'live') {
      return 'The engine was restarted from the panel. The live stream comes '
           + 'back on its own. Nothing is lost: alerts are stored as they '
           + 'arrive and the pages still refresh.';
    }
    switch (this.live.sensor()) {
      case 'disconnected':
        return 'The live connection to the panel dropped. Pages still refresh '
             + 'by polling, but new alerts will not appear on their own until it '
             + 'reconnects.';
      case 'paused':
        return 'Incoming data is paused. The engine keeps working.';
      case 'stopped':
        return 'The detection engine is not running. Nothing is being inspected.';
      case 'idle':
        return 'The engine is running and its packet counter has not moved. '
             + 'Either the network is silent or the sensor is not being handed '
             + 'any traffic. Run scripts/verify.sh to tell those apart.';
      default:
        return 'The engine is running and packets are arriving.';
    }
  }

  protected signOut(): void {
    this.live.disconnect();
    this.auth.logout().subscribe({
      next: () => this.router.navigate(['/login']),
      // The cookie is gone locally either way; the screen must not get stuck.
      error: () => this.router.navigate(['/login']),
    });
  }

  ngOnDestroy(): void {
    this.live.disconnect();
  }

  /** Icon names the label of the mode you are in, not the one you would switch
   *  to - a switch that shows its destination is read backwards half the time. */
  protected themeIcon(): string {
    const icons: Record<ThemeMode, string> = { system: 'monitor', light: 'sun', dark: 'moon' };
    return icons[this.theme.mode()];
  }

  protected themeLabel(): string {
    const mode = this.theme.mode();
    return mode === 'system' ? `Theme: follows the system (${this.theme.resolved()})` : `Theme: ${mode}`;
  }

  protected iconPath(icon: string): string {
    return ICON_PATHS[icon] ?? ICON_PATHS['gauge'];
  }

  protected toggleSidebar(): void {
    this.sidebarOpen.update((v) => !v);
  }

  protected closeSidebar(): void {
    this.sidebarOpen.set(false);
  }
}
