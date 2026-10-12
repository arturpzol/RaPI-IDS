import { provideRouter } from '@angular/router';
import { ComponentFixture, TestBed, discardPeriodicTasks, fakeAsync, tick }
  from '@angular/core/testing';
import { of, throwError } from 'rxjs';

import { Api } from '../../core/api';
import { LoadHistory, SystemMetrics } from '../../core/models';
import { System } from './system';

function metrics(overrides: Record<string, unknown> = {}): SystemMetrics {
  return {
    timestamp: 0,
    cpu: {
      percent: 12, per_core: [10, 12, 14, 12], temperature_c: 47,
      load_avg: { '1m': 0.4, '5m': 0.3, '15m': 0.2 },
    },
    memory: { total: 8e9, used: 2e9, available: 6e9, percent: 25 },
    swap: { total: 0, used: 0, percent: 0 },
    disk: { total: 1e11, used: 5e10, free: 5e10, percent: 50 },
    throttling: null,
    uptime_seconds: 7200,
    ...overrides,
  } as SystemMetrics;
}

function history(
  points: Partial<{ ts: number; cpu: number; cpu_peak: number; temp: number | null; memory: number }>[],
  overrides: Partial<LoadHistory> = {},
): LoadHistory {
  return {
    hours: 1,
    source: 'minute',
    resolution_seconds: 60,
    retention_hours: 24 * 7,
    first_sample: 1_779_000_000,
    points: points.map((p) => ({
      ts: 1_780_000_000, cpu: 10, cpu_peak: 10, temp: 45, memory: 30, ...p,
    })),
    ...overrides,
  } as LoadHistory;
}

describe('System', () => {
  let fixture: ComponentFixture<System>;
  let component: any;
  let api: jasmine.SpyObj<Api>;

  function build() {
    fixture = TestBed.createComponent(System);
    component = fixture.componentInstance;
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  beforeEach(() => {
    api = jasmine.createSpyObj<Api>('Api', [
      'systemInfo', 'systemMetrics', 'systemHistory', 'network', 'suricataStatus', 'sshAccess',
    ]);
    api.sshAccess.and.returnValue(of({ active: true, source: 'panel', login: 'rapi' }));
    api.systemInfo.and.returnValue(of({
      hostname: 'rapi-ids', model: 'Raspberry Pi 5', os: 'Debian 13', kernel: '6.18',
      python: '3.13', boot_time: 0, uptime_seconds: 7200,
    } as any));
    api.systemMetrics.and.returnValue(of(metrics()));
    api.systemHistory.and.returnValue(of(history([{ cpu: 10 }, { cpu: 20, cpu_peak: 90 }])));
    api.network.and.returnValue(of({ interfaces: [] } as any));
    api.suricataStatus.and.returnValue(of({ capture: { interfaces: [] } } as any));
    TestBed.configureTestingModule({
      providers: [{ provide: Api, useValue: api }, provideRouter([])],
    });
  });

  afterEach(() => fixture?.destroy());

  it('does not ask about the capture interface on the metrics timer', fakeAsync(() => {
    // Measured: one /api/suricata/status forks four processes and takes 28 ms.
    // On the 3 s metrics timer that was 80 processes a minute on a Pi, for a
    // badge that changes when somebody runs the wizard and not otherwise.
    build();
    const atStart = api.suricataStatus.calls.count();
    const metricsAtStart = api.systemMetrics.calls.count();

    tick(9_000);                        // three metrics ticks
    expect(api.systemMetrics.calls.count()).toBe(metricsAtStart + 3);
    expect(api.suricataStatus.calls.count()).toBe(atStart);

    tick(6_000);                        // past the capture tick at 15 s
    expect(api.suricataStatus.calls.count()).toBe(atStart + 1);

    discardPeriodicTasks();
  }));

  it('does not report a board with no thermal sensor as running normally', () => {
    // `?? 0` turned "no reading" into zero degrees in good order, on the tile
    // whose whole job is to say when the board is too hot.
    api.systemMetrics.and.returnValue(of(metrics({
      cpu: { ...metrics().cpu, temperature_c: null },
    })));
    const dom = build();
    const tile = Array.from(dom.querySelectorAll('.tile'))
      .find((t) => t.textContent?.includes('CPU temperature'))!;
    expect(tile.textContent).toContain('no reading');
    expect(tile.textContent).not.toContain('normal');
    expect(tile.textContent).not.toContain('\u00b0C');
    expect(tile.classList).not.toContain('alarm');
  });

  describe('remote access', () => {
    function card(): string {
      return build().querySelector('.ssh-card')?.textContent?.replace(/\s+/g, ' ') ?? '';
    }

    it('names the login and says the password is the panel one', () => {
      const text = card();
      expect(text).toContain('Log in as rapi with the panel password');
      // The panel knows this password, so it must not look like a way to root.
      expect(text).toContain('cannot use sudo');
      expect(text).toContain('ssh rapi@rapi-ids.local');
      expect(text).toContain('sudo systemctl disable --now ssh.service ssh.socket');
    });

    it('does not claim a password that came with the card', () => {
      api.sshAccess.and.returnValue(of({ active: true, source: 'card', login: 'pi' }));
      const text = card();
      expect(text).toContain('Log in as pi with the password set when the card was prepared');
      expect(text).toContain('ssh pi@rapi-ids.local');
      expect(text).not.toContain('panel password');
    });

    it('points at the key when the card came with a key and no password', () => {
      api.sshAccess.and.returnValue(of({ active: true, source: 'key', login: 'rapi' }));
      const text = card();
      expect(text).toContain('Log in as rapi with the key given when the card was prepared');
      expect(text).not.toContain('password');
    });

    it('does not claim somebody\'s own login either', () => {
      api.sshAccess.and.returnValue(of({ active: true, source: 'other', login: 'rapi' }));
      expect(card()).toContain('the panel does not change it');
      expect(card()).not.toContain('with the panel password');
    });

    it('says when it is off, and how to switch it on', () => {
      api.sshAccess.and.returnValue(of({ active: false, source: 'panel', login: 'rapi' }));
      const text = card();
      expect(text).toContain('SSH is off.');
      expect(text).toContain('sudo systemctl enable --now ssh.service');
      expect(text).not.toContain('ssh rapi@');
    });

    it('shows nothing rather than a guess when the device cannot say', () => {
      api.sshAccess.and.returnValue(throwError(() => ({ status: 500 })));
      expect(build().querySelector('.ssh-card')).toBeNull();
    });
  });

  describe('the link speed', () => {
    function withLinks(links: Array<Record<string, unknown>>, capture: string[] = []) {
      api.network.and.returnValue(of({
        interfaces: links.map((l) => ({
          name: 'x', is_up: true, speed_mbps: 0, mtu: 1500, mac: null, ipv4: [],
          ipv6: [], bytes_sent: 0, bytes_recv: 0, packets_sent: 0, packets_recv: 0,
          errors_in: 0, errors_out: 0, drops_in: 0, ...l,
        })),
      } as any));
      api.suricataStatus.and.returnValue(of({
        capture: {
          interfaces: capture.map((name) => ({
            name, present: true, up: true, carrier: true, operstate: 'up', promisc: true,
          })),
        },
      } as any));
    }

    it('says what the wire negotiated, in the units people use', () => {
      withLinks([{ name: 'eth1', speed_mbps: 1000 }, { name: 'eth0', speed_mbps: 100 }]);
      const dom = build();
      const speeds = Array.from(dom.querySelectorAll('tbody tr'))
        .map((row) => row.children[2].textContent!.trim());
      expect(speeds).toEqual(['1 Gb/s', '100 Mb/s']);
    });

    it('does not turn an interface with no fixed rate into a fault', () => {
      // The loopback and wireless report zero, which is not a speed problem.
      withLinks([{ name: 'wlan0', speed_mbps: 0 }]);
      const dom = build();
      const cell = dom.querySelector('tbody tr')!.children[2];
      expect(cell.textContent!.trim()).toBe('-');
      expect(cell.classList).not.toContain('bad');
    });

    it('marks a capture port that came up below a gigabit', () => {
      // A rack move left one port of the inline pair at 100 Mb/s, and the
      // whole link ran at a tenth of its speed with nothing saying so.
      withLinks([{ name: 'eth0', speed_mbps: 100 }, { name: 'eth1', speed_mbps: 1000 },
                 { name: 'wlan0', speed_mbps: 100 }], ['eth0', 'eth1']);
      const dom = build();
      const marked = Array.from(dom.querySelectorAll('tbody tr'))
        .filter((row) => row.children[2].classList.contains('bad'))
        .map((row) => row.children[0].textContent!.trim());
      expect(marked).toEqual(['eth0 capture']);
    });
  });

  describe('the capture badge', () => {
    function withCapture(link: Record<string, unknown>) {
      api.suricataStatus.and.returnValue(of({
        capture: { interfaces: [{ name: 'eth0', present: true, up: true,
                                  carrier: true, operstate: 'up', promisc: true,
                                  ...link }] },
      } as any));
    }

    it('marks only the interface the engine listens on', () => {
      withCapture({});
      build();
      expect(component.captureRole('eth0')).toEqual({ label: 'capture', warn: null });
      expect(component.captureRole('wlan0')).toBeNull();
    });

    it('says when a capture interface cannot hand the engine anything', () => {
      // Each of these renders as a quiet, working sensor otherwise: the service
      // reports itself running and the alert count simply stops moving.
      const cases: Array<[Record<string, unknown>, string]> = [
        [{ present: false }, 'configured but missing'],
        [{ up: false }, 'down'],
        [{ carrier: false }, 'no cable'],
        [{ promisc: false }, 'not promiscuous'],
      ];
      for (const [link, expected] of cases) {
        withCapture(link);
        const local = TestBed.createComponent(System);
        local.detectChanges();
        expect((local.componentInstance as any).captureRole('eth0').warn).toBe(expected);
        local.destroy();
      }
    });

    it('shows no badge when the IDS module cannot be asked', () => {
      // A panel built without the module is not a panel with a broken sensor.
      api.suricataStatus.and.returnValue(throwError(() => new Error('404')));
      build();
      expect(component.captureRole('eth0')).toBeNull();
    });
  });

  it('draws the history the backend kept, not what this tab has seen', () => {
    // Two minutes of browser-side history answers no question anyone has.
    build();
    expect(api.systemHistory).toHaveBeenCalledWith(1);
    expect(component.cpuChart().length).toBe(2);
  });

  it('carries the peak next to the average', () => {
    build();
    expect(component.cpuChart()[1].note).toContain('90');
  });

  it('says what one point on the chart covers', () => {
    build();
    expect(component.resolutionLabel()).toBe('1 min average');
    api.systemHistory.and.returnValue(of(history([{}], { resolution_seconds: 480 })));
    component.setHistoryHours('24');
    expect(api.systemHistory).toHaveBeenCalledWith(24);
    expect(component.resolutionLabel()).toBe('8 min average');
  });

  it('counts in hours and days once a point covers that much', () => {
    build();
    api.systemHistory.and.returnValue(of(history([{}], {
      source: 'hour', resolution_seconds: 3600,
    })));
    component.setHistoryHours('168');
    expect(component.resolutionLabel()).toBe('1 h average');

    api.systemHistory.and.returnValue(of(history([{}], {
      source: 'hour', resolution_seconds: 86400 * 2,
    })));
    component.setHistoryHours('0');
    expect(component.resolutionLabel()).toBe('2 day average');
  });

  it('offers windows longer than a day, up to everything on record', () => {
    build();
    const values = component.historyOptions.map((o: any) => o.value);
    expect(values).toContain(24 * 7);
    expect(values).toContain(24 * 30);
    expect(values).toContain(0);   // everything
  });

  it('treats "everything" as a window, not as a missing value', () => {
    // Number('0') is falsy, so a fallback with || would silently send 1 hour.
    build();
    component.setHistoryHours('0');
    expect(api.systemHistory).toHaveBeenCalledWith(0);
    expect(component.historyHours()).toBe(0);
  });

  it('falls back to an hour when the select hands over nonsense', () => {
    build();
    component.setHistoryHours('later');
    expect(component.historyHours()).toBe(1);
  });

  it('labels the axis with a clock on an hour window and a date on a long one', () => {
    // "14:00" repeated across a month says nothing about which day anything
    // happened on.
    // The clock format itself follows the viewer's locale, so the assertion is
    // about which one is used, not about how that locale writes it.
    build();
    expect(component.cpuChart()[0].label).toContain(':');
    api.systemHistory.and.returnValue(of(history([{}], {
      source: 'hour', resolution_seconds: 3600,
    })));
    component.setHistoryHours('720');
    expect(component.cpuChart()[0].label).not.toContain(':');
  });

  it('says how far back the history actually goes', () => {
    // A device switched on this morning has nothing to show for "last 30
    // days", and an empty chart on its own looks like a fault.
    build();
    expect(component.coverageLabel()).toContain('since');
    api.systemHistory.and.returnValue(of(history([{}], { first_sample: null })));
    component.setHistoryHours('1');
    expect(component.coverageLabel()).toBe('');
  });

  it('says when a window is drawn from hourly averages', () => {
    build();
    expect(component.detailNote()).toBe('');
    api.systemHistory.and.returnValue(of(history([{}], {
      source: 'hour', resolution_seconds: 3600, retention_hours: 24 * 7,
    })));
    component.setHistoryHours('720');
    expect(component.detailNote()).toContain('7 days');
  });

  it('skips a missing temperature instead of drawing it as zero', () => {
    // Some boards have no thermal zone, and a plunge to 0 degrees reads as a
    // measurement rather than as a gap.
    api.systemHistory.and.returnValue(of(history([{ temp: 45 }, { temp: null }, { temp: 46 }])));
    build();
    expect(component.tempChart().length).toBe(2);
    expect(component.memoryChart().length).toBe(3);
  });

  it('has nothing to say about throttling on a board that does not report it', () => {
    build();
    expect(component.throttleWarnings()).toEqual([]);
  });

  it('warns about what is happening now', () => {
    api.systemMetrics.and.returnValue(of(metrics({
      throttling: {
        raw: '0x50005', under_voltage_now: true, frequency_capped_now: false,
        throttled_now: false, soft_temp_limit_now: false,
      },
    })));
    build();
    const warnings = component.throttleWarnings();
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toContain('RIGHT NOW');
    expect(warnings[0]).toContain('power supply');
  });

  it('says nothing about a hot quarter of an hour three days ago', () => {
    // 0xe0000 is what this device reported after an image build: the board's
    // sticky bits set, nothing wrong now. Those bits stay lit until a reboot,
    // so the warning stood for three days on a machine that had been cool the
    // whole time, and it could not say when it happened or how hot it got. A
    // warning nobody can clear teaches people to ignore the box it lives in,
    // and the live under-voltage line lives in that same box.
    api.systemMetrics.and.returnValue(of(metrics({
      throttling: {
        raw: '0xe0000', under_voltage_now: false, frequency_capped_now: false,
        throttled_now: false, soft_temp_limit_now: false,
      },
    })));
    build();
    expect(component.throttleWarnings()).toEqual([]);
    expect((fixture.nativeElement as HTMLElement).textContent)
      .not.toContain('Hardware warning');
  });

  it('reports a backend it cannot reach', () => {
    api.systemMetrics.and.returnValue(throwError(() => ({ message: 'Http failure' })));
    build();
    expect(component.error()).toContain('Http failure');
  });

  it('stops polling when the view goes away', () => {
    build();
    expect(component.timers.length).toBeGreaterThan(0);
    fixture.destroy();
    expect(component.timers.length).toBe(0);
  });
});
