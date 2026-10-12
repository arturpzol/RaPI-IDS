import { Component, OnDestroy, OnInit, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';

import { Api } from '../../core/api';
import { DurationPipe, NumberPipe, formatBytes } from '../../core/format';
import {
  CaptureLink, LoadHistory, LoadPoint, NetworkInterface, SshAccess, SystemInfo,
  SystemMetrics,
} from '../../core/models';
import { ChartDatum, LineChart } from '../../shared/line-chart';
import { Meter } from '../../shared/meter';
import { StatTile } from '../../shared/stat-tile';

const METRICS_REFRESH_MS = 3_000;

/** The chart moves one point a minute at its finest, so asking more often than
 *  that only costs requests. */
const HISTORY_REFRESH_MS = 30_000;

/** The capture interface, which changes when somebody runs the wizard and not
 *  otherwise.
 *
 *  Measured on this device: one /api/suricata/status forks four processes
 *  (systemctl three times, suricata -V once) and takes 28 ms. On the metrics
 *  timer that was 80 processes a minute on a Pi, for a badge that is the same
 *  from one week to the next. The dashboard asks the same endpoint every 30 s
 *  and the IDS page every 10 s. */
const CAPTURE_REFRESH_MS = 15_000;

@Component({
  selector: 'app-system',
  imports: [LineChart, Meter, StatTile, NumberPipe, DurationPipe, RouterLink],
  templateUrl: './system.html',
  styleUrl: './system.css',
})
export class System implements OnInit, OnDestroy {
  private api = inject(Api);

  protected readonly info = signal<SystemInfo | null>(null);
  protected readonly metrics = signal<SystemMetrics | null>(null);
  protected readonly interfaces = signal<NetworkInterface[]>([]);
  /** Capture interfaces as the engine has them, keyed by name below. */
  protected readonly capture = signal<CaptureLink['interfaces']>([]);
  protected readonly error = signal<string | null>(null);
  protected readonly ssh = signal<SshAccess | null>(null);

  /** How to get in over SSH, in one sentence, or null while it is unknown.
   *
   *  Whose password it takes decides the sentence: the panel only sets it on
   *  an account it found locked, so a password that came with the card, or a
   *  checkout's own login, is described rather than claimed. */
  protected readonly sshHow = computed<string | null>(() => {
    const s = this.ssh();
    if (!s) return null;
    if (!s.active) return 'SSH is off.';
    const who = s.login ?? 'rapi';
    switch (s.source) {
      case 'panel':
        // No sudo on purpose: the panel knows this password and could set it,
        // so it must not lead to root. An account from the card can.
        return `SSH is on. Log in as ${who} with the panel password. ` +
          'That account cannot use sudo; an account whose password was set when ' +
          'the card was prepared can.';
      case 'card':
        return `SSH is on. Log in as ${who} with the password set when the card was prepared.`;
      case 'key':
        return `SSH is on. Log in as ${who} with the key given when the card was prepared.`;
      case 'other':
        return `SSH is on. Log in as ${who} with that account's own password; the panel does not change it.`;
      case 'none':
        return `SSH is on, but ${who} has no password yet, so only a key gets in. ` +
          'It takes the panel password the next time that is changed.';
      default:
        return 'SSH is on.';
    }
  });

  /** Sampled by the backend, so it survives leaving the page. */
  protected readonly history = signal<LoadHistory | null>(null);
  protected readonly historyHours = signal(1);

  private timers: ReturnType<typeof setInterval>[] = [];

  /** What to say about one interface's role, or null when it has none.
   *
   *  Two separate facts, and the second is the one that catches the failure
   *  this project has already been bitten by: an interface can be named in the
   *  engine's configuration and still hand it nothing.
   */
  protected captureRole(name: string): { label: string; warn: string | null } | null {
    const link = this.capture().find((l) => l.name === name);
    if (!link) return null;
    if (!link.present) return { label: 'capture', warn: 'configured but missing' };
    if (!link.up) return { label: 'capture', warn: 'down' };
    if (!link.carrier) return { label: 'capture', warn: 'no cable' };
    if (!link.promisc) {
      // A mirror port only ever delivers frames addressed to other machines.
      return { label: 'capture', warn: 'not promiscuous' };
    }
    return { label: 'capture', warn: null };
  }

  protected readonly cpuChart = computed<ChartDatum[]>(() =>
    (this.history()?.points ?? []).map((point) => {
      const at = new Date(point.ts * 1000);
      return {
        label: this.axisLabel(at),
        title: at.toLocaleString(undefined, {
          day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit',
        }),
        value: Math.round(point.cpu),
        // The line is an average over the step, which on a 24 h window is eight
        // minutes. Without the peak beside it, a burst that pinned every core
        // for half a minute would show up as a barely visible bump.
        note: `peak ${Math.round(point.cpu_peak)} %`,
      };
    }),
  );

  protected readonly tempChart = computed(() => this.series((point) => point.temp));
  protected readonly memoryChart = computed(() => this.series((point) => point.memory));

  /** A clock on an hour-wide axis and a date on a week-wide one. The axis has
   *  room for one or the other, and "14:00" repeated across a month says
   *  nothing about which day anything happened on. */
  private axisLabel(at: Date): string {
    const seconds = this.history()?.resolution_seconds ?? 60;
    if (seconds >= 3600) {
      return at.toLocaleDateString(undefined, { day: '2-digit', month: '2-digit' });
    }
    return clock(at);
  }

  /** Shared shape of the secondary charts: same X axis, no peak to report.
   *  A point with no reading is skipped rather than drawn as zero - the
   *  thermal zone is missing on some boards, and a plunge to 0 degrees would
   *  read as a measurement, not as a gap. */
  private series(pick: (point: LoadPoint) => number | null): ChartDatum[] {
    const out: ChartDatum[] = [];
    for (const point of this.history()?.points ?? []) {
      const value = pick(point);
      if (value === null) continue;
      const at = new Date(point.ts * 1000);
      out.push({
        label: this.axisLabel(at),
        title: at.toLocaleString(undefined, {
          day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit',
        }),
        value: Math.round(value * 10) / 10,
      });
    }
    return out;
  }

  /** What one point on the chart actually covers, said out loud. */
  protected readonly resolutionLabel = computed(() => {
    const seconds = this.history()?.resolution_seconds ?? 60;
    if (seconds >= 86400) {
      const days = Math.round(seconds / 86400);
      return days === 1 ? '1 day average' : `${days} day average`;
    }
    if (seconds >= 3600) {
      const hours = Math.round(seconds / 3600);
      return hours === 1 ? '1 h average' : `${hours} h average`;
    }
    const minutes = Math.max(1, Math.round(seconds / 60));
    return minutes === 1 ? '1 min average' : `${minutes} min average`;
  });

  /** How far the history actually goes back, which is not the same as the
   *  window asked for: a device switched on this morning has nothing to show
   *  for "last 30 days", and an empty chart on its own looks like a fault. */
  protected readonly coverageLabel = computed(() => {
    const first = this.history()?.first_sample;
    if (!first) return '';
    return `since ${new Date(first * 1000).toLocaleString(undefined, {
      day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit',
    })}`;
  });

  /** Minute detail has a retention; the hourly averages behind the long windows
   *  do not. Said once, next to the window that is affected. */
  protected readonly detailNote = computed(() => {
    const history = this.history();
    if (!history || history.source === 'minute') return '';
    const days = Math.round(history.retention_hours / 24);
    return `hourly averages. Minute detail is kept for ${days} days`;
  });

  /** Zero is "everything on record". Minute detail runs out after a week and
   *  the longer windows are drawn from hourly averages, which are kept for as
   *  long as the device has been running. */
  protected readonly historyOptions = [
    { value: 1, label: 'Last hour' },
    { value: 6, label: 'Last 6 hours' },
    { value: 24, label: 'Last 24 hours' },
    { value: 24 * 7, label: 'Last 7 days' },
    { value: 24 * 30, label: 'Last 30 days' },
    { value: 0, label: 'Everything' },
  ];

  protected readonly perCore = computed(() => this.metrics()?.cpu.per_core ?? []);

  protected readonly throttleWarnings = computed(() => {
    const t = this.metrics()?.throttling;
    if (!t) return [];
    const out: string[] = [];
    if (t.under_voltage_now) out.push('Under-voltage RIGHT NOW. Check the power supply');
    if (t.throttled_now) out.push('Throttling RIGHT NOW. The CPU slowed down because of temperature');
    if (t.frequency_capped_now) out.push('Frequency capped RIGHT NOW');
    if (t.soft_temp_limit_now) out.push('Soft temperature limit reached');
    // Only what is happening now. The board also carries two sticky bits for
    // "this happened at some point since boot", and they were shown here until
    // one hot quarter of an hour during an image build left a warning standing
    // for three days on a device that had been cool ever since - without
    // saying when, or how hot. See _throttled() in the system router.
    return out;
  });

  ngOnInit(): void {
    this.api.systemInfo().subscribe({
      next: (i) => this.info.set(i),
      error: (err) => this.error.set(err?.message ?? 'Could not fetch system information'),
    });
    this.loadMetrics();
    this.loadNetwork();
    this.loadCapture();
    this.loadHistory();
    // Changes only when somebody sets a password or switches SSH at the
    // console, so once per visit is enough.
    this.api.sshAccess().subscribe({ next: (s) => this.ssh.set(s), error: () => {} });
    this.timers.push(setInterval(() => {
      this.loadMetrics();
      this.loadNetwork();
    }, METRICS_REFRESH_MS));
    this.timers.push(setInterval(() => this.loadCapture(), CAPTURE_REFRESH_MS));
    this.timers.push(setInterval(() => this.loadHistory(), HISTORY_REFRESH_MS));
  }

  ngOnDestroy(): void {
    this.timers.forEach(clearInterval);
    this.timers = [];
  }

  protected setHistoryHours(value: string): void {
    // Number('0') is falsy and 0 is a real window here ("everything"), so this
    // cannot fall back with ||.
    const hours = Number(value);
    this.historyHours.set(Number.isFinite(hours) && hours >= 0 ? hours : 1);
    this.loadHistory();
  }

  /** Whether this board reports a temperature at all. Not every one does, and
   *  "no reading" and "cool" are not the same answer. */
  protected readonly hasTemperature = computed(
    () => typeof this.metrics()?.cpu?.temperature_c === 'number');

  protected bytes(value: number | null | undefined): string {
    return formatBytes(value);
  }

  /** What the wire negotiated, in the units people say out loud.
   *
   *  Zero is what the kernel reports for an interface that has no fixed speed
   *  to report at all: the loopback, and wireless, whose rate changes with
   *  every frame. That is not a fault and must not read as one.
   */
  protected linkSpeed(mbps: number | null | undefined): string {
    if (!mbps || mbps <= 0) return '-';
    return mbps >= 1000 ? `${mbps / 1000} Gb/s` : `${mbps} Mb/s`;
  }

  /** A capture interface below a gigabit is worth pointing at.
   *
   *  Measured here: the inline pair came up with one port at 100 Mb/s after
   *  the device was moved into a rack, and the whole link ran at a tenth of
   *  the speed with nothing on any screen saying so. Only for the interfaces
   *  the engine uses: the panel's own wired port is nobody's bottleneck.
   */
  protected slowLink(i: NetworkInterface): boolean {
    return !!this.captureRole(i.name) && i.is_up
      && i.speed_mbps > 0 && i.speed_mbps < 1000;
  }

  private loadMetrics(): void {
    this.api.systemMetrics().subscribe({
      next: (m) => {
        this.metrics.set(m);
        this.error.set(null);
      },
      error: (err) => this.error.set(err?.message ?? 'No contact with the backend'),
    });
  }

  private loadHistory(): void {
    this.api.systemHistory(this.historyHours()).subscribe({
      next: (h) => this.history.set(h),
      error: () => {},
    });
  }

  private loadNetwork(): void {
    this.api.network().subscribe({
      next: (res) => this.interfaces.set(res.interfaces),
      error: () => {},
    });
  }

  /** Which interfaces the IDS is listening on.
   *
   *  Asked of the IDS module rather than of /api/system/network, because
   *  knowing it means reading the engine's own configuration and that is not
   *  something a core page should be doing. A panel built without the module,
   *  or with the engine stopped, simply gets no answer and shows no badge -
   *  which is the truth in both cases.
   */
  private loadCapture(): void {
    this.api.suricataStatus().subscribe({
      next: (s) => this.capture.set(s.capture?.interfaces ?? []),
      error: () => this.capture.set([]),
    });
  }
}

/** HH:MM in the viewer's locale - the axis has no room for anything more. */
function clock(at: Date): string {
  return at.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}
