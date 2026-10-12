import {
  Component, OnDestroy, OnInit, computed, inject, signal,
} from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';

import { Api } from '../../core/api';
import { Live } from '../../core/live';
import { DurationPipe, NumberPipe, TimePipe, formatBytes } from '../../core/format';
import {
  Alert, AlertSummary, ET_SEVERITIES, GeoSummary, SystemMetrics, TopologyChoice,
  UNRATED, UNRATED_LABEL, severityClass, severityLabel,
} from '../../core/models';
import { ChartDatum, LineChart } from '../../shared/line-chart';
import { Meter } from '../../shared/meter';
import { RankItem, RankList } from '../../shared/rank-list';
import { StatTile } from '../../shared/stat-tile';
import { WorldMap } from '../../shared/world-map';

const SUMMARY_REFRESH_MS = 30_000;
const METRICS_REFRESH_MS = 5_000;

/** Windows the dashboard offers, in hours, keyed by the token that goes in the
 *  URL. The same tokens the alert list uses, so the tiles can link straight
 *  into it without translating.
 *
 *  The reason this is a choice at all: every figure on this screen lives in one
 *  window, so when a burst ages past the end of it, it leaves the tile, the
 *  chart and all three top-ten lists in the same instant. Nothing is left
 *  saying it ever happened, and a quiet day and a dead sensor then look
 *  identical. Widening the window is the cheapest way to tell them apart. */
const WINDOWS: Record<string, number> = { '24h': 24, '7d': 168, '30d': 720 };
const DEFAULT_WINDOW = '24h';

/** Stacking order: the least serious sits at the bottom, Critical on top.
 *  '' is the key for a rule ET has not rated. */
const TIMELINE_SEVERITIES = ['', ...[...ET_SEVERITIES].reverse()];

@Component({
  selector: 'app-dashboard',
  imports: [
    RouterLink, LineChart, RankList, StatTile, Meter, WorldMap,
    NumberPipe, DurationPipe, TimePipe,
  ],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.css',
})
export class Dashboard implements OnInit, OnDestroy {
  private api = inject(Api);
  private router = inject(Router);
  private route = inject(ActivatedRoute);
  protected live = inject(Live);

  /** Key of WINDOWS. Kept in the URL so a reload, or a link sent to somebody
   *  else, still shows the window that was being looked at. */
  protected readonly window = signal<string>(DEFAULT_WINDOW);
  private readonly hours = computed(() => WINDOWS[this.window()] ?? WINDOWS[DEFAULT_WINDOW]);

  /** Every card that names a window names this one.
   *
   *  Five card titles used to have "(24 h)" typed into them while the numbers
   *  under them came from the selector. Pick 30 days and the whole screen was
   *  labelled with the wrong period - a month of signature counts read as a
   *  day's badly overstates what is happening now. */
  protected readonly windowLabel = computed(
    () => this.windowOptions.find((o) => o.value === this.window())?.short ?? '24 h',
  );

  /** The same window as it reads inside a sentence rather than in brackets.
   *
   *  Named on the selector itself, because the sliding edge is the one thing
   *  about this screen nobody guesses: the figures it governs are measured
   *  back from now, so on a quiet night a count falls hour by hour with
   *  nothing touched and no new alert arriving. That looked like a bug for as
   *  long as the screen said "(24 h)" and left the reader to work out
   *  which 24. */
  protected readonly windowPhrase = computed(
    () => 'the ' + (this.windowOptions.find((o) => o.value === this.window())?.label
                    ?? 'Last 24 hours').toLowerCase(),
  );

  /** The chart's own bucket size, which is the server's decision and not the
   *  window's: above 48 hours it switches to one bar per day, and the title
   *  said "per hour" over thirty daily bars. */
  protected readonly timelineUnit = computed(
    () => this.summary()?.timeline_step_hours === 24 ? 'day' : 'hour',
  );

  /** What the period governs, on the control that sets it.
   *
   *  It used to stand under the title as three sentences on every visit: true,
   *  read once, and three lines tall above the numbers they explain. On the
   *  selector it is where somebody asks the question. */
  protected readonly windowHelp = computed(() =>
    'Covers the chart, the map, the lists and the blocked count: '
    + `${this.windowPhrase()} counted back from now, so those figures fall as `
    + 'alerts age out of it. Two things ignore it: the review queue, which '
    + 'only moves when an alert arrives or somebody clears it, and the rating '
    + 'tiles, which count today against yesterday and start again at midnight.');

  protected readonly windowOptions = [
    { value: '24h', label: 'Last 24 hours', short: '24 h' },
    { value: '7d', label: 'Last 7 days', short: '7 d' },
    { value: '30d', label: 'Last 30 days', short: '30 d' },
  ];

  protected readonly summary = signal<AlertSummary | null>(null);
  /** The last few alerts as stored, so the card has something to show before
   *  the stream has delivered anything. */
  protected readonly storedAlerts = signal<Alert[]>([]);
  protected readonly geo = signal<GeoSummary | null>(null);
  protected readonly metrics = signal<SystemMetrics | null>(null);
  protected readonly loadError = signal<string | null>(null);

  /** True until somebody has been through the layout wizard once.
   *
   *  Worth a request on every dashboard load because this is the screen where
   *  the consequence shows: an empty map and an empty alert list look the same
   *  whether the network is quiet or nothing is reaching the sensor. */
  protected readonly layoutUnknown = signal(false);
  /** The recorded layout, for the one place it changes what the screen says. */
  protected readonly layout = signal<TopologyChoice | null>(null);

  private timers: ReturnType<typeof setInterval>[] = [];
  private summaryRequest: Subscription | null = null;
  private geoRequest: Subscription | null = null;

  /** Merged from the stream and from REST - see Live.status. */
  protected readonly status = this.live.status;

  protected readonly timeline = computed<ChartDatum[]>(() => {
    const summary = this.summary();
    const rows = summary?.timeline ?? [];
    // A bucket is an hour on the short window and a day on the long ones, and
    // the two are indistinguishable from the data: "07" is either. The server
    // says which, because the server is what decided it.
    const daily = summary?.timeline_step_hours === 24;
    const day = (r: { bucket: string }) => r.bucket.slice(8, 10) + '/' + r.bucket.slice(5, 7);
    return rows.map((r) => ({
      // "2026-08-17T10:00" an hour at a time, "2026-08-17" a day at a time
      label: daily ? r.bucket.slice(8, 10) : r.bucket.slice(11, 13),
      title: daily ? day(r) : day(r) + ', ' + r.bucket.slice(11, 13) + ':00',
      value: r.count,
      // Splitting by severity turns "20 alerts" into "20 alerts, all minor" -
      // the same curve, but it now answers whether it matters.
      segments: TIMELINE_SEVERITIES.map((sev) => ({
        value: r.by_severity?.[sev] ?? 0,
        label: severityLabel(sev),
        className: severityClass(sev),
      })),
    }));
  });

  /** Only severities actually present, so the legend never lists empty classes. */
  protected readonly timelineLegend = computed(() => {
    const rows = this.summary()?.timeline ?? [];
    const present = new Set<string>();
    for (const row of rows) {
      for (const [sev, count] of Object.entries(row.by_severity ?? {})) {
        if (count > 0) present.add(sev);
      }
    }
    return TIMELINE_SEVERITIES.filter((s) => present.has(s)).map((sev) => ({
      label: severityLabel(sev),
      className: severityClass(sev),
    }));
  });

  /** Under the queue. Two facts, and no window in either of them: how big the
   *  backlog is against everything the panel has ever stored, and that this
   *  number will not shrink by itself while nobody looks.
   *
   *  The lifetime total earns its place by telling a device switched on an
   *  hour ago from one that has run a month with nobody reading it. */
  protected readonly pendingHint = computed(() => {
    const stored = this.summary()?.total_all_time ?? 0;
    const pending = this.summary()?.pending ?? 0;
    const total = `${stored.toLocaleString()} stored in total`;
    return pending > 0
      ? `of ${total}, and none of it ages out on its own`
      : `queue empty, ${total}`;
  });

  /** The engine's own events for today, named where the day's numbers are.
   *
   *  A promise being kept: retransmissions, parser complaints and notes about
   *  this machine are a quarter of what is stored and are outside every figure
   *  on this screen, because one video call used to outrank the week's real
   *  alerts. Leaving them out silently would be the worse of the two faults.
   *
   *  Counted over the same calendar day as the totals beside it, and a link
   *  rather than a number, because a figure nobody can open is one nobody can
   *  check. */
  protected readonly notesToday = computed(() => {
    const notes = this.summary()?.diagnostics_today ?? 0;
    return notes > 0 ? `${notes.toLocaleString()} engine notes` : '';
  });

  /** The top strip's second half: today by ET rating, one tile per tier.
   *
   *  A total says how many and never how serious. 417 alerts is a bad morning
   *  or a dull one depending entirely on whether one of them is Critical, and
   *  this breakdown used to sit in a rank list below the fold while the tiles
   *  above it shouted numbers nobody could act on.
   *
   *  Today, not the rolling window, for the same reason the totals are: a
   *  figure at the top of the screen that falls on its own is one nobody
   *  trusts. Yesterday rides along in the hint, because a rating on its own
   *  says nothing about whether this is normal for this network.
   *
   *  Zero prints as a dash. "0" reads as a measurement somebody took; on the
   *  Critical tile that is exactly the wrong impression to leave when the
   *  engine has been down all morning.
   *
   *  The unrated tier appears only when it holds something. It is not one of
   *  ET's tiers - it is the rules ET never graded - and a permanent tile that
   *  is empty on most devices would be the fifth thing to read before the
   *  first one that matters. Hiding it while it is empty hides nothing. */
  protected readonly ratingTiles = computed(() => {
    const counts = (rows: AlertSummary['by_severity'] | undefined) => {
      const map = new Map<string, number>();
      for (const r of rows ?? []) map.set(r.severity || UNRATED, r.count);
      return map;
    };
    const day = counts(this.summary()?.today_by_severity);
    const before = counts(this.summary()?.yesterday_by_severity);
    const tiers: string[] = [...ET_SEVERITIES, UNRATED];
    return tiers
      .filter((t) => t !== UNRATED
                     || (day.get(UNRATED) ?? 0) + (before.get(UNRATED) ?? 0) > 0)
      .map((tier) => {
        const now = day.get(tier) ?? 0;
        const was = before.get(tier) ?? 0;
        return {
          tier,
          label: tier === UNRATED ? UNRATED_LABEL : tier,
          value: now ? now.toLocaleString() : '-',
          tone: `rating ${severityClass(tier)}${now ? ' lit' : ''}`,
          hint: was ? `${was.toLocaleString()} yesterday` : 'none yesterday',
        };
      });
  });

  /** The pair the tiles used to be, now beside the chart they belong to: the
   *  chart is where a day's total means something, next to the shape of it. */
  protected readonly dayTotals = computed(() => {
    const s = this.summary();
    return {
      today: (s?.today ?? 0).toLocaleString(),
      yesterday: (s?.yesterday ?? 0).toLocaleString(),
    };
  });

  protected readonly signatureRanks = computed<RankItem[]>(() =>
    (this.summary()?.top_signatures ?? []).map((r) => ({
      label: r.signature ?? '(unnamed)',
      value: r.count,
      severityClass: severityClass(r.severity),
      key: r.signature_id,
    })),
  );

  protected readonly sourceRanks = computed<RankItem[]>(() =>
    (this.summary()?.top_sources ?? []).map((r) => ({
      label: r.src_ip,
      value: r.count,
      key: r.src_ip,
    })),
  );

  protected readonly geoCountries = computed(() => this.geo()?.countries ?? []);

  /** Says what the map is, and deliberately not how old the data behind it is.
   *
   *  The build date used to sit here, on the theory that a geo database ages
   *  silently. It does, but the date read as a defect rather than as a fact:
   *  Debian ships this data every few months and there is nothing to do about
   *  a gap except wait, so printing "data from January" only invites a question
   *  with no answer. Country allocations move slowly enough that a few months
   *  changes no answer on this map; what ages fast is city and network data,
   *  which the panel does not offer. The date is still on /api/suricata/geo for
   *  anyone diagnosing a wrong country.
   */
  protected readonly geoCaption = computed(() =>
    this.geo()?.database?.available ? 'country level' : 'no geo database',
  );

  /** An empty map has two very different causes and they deserve different
   *  sentences: nothing happened, or plenty happened and none of it crossed the
   *  perimeter. The second is the normal state of a sensor watching its own
   *  segment, and reading "no alerts" there would be wrong. */
  protected readonly mapEmptyText = computed(() => {
    const geo = this.geo();
    if (!geo) return 'Loading';
    if (!geo.database.available) return 'No geo database installed';
    // The three buckets are not one thing: "unknown" is public addresses the
    // database has no entry for, and calling those inside the network was
    // wrong in the one direction that matters here. The chips below the map
    // name each of them, so the empty text only has to say which case it is.
    const inside = geo.local.home + geo.local.private;
    const elsewhere = geo.local.unknown
      + geo.unplaced.reduce((sum, c) => sum + c.count, 0);
    if (inside > 0 && elsewhere === 0) {
      return 'Every alert in this period came from inside the network';
    }
    // Countries the map has no shape for count here too: they are alerts, and
    // the chips below name them one by one, so "no alerts" over them was the
    // same untruth this text was already fixed for once.
    if (inside + elsewhere > 0) {
      return 'No alert in this period could be put on the map';
    }
    return 'No alerts in this period';
  });

  /** Everything the map cannot place, as filter chips. Zero counts are dropped:
   *  a row of zeroes reads as broken rather than quiet. */
  protected readonly geoChips = computed(() => {
    const geo = this.geo();
    if (!geo) return [];
    const chips = [
      { code: 'home', label: 'Own network', count: geo.local.home },
      { code: 'private', label: 'Other private', count: geo.local.private },
      { code: 'unknown', label: 'Not located', count: geo.local.unknown },
      ...geo.unplaced.map((c) => ({ code: c.code, label: c.name, count: c.count })),
    ];
    return chips.filter((c) => c.count > 0);
  });

  /** Recent alerts: from the WS stream, falling back to the database.
   *
   *  The fallback is the point, and for a long time it was only in this comment.
   *  `live.alerts` is written in exactly one place - the WebSocket handler - so
   *  it is empty on every page load, after every reconnect and for as long as
   *  the stream is paused. The card then printed "Waiting for alerts. Silence
   *  here is good news." directly under a tile reading four thousand alerts.
   */
  protected readonly recentAlerts = computed(() => {
    const live = this.live.alerts();
    const seen = new Set(live.map((a) => a.id));
    const stored = this.storedAlerts().filter((a) => !seen.has(a.id));
    return [...live, ...stored].slice(0, 6);
  });

  /** The engine emits counters every 8 s; before the first report every figure
   *  derived from them is unknown, not zero. */
  protected readonly hasStats = computed(() => !!this.status()?.last_stats_at);

  /** Link state of what the engine captures on, and the sentence that goes with
   *  it. The sentence is written by the backend on purpose: what counts as a
   *  problem is decided where the kernel is read, not in a template. */
  protected readonly captureProblem = computed(() => this.status()?.capture?.problem ?? null);
  protected readonly captureState = computed(() => this.status()?.capture?.state ?? 'ok');

  /** Two different failures and they read differently. "Down" means the panel
   *  did something (or failed to do it again after a reboot); "no carrier"
   *  means the cable or the far end. */
  protected readonly captureHeadline = computed(() =>
    this.captureState() === 'bad'
      ? 'No traffic is reaching the engine'
      : 'Nothing is arriving on the capture interface',
  );

  protected readonly dropAlarm = computed(
    () => this.status()?.engine?.sensor_problem === 'drops',
  );
  /** Whether capture loss can be known here at all. Not the same question as
   *  whether a stats record has arrived: one arrives in blocking mode too and
   *  carries no capture section, and this tile used to read that absence as a
   *  clean 0.00 %. */
  protected readonly lossMeasured = computed(
    () => this.hasStats() && !!this.status()?.engine?.loss_measured,
  );

  /** Its own colour, lit only when the engine has actually stopped something. */
  protected readonly blockedTone = computed(
    () => `blocking${(this.summary()?.blocked ?? 0) > 0 ? ' lit' : ''}`);

  /** Zero means two different things depending on the mode, and the tile has to
   *  say which. Inline and stopping nothing is a state worth naming: it is the
   *  one that reads as working while no packet is ever stopped. */
  protected readonly blockedHint = computed(() => {
    const blocked = this.summary()?.blocked ?? 0;
    if (blocked > 0) return `stopped by the engine in ${this.windowLabel()}`;
    return `blocking is on, nothing stopped in ${this.windowLabel()}`;
  });

  protected readonly lossHint = computed(() => {
    if (!this.hasStats()) return 'waiting for the first counter report';
    const e = this.status()!.engine;
    if (!e.loss_measured) return 'not reported while inline on a queue';
    return `${(e.kernel_drops ?? 0).toLocaleString()} of `
      + `${(e.kernel_packets ?? 0).toLocaleString()}`;
  });

  /** The tile used to colour itself off temperature OR throttling and then take
   *  its words from throttling alone, so 80 degrees with clean bits rendered
   *  red and said "normal". And with no vcgencmd the throttling block is null,
   *  which is not the same as knowing there is none. */
  protected readonly tempHint = computed(() => {
    if (this.throttleAlarm()) return 'throttling / under-voltage!';
    if (this.tempAlarm()) return 'hot';
    // A board with no thermal zone reports nothing, and `?? 0` turned that
    // into a reading of zero degrees described as normal.
    if (!this.hasTemperature()) return 'no reading from this board';
    if (!this.metrics()?.throttling) return 'temperature only, no throttling data';
    return 'normal';
  });

  protected readonly hasTemperature = computed(
    () => typeof this.metrics()?.cpu?.temperature_c === 'number');
  // No guard for the missing reading: `?? 0` is below every threshold, so an
  // absent sensor cannot raise this. What it could do is read as normal, which
  // is the hint's job above.
  protected readonly tempAlarm = computed(
    () => (this.metrics()?.cpu.temperature_c ?? 0) >= 75);
  protected readonly throttleAlarm = computed(() => {
    const t = this.metrics()?.throttling;
    return !!t && (t.under_voltage_now || t.throttled_now);
  });

  ngOnInit(): void {
    const since = this.route.snapshot.queryParamMap.get('since');
    if (since && since in WINDOWS) this.window.set(since);

    this.loadSummary();
    this.loadGeo();
    this.loadRecentAlerts();
    this.loadMetrics();
    this.loadStatus();
    this.loadLayout();

    this.timers.push(setInterval(() => this.loadSummary(), SUMMARY_REFRESH_MS));
    this.timers.push(setInterval(() => this.loadGeo(), SUMMARY_REFRESH_MS));
    this.timers.push(setInterval(() => this.loadRecentAlerts(), SUMMARY_REFRESH_MS));
    // The service state only changes when someone starts or stops the engine,
    // and asking costs a systemctl call - so it rides along with the summary.
    this.timers.push(setInterval(() => this.loadStatus(), SUMMARY_REFRESH_MS));
    this.timers.push(setInterval(() => this.loadMetrics(), METRICS_REFRESH_MS));
  }

  ngOnDestroy(): void {
    this.timers.forEach(clearInterval);
    this.timers = [];
  }

  /** Both requests are reissued at once rather than waiting for the 30 second
   *  poll: the whole screen belongs to one window, and half of it moving now
   *  while the other half moves in half a minute is worse than either. */
  protected setWindow(value: string): void {
    this.window.set(value in WINDOWS ? value : DEFAULT_WINDOW);
    this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { since: this.window() },
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });
    this.loadSummary();
    this.loadGeo();
    this.loadRecentAlerts();
  }

  /** A country on the map opens the alert list already filtered to it. */
  protected openCountry(code: string): void {
    this.router.navigate(['/ids'], { queryParams: { tab: 'alerts', cc: code } });
  }

  protected severityLabel(sev: string | null | undefined): string {
    return severityLabel(sev);
  }

  protected severityCls(sev: string | null | undefined): string {
    return severityClass(sev);
  }

  protected bytes(value: number | null | undefined): string {
    return formatBytes(value);
  }

  /** The 30 second poll and a change to the noise setting both land here, and
   *  the poll can already be in flight when the setting changes. Without
   *  dropping it, the older answer arrives second and puts the figures back -
   *  which reads as the toggle not having worked. */
  private loadSummary(): void {
    this.summaryRequest?.unsubscribe();
    this.summaryRequest = this.api.summary(this.hours()).subscribe({
      next: (s) => {
        this.summary.set(s);
        this.loadError.set(null);
      },
      error: (err) => this.loadError.set(err?.message ?? 'Could not fetch the summary'),
    });
  }

  /** Only what the card can show. The stream keeps it current after this. */
  private loadRecentAlerts(): void {
    this.api.alerts({ limit: 6, offset: 0, hours: WINDOWS[this.window()] ?? null })
      .subscribe({
        next: (page) => this.storedAlerts.set(page.items),
        // Silent: loadSummary reports a dead backend, and one outage should not
        // raise two banners.
        error: () => {},
      });
  }

  private loadGeo(): void {
    this.geoRequest?.unsubscribe();
    this.geoRequest = this.api.geo(this.hours()).subscribe({
      next: (g) => this.geo.set(g),
      // Silent: the summary above already reports a dead backend, and a second
      // error banner for the same outage is noise.
      error: () => {},
    });
  }

  /** How to provoke an alert, which depends on where the sensor is standing.
   *
   *  The stock advice ("run this here") is only true when the engine watches
   *  the traffic of this machine. On a mirror or a tap the capture interface
   *  carries somebody else's conversations and nothing this device sends ever
   *  appears on it, so the test comes back silent and reads as a broken sensor.
   */
  protected testHint(): string {
    const profile = this.layout()?.profile ?? '';
    const capture = this.layout()?.roles?.['capture'];
    if (profile === 'mirror') {
      const iface = capture ? ` (${capture})` : '';
      return `To test detection, run this on a machine in the segment being watched.
              Traffic from this device never reaches the capture interface${iface}:`;
    }
    if (profile === 'bridge') {
      return 'To test detection, run this on a machine whose traffic passes through this device:';
    }
    return 'To test detection, run';
  }

  /** Asked once per visit, not on a timer: the answer changes when a person
   *  clicks through the wizard, which reloads the page anyway. */
  private loadLayout(): void {
    this.api.topology().subscribe({
      next: (state) => {
        this.layoutUnknown.set(!state.current.profile);
        this.layout.set(state.current);
      },
      error: () => {},
    });
  }

  private loadStatus(): void {
    this.api.suricataStatus().subscribe({
      next: (s) => this.live.setRestStatus(s),
      error: () => {},
    });
  }

  private loadMetrics(): void {
    this.api.systemMetrics().subscribe({
      next: (m) => this.metrics.set(m),
      error: () => {},
    });
  }
}
