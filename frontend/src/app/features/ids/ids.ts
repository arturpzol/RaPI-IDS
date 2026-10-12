import {
  Component, ElementRef, Injector, OnDestroy, OnInit, afterNextRender, computed, effect,
  inject, signal, untracked,
} from '@angular/core';
import { Observable, Subscription } from 'rxjs';
import { FormsModule } from '@angular/forms';

import { ActivatedRoute, Router } from '@angular/router';

import { Api } from '../../core/api';
import { Live } from '../../core/live';
import { DateTimePipe, NumberPipe, TimePipe, formatBytes } from '../../core/format';
import {
  Alert, AlertPage, ET_SEVERITIES, LiveEvent, Protection, ProtectionResult,
  UNRATED, severityClass, severityLabel,
} from '../../core/models';
import { StatTile } from '../../shared/stat-tile';
import { LogsView } from './logs';
import { NotifyView } from './notify';
import { ProtectionView } from './protection';

type Tab = 'alerts' | 'protection' | 'live' | 'rules' | 'logs' | 'notify';

const TABS: readonly Tab[] = ['alerts', 'protection', 'live', 'rules', 'logs', 'notify'];

const PAGE_SIZE = 50;

/** Time windows the alert list offers, in hours. Stored as the token, not as a
 *  timestamp: a URL carrying "24h" still means the last 24 hours tomorrow,
 *  while one carrying an ISO date means whatever it meant when it was copied. */
const WINDOWS: Record<string, number> = { '1h': 1, '24h': 24, '7d': 168, '30d': 720 };

/** The other kind of period this list takes: a named calendar day, resolved by
 *  the backend. Not hours, and deliberately not expressible as hours: "today"
 *  at nine in the morning is nine hours, at midnight it is one minute, and the
 *  dashboard tiles that link here count days. A link that opened a rolling
 *  window under a number that counted a day would disagree with the tile that
 *  was clicked, which is the fault this whole screen keeps being fixed for. */
const DAYS = ['today', 'yesterday'];

/** Which rows the list holds. A union rather than a string, so a caller that
 *  types 'alerts' or 'diagnostics' fails to build instead of quietly doing
 *  nothing. The only place a bare string arrives is the select, and it is
 *  narrowed once, at that boundary. */
type Kind = 'alert' | 'diagnostic' | 'all';

/** One labelled line pulled out of the raw EVE record for the detail pane. */
export interface AlertFact {
  label: string;
  value: string;
}

@Component({
  selector: 'app-ids',
  imports: [
    FormsModule, StatTile, ProtectionView, LogsView, NotifyView,
    NumberPipe, TimePipe, DateTimePipe,
  ],
  templateUrl: './ids.html',
  styleUrl: './ids.css',
})
export class Ids implements OnInit, OnDestroy {
  private api = inject(Api);
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  protected live = inject(Live);
  private host: ElementRef<HTMLElement> = inject(ElementRef);
  private injector = inject(Injector);

  // Alerts first - that is what the panel is for. `?tab=` overrides it, so a
  // link can point at one particular tab.
  protected readonly tab = signal<Tab>('alerts');

  // --- alerts from the database ---
  protected readonly page = signal<AlertPage | null>(null);
  protected readonly loading = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly offset = signal(0);

  // filters
  protected readonly search = signal('');
  protected readonly severity = signal<string | null>(null);
  protected readonly onlyUnacked = signal(false);
  /** Country of the source address, set by clicking the dashboard map. Also
   *  takes 'home' / 'private' / 'unknown', the buckets that have no country. */
  protected readonly country = signal<string | null>(null);
  /** Key of WINDOWS, or '' for no limit. */
  protected readonly window = signal<string>('');

  // details of the selected alert
  protected readonly selected = signal<Alert | null>(null);
  protected readonly selectedId = signal<number | null>(null);
  protected readonly rawExpanded = signal(false);

  /** Rebuilt only when another alert is opened, not on every change detection. */
  protected readonly selectedFacts = computed<AlertFact[]>(() => {
    const alert = this.selected();
    return alert ? this.factsOf(alert) : [];
  });
  /** SID being silenced or restored right now - the button says so meanwhile. */
  /** True while the bulk acknowledgement is in flight, so the button can say
   *  so and cannot be pressed twice on a table of twelve thousand rows. */
  protected readonly ackingAll = signal(false);
  protected readonly muting = signal<number | null>(null);
  /** SIDs currently dropped from the rule set, so the detail pane can say so. */
  protected readonly mutedSids = signal<ReadonlySet<number>>(new Set());
  /** SIDs that alert and are never dropped. */
  protected readonly allowedSids = signal<ReadonlySet<number>>(new Set());

  /** Threats, or the engine's notes about itself and the traffic.
   *
   *  Not a control on the toolbar: it would be a fifth one, and the reader who
   *  wants engine notes is not the reader filtering an alert list. It arrives
   *  as a link under the list and leaves as a removable pill, the way the
   *  country filter already works. */
  protected readonly kind = signal<Kind>('alert');

  /** Only what the engine stopped. Off unless asked for: on a sensor reading a
   *  copy nothing is ever blocked, so it would be a filter that empties the
   *  list on most devices. */
  protected readonly onlyBlocked = signal(false);

  // --- live view ---
  protected readonly eventFilter = signal<string>('');

  // --- the engine ---

  /** Whether the sensor is keeping up, and the numbers behind the answer.
   *
   *  Read off the engine's own stats record rather than off its decoder event
   *  rules. Those rules fire per packet: five "protocol detection skipped" in
   *  a week turned the old card red on a machine that had dropped nothing at
   *  all out of 13.7 million packets. Zeek documents capture loss as something
   *  that should never exceed 1 %, Security Onion colours its per-node loss on
   *  the same scale, and Suricata publishes the counters for free.
   */
  protected readonly sensorBad = computed(
    () => this.status()?.engine?.sensor_problem != null,
  );

  /** True when the engine publishes no capture counters, so the question this
   *  card asks has no answer here rather than a reassuring one. Amber, not
   *  green and not red: nothing is known to be wrong and nothing is known. */
  protected readonly sensorUnknown = computed(() => {
    const e = this.status()?.engine;
    return !!e && !e.loss_measured && !this.sensorBad();
  });

  /** Whether the engine has published any counters yet. Absent counters and
   *  counters that cannot exist read the same on every card below, and they
   *  are not the same answer. */
  protected readonly hasStats = computed(() => !!this.status()?.last_stats_at);

  /** What the "Dropped packets" tile says under its figure. */
  protected readonly lossHint = computed(() => {
    if (!this.hasStats()) return 'waiting for the first counter report';
    if (!this.status()!.engine.loss_measured) {
      return 'not reported while inline on a queue';
    }
    return 'above 1% = the engine cannot keep up';
  });

  protected readonly sensorLine = computed(() => {
    const e = this.status()?.engine;
    if (!e) return 'Checking...';
    const n = (value: number) => value.toLocaleString();
    switch (e.sensor_problem) {
      case 'drops':
        return `Packets are being dropped: ${(e.drop_rate_percent ?? 0).toFixed(2)} %. `
          + 'The engine is not keeping up with the link.';
      case 'errors':
        return `The capture reported ${n(e.capture_errors ?? 0)} `
          + `error${e.capture_errors === 1 ? '' : 's'}. `
          + 'Packets are reaching the card and not the engine.';
      case 'gaps':
        return `${e.gap_rate_percent.toFixed(2)} % of TCP streams could not be `
          + 'reassembled. The engine is seeing part of the traffic only.';
      default:
        // Absence of a counter is not a clean bill of health. In NFQUEUE mode
        // there is no ring and no kernel_drops, and reading the missing section
        // as zero is how this card reported a healthy sensor for an evening
        // while the engine inspected nothing off the mirror port at all.
        // Before the engine's first report there is nothing to read, and an
        // absent capture section then looked exactly like a netfilter queue:
        // for the first half minute after every restart this card described an
        // ordinary mirror-port sensor as inline on a queue.
        if (!this.hasStats()) {
          return 'Waiting for the first counter report from the engine. '
            + 'It publishes one every 8 seconds.';
        }
        if (!e.loss_measured) {
          const stopped = e.blocked ?? 0;
          const byRules = e.blocked_by_rules ?? 0;
          return 'Inline on a netfilter queue, so capture loss is not reported '
            + `here and nothing on this screen can measure it. ${n(stopped)} `
            + `packet${stopped === 1 ? '' : 's'} stopped, ${n(byRules)} of them `
            + 'by a rule.';
        }
        // Not "nothing is being missed": this line used to say that beside a
        // count of reassembly gaps, and a gap is exactly something missed. The
        // claim that holds is the one about packets, which is the number this
        // sentence is now allowed to make.
        return e.kernel_drops === 0
          ? 'Keeping up. No packets dropped.'
          : `Keeping up. ${(e.drop_rate_percent ?? 0).toFixed(2)} % of packets `
            + 'dropped, under the one percent that matters.';
    }
  });

  /** The evidence under the verdict. The drop percentage is absent while the
   *  sensor is keeping up: the sentence above has just made that claim, and the
   *  tile beside the card carries the figure. */
  protected readonly sensorDetail = computed(() => {
    const e = this.status()?.engine;
    if (!e) return '';
    // The same guard as the verdict above it, which it used to contradict:
    // "Waiting for the first counter report" over "0 of 0 TCP streams
    // incomplete, no capture counters in this mode" is two answers to one
    // question, and the second one is a measurement nobody made.
    if (!this.hasStats()) return '';
    const n = (value: number) => value.toLocaleString();
    const parts = [
      `${n(e.reassembly_gaps)} of ${n(e.tcp_sessions)} TCP streams incomplete`,
    ];
    // Only where there is a capture to have errors. Printing "0 capture errors"
    // off an absent section is the same false comfort as the drop figure.
    if (e.loss_measured) {
      parts.push(`${n(e.capture_errors ?? 0)} capture `
        + `error${e.capture_errors === 1 ? '' : 's'}`);
    } else {
      parts.push('no capture counters in this mode');
    }
    if (e.sensor_problem === 'drops') {
      parts.unshift(`${n(e.kernel_drops ?? 0)} dropped `
        + `of ${n(e.kernel_packets ?? 0)} packets`);
    }
    return parts.join(' \u00b7 ');
  });
  protected readonly actionBusy = signal<string | null>(null);
  protected readonly actionResult = signal<{ ok: boolean; text: string } | null>(null);
  protected readonly engineLog = signal<string[] | null>(null);

  private tabParam?: Subscription;
  private statusTimer: ReturnType<typeof setInterval> | null = null;
  private searchDebounce: ReturnType<typeof setTimeout> | null = null;
  private alertsRequest: Subscription | null = null;

  /** Merged from the stream and from REST - see Live.status. */
  protected readonly status = this.live.status;

  protected readonly pageCount = computed(() => {
    const p = this.page();
    return p ? Math.max(Math.ceil(p.total / PAGE_SIZE), 1) : 1;
  });

  protected readonly currentPage = computed(() => Math.floor(this.offset() / PAGE_SIZE) + 1);

  /** Event types present in the buffer - used to build the filter. */
  protected readonly eventTypes = computed(() => {
    const types = new Set(this.live.events().map((e) => e.event_type));
    return [...types].sort();
  });

  protected readonly filteredEvents = computed<LiveEvent[]>(() => {
    const filter = this.eventFilter();
    const events = this.live.events();
    return filter ? events.filter((e) => e.event_type === filter) : events;
  });

  constructor() {
    // A new alert from the stream => refresh the first page so the view does
    // not lie. Later pages are left alone (the user is reading history).
    effect(() => {
      const count = this.live.alerts().length;
      if (count > 0 && this.offset() === 0 && this.tab() === 'alerts') {
        // untracked: loadAlerts() reads the filter signals, and without this the
        // effect would subscribe to them too - every keystroke would then fire a
        // request of its own, straight past the debounce below.
        untracked(() => this.loadAlerts());
      }
    });

    // The tab bar scrolls sideways on a phone, so the active tab can sit off
    // the right edge: arriving on ?tab=notify from a link then opens a screen
    // whose header shows Alerts. Only the bar is scrolled, never the page.
    effect(() => {
      const index = TABS.indexOf(this.tab());
      const bar = this.host.nativeElement.querySelector<HTMLElement>('.tabs');
      const button = bar?.querySelectorAll<HTMLElement>('.tab')[index];
      if (!bar || !button) return;
      bar.scrollLeft = button.offsetLeft - (bar.clientWidth - button.offsetWidth) / 2;
    });

    // Below 1000px the two columns stack and the detail card lands under the
    // whole list, which on a phone is off screen: tapping a row looked like it
    // did nothing at all. Scroll to it, but only when it is not already in
    // view, so the wide layout - where the card sits beside the list and stays
    // put - is left alone.
    effect(() => {
      if (!this.selected()) return;
      afterNextRender(() => {
        const card = this.host.nativeElement.querySelector<HTMLElement>('.detail-card');
        if (!card) return;
        const box = card.getBoundingClientRect();
        if (box.top >= 0 && box.bottom <= window.innerHeight) return;
        card.scrollIntoView({ block: 'start', behavior: 'smooth' });
      }, { injector: this.injector });
    });
  }

  ngOnInit(): void {
    const requested = this.route.snapshot.queryParamMap.get('tab') as Tab | null;
    if (requested && TABS.includes(requested)) this.tab.set(requested);
    // And afterwards, because the links inside this screen lead to it: three
    // sentences on the Protection tab point at the alert list, and Angular
    // keeps the component it already has, so the address changed and nothing
    // else did. They read as dead links.
    //
    // The tab only. Every other parameter is this screen's own state by then,
    // and syncUrl puts it back in the address, which the navigation that
    // brought us here had dropped.
    this.tabParam = this.route.queryParamMap.subscribe((params) => {
      const tab = params.get('tab') as Tab | null;
      if (tab && TABS.includes(tab) && tab !== this.tab()) this.setTab(tab);
    });
    this.country.set(this.route.snapshot.queryParamMap.get('cc'));
    this.onlyUnacked.set(this.route.snapshot.queryParamMap.get('unacked') === '1');
    const wanted = this.route.snapshot.queryParamMap.get('kind');
    if (wanted === 'diagnostic' || wanted === 'all') this.kind.set(wanted);
    this.onlyBlocked.set(this.route.snapshot.queryParamMap.get('blocked') === '1');
    const since = this.route.snapshot.queryParamMap.get('since');
    // Anything we do not recognise is ignored rather than passed on, so a typed
    // URL cannot turn into a filter nobody can see or clear.
    //
    // 'all' is the URL spelling of the empty token the selector uses for "all
    // time". It exists because an empty query parameter is not a reliable way
    // to say anything, and because the dashboard's queue tile counts the whole
    // table: opening a 24 h list under an all-time number would put two
    // different figures on two screens and call them the same thing.
    if (since === 'all') this.window.set('');
    else if (since && (since in WINDOWS || DAYS.includes(since))) this.window.set(since);
    // A rating carried in from the dashboard's rating tiles. Read here rather
    // than left to the tile, because the list has to be able to say what it is
    // showing and to clear it.
    const rated = this.route.snapshot.queryParamMap.get('severity');
    if (rated && (ET_SEVERITIES.includes(rated as any) || rated === UNRATED)) {
      this.severity.set(rated);
    }

    this.loadAlerts();
    this.loadStatus();
    this.loadMuted();
    this.live.resetNewAlertCount();
    this.statusTimer = setInterval(() => this.loadStatus(), 10_000);
  }

  ngOnDestroy(): void {
    this.tabParam?.unsubscribe();
    if (this.statusTimer) clearInterval(this.statusTimer);
    if (this.searchDebounce) clearTimeout(this.searchDebounce);
    this.alertsRequest?.unsubscribe();
  }

  protected setTab(tab: Tab): void {
    this.tab.set(tab);
    this.syncUrl();
    if (tab === 'alerts') this.loadAlerts();
  }

  /** Write every filter that can arrive through the URL back into it.
   *
   *  All of them except the search box, which no other screen sets. The
   *  dashboard sends a rating, a country, a day, the queue and the blocked
   *  rows, ngOnInit reads them back, and anything the toolbar changes without
   *  rewriting the URL comes back on the next reload: the page then looks like
   *  it ignored the click. That is what happened to the rating, which was
   *  restored from the URL and never written to it.
   *
   *  replaceUrl: filtering is not navigation, and the back button should lead
   *  out of the page rather than through every checkbox on it.
   */
  private syncUrl(): void {
    this.router.navigate([], {
      relativeTo: this.route,
      // A null parameter is dropped from the URL rather than written empty.
      queryParams: {
        tab: this.tab(),
        cc: this.country(),
        unacked: this.onlyUnacked() ? 1 : null,
        since: this.window() || null,
        severity: this.severity(),
        kind: this.kind() === 'alert' ? null : this.kind(),
        blocked: this.onlyBlocked() ? 1 : null,
      },
      replaceUrl: true,
    });
  }

  // --- alert list ---

  protected loadAlerts(): void {
    // Drop whatever is still in flight. A search runs `LIKE '%x%'` over four
    // columns - a full table scan - while an unfiltered page is quick. Without
    // this, the slow filtered response lands after the fast unfiltered one and
    // overwrites it, which is what made "Clear" look like it did nothing.
    this.alertsRequest?.unsubscribe();
    this.loading.set(true);
    this.alertsRequest = this.api.alerts({
      limit: PAGE_SIZE,
      offset: this.offset(),
      search: this.search() || null,
      severity: this.severity(),
      // No severity cap is sent: the device decides what it shows, and a client
      // that carried its own default could disagree with the dashboard beside it.
      src_cc: this.country(),
      // Sent as a number of hours, not as a timestamp: the cutoff belongs to
      // the machine the engine writes its timestamps on, and a browser in
      // another timezone would work out a different one for the same window.
      hours: DAYS.includes(this.window()) ? null : WINDOWS[this.window()] ?? null,
      day: DAYS.includes(this.window()) ? this.window() : null,
      acknowledged: this.onlyUnacked() ? false : null,
      kind: this.kind(),
      blocked: this.onlyBlocked() ? true : null,
    }).subscribe({
      next: (p) => {
        this.page.set(p);
        this.error.set(null);
        this.loading.set(false);
      },
      error: (err) => {
        this.error.set(err?.message ?? 'Could not fetch alerts');
        this.loading.set(false);
      },
    });
  }

  protected onSearchInput(value: string): void {
    this.search.set(value);
    if (this.searchDebounce) clearTimeout(this.searchDebounce);
    this.searchDebounce = setTimeout(() => {
      this.offset.set(0);
      this.loadAlerts();
    }, 350);
  }

  protected setSeverity(value: string): void {
    this.severity.set(value || null);
    this.offset.set(0);
    // The URL carries this filter in from the dashboard's rating tiles and
    // ngOnInit reads it back, so clearing it here without rewriting the URL
    // left a filter that came back on the next reload.
    this.syncUrl();
    this.loadAlerts();
  }

  protected setWindow(value: string): void {
    // Both kinds of period, because the selector offers both. Checked against
    // WINDOWS alone, picking Today set the window to "all time" while the box
    // went on reading Today, so the control and the list disagreed. Only the
    // URL path had a test, and the URL path used its own guard.
    this.window.set(value in WINDOWS || DAYS.includes(value) ? value : '');
    this.offset.set(0);
    this.syncUrl();
    this.loadAlerts();
  }

  protected toggleUnacked(): void {
    this.onlyUnacked.update((v) => !v);
    this.offset.set(0);
    this.syncUrl();
    this.loadAlerts();
  }

  /** Whether anything is narrowing the list at all.
   *
   *  Used by the empty state to decide whether there is a way out to offer. It
   *  listed four of the six filters, so a list emptied by "blocked only" on a
   *  sensor that blocks nothing said no rows matched and offered nothing. */
  protected readonly anyFilter = computed(() =>
    !!this.search() || this.severity() !== null || this.onlyUnacked()
    || this.onlyBlocked() || this.kind() !== 'alert' || !!this.country()
    || !!this.window());

  /** One sentence naming what is in the list, under it.
   *
   *  The toolbar says which kind is selected; this says what that kind is.
   *  "Engine notes" is a label somebody has to be told the meaning of once. */
  protected readonly kindNote = computed(() => {
    switch (this.kind()) {
      case 'diagnostic':
        return "The engine's own events. Nothing here was sent by anybody; "
          + 'it is the sensor describing what it saw.';
      case 'all':
        return 'Everything the engine raised, threats and its own notes in one '
          + "list. This is what the engine's own counter counts.";
      default:
        return "Threats only. What the engine says about the traffic and about "
          + 'itself is under "Engine notes", because it is not an attack.';
    }
  });

  protected resetFilters(): void {
    // Otherwise a keystroke from a moment ago still fires its query afterwards.
    if (this.searchDebounce) {
      clearTimeout(this.searchDebounce);
      this.searchDebounce = null;
    }
    this.search.set('');
    this.severity.set(null);
    this.onlyUnacked.set(false);
    this.window.set('');
    this.kind.set('alert');
    this.onlyBlocked.set(false);
    this.clearCountry();   // drops the country as well, and rewrites the URL
  }

  /** Switch the list between threats and the engine's own notes.
   *
   *  Paging has to go back to the start: the two lists have nothing to do with
   *  each other, and page 4 of one is not page 4 of the other. */
  /** Narrow the list to what was actually stopped, or widen it back. */
  protected setBlocked(only: boolean): void {
    this.onlyBlocked.set(only);
    this.offset.set(0);
    this.syncUrl();
    this.loadAlerts();
  }

  /** What the badge beside "Alerts" is counting, in words.
   *
   *  It is the list as filtered, which is a different thing from every other
   *  count on this screen. Read against the engine's own counter it looked like
   *  events had gone missing; they had not, the two were measuring a different
   *  kind, a different period and a different set of filters.
   */
  protected readonly alertCountHint = computed(() => {
    const parts: string[] = [
      this.kind() === 'diagnostic' ? "the engine's own notes"
        : this.kind() === 'all' ? 'threats and engine notes'
        : 'threats, without the engine\'s own notes',
      // The label, not the token the URL carries: "in the last 7d" was the
      // selector's value read out loud, and the selector says "Last 7 days"
      // two centimetres away.
      DAYS.includes(this.window()) ? this.window()
        : this.window() ? `in the ${this.windowPhrase()}`
        : 'over all time',
    ];
    if (this.onlyBlocked()) parts.push('stopped by the engine');
    if (this.onlyUnacked()) parts.push('not yet acknowledged');
    if (this.severity()) parts.push(`rated ${this.severity()}`);
    if (this.search()) parts.push(`matching "${this.search()}"`);
    if (this.country()) parts.push(`from ${this.countryLabel(this.country()!)}`);
    return parts.join(', ');
  });

  /** The engine raised this many; the panel has this many. Equal is the whole
   *  point: it says nothing was lost between the reader and the table. */
  protected readonly engineAlertsHint = computed(() => {
    const e = this.status()?.engine;
    if (!e || e.alerts_stored == null) return 'counted since the engine started';
    if ((e.alerts_missing ?? 0) > 0) {
      return `${e.alerts_missing!.toLocaleString()} of them never reached the panel`;
    }
    return 'since the engine started, all of them stored here';
  });

  protected readonly engineAlertsBad = computed(
    () => (this.status()?.engine?.alerts_missing ?? 0) > 0,
  );

  /** The engine's own counter, opened. It counts threats and the engine's own
   *  notes together, so the list has to show both, and the reader is on the
   *  engine tab when they press it. */
  protected showEverything(): void {
    this.setKind('all');
    this.setTab('alerts');
  }

  /** From the select, whose value is a string the template cannot type. The one
   *  place an unchecked kind enters, and the only place that needs a guard. */
  protected chooseKind(value: string): void {
    if (value === 'alert' || value === 'diagnostic' || value === 'all') {
      this.setKind(value);
    }
  }

  protected setKind(kind: Kind): void {
    this.kind.set(kind);
    this.offset.set(0);
    this.syncUrl();
    this.loadAlerts();
  }

  /** Drop the country filter, and the query parameter that carried it - a
   *  refresh would otherwise bring the filter back after "Clear". */
  protected clearCountry(): void {
    this.country.set(null);
    this.offset.set(0);
    this.syncUrl();
    this.loadAlerts();
  }

  /** Country name for the filter pill.
   *
   *  Intl.DisplayNames is in the browser already, so the panel does not have to
   *  ship a name table or ask the backend for one. Anything it cannot name -
   *  and our own three buckets - falls through to a label of ours.
   */
  protected countryLabel(code: string): string {
    const own: Record<string, string> = {
      home: 'own network',
      private: 'other private ranges',
      unknown: 'no location',
    };
    if (own[code]) return own[code];
    try {
      return new Intl.DisplayNames(['en'], { type: 'region' }).of(code) ?? code;
    } catch {
      return code;
    }
  }

  protected prevPage(): void {
    this.offset.update((o) => Math.max(o - PAGE_SIZE, 0));
    this.loadAlerts();
  }

  protected nextPage(): void {
    const total = this.page()?.total ?? 0;
    this.offset.update((o) => (o + PAGE_SIZE < total ? o + PAGE_SIZE : o));
    this.loadAlerts();
  }

  // --- detail ---

  protected select(alert: Alert): void {
    if (this.selectedId() === alert.id) {
      this.closeDetail();
      return;
    }
    this.selectedId.set(alert.id);
    this.rawExpanded.set(false);
    this.api.alert(alert.id).subscribe({
      next: (full) => this.selected.set(full),
      error: () => this.selected.set(alert),
    });
  }

  protected closeDetail(): void {
    this.selectedId.set(null);
    this.selected.set(null);
  }

  protected ack(alert: Alert, event: MouseEvent): void {
    event.stopPropagation();
    this.api.ackAlert(alert.id, !alert.acknowledged).subscribe({
      next: () => {
        this.loadAlerts();
        if (this.selected()?.id === alert.id) {
          this.selected.update((a) => (a ? { ...a, acknowledged: !alert.acknowledged } : a));
        }
      },
    });
  }

  /** Clear the whole review queue.
   *
   *  The queue tile on the dashboard is the one figure there that waits for a
   *  person, which only works if clearing it is one action rather than several
   *  thousand. This device had 12,362 unacknowledged rows out of 12,375 when
   *  the tile was built, so without this the number would have been a red badge
   *  that could never reach zero.
   *
   *  Guarded by a confirmation, because it touches every row and there is no
   *  bulk undo. It names no count on purpose: the only number this screen has
   *  is the total for the filters in force, and this clears the whole queue,
   *  so printing that one would understate what is about to happen. The server
   *  picks the cutoff, so alerts that arrive while it runs stay in the queue.
   */
  protected ackAll(): void {
    if (!confirm(
      `Mark everything as reviewed?\n\n`
      + `This clears the review queue, including alerts not on this page. `
      + `Alerts arriving from now on stay unreviewed. There is no bulk undo.`,
    )) return;
    this.ackingAll.set(true);
    this.api.ackAllAlerts().subscribe({
      next: () => { this.ackingAll.set(false); this.loadAlerts(); },
      error: () => { this.ackingAll.set(false); this.loadAlerts(); },
    });
  }

  /** Drop this signature from the rule set for good.
   *
   *  Not a display filter: the rule stops being compiled, so a noisy signature
   *  costs the engine nothing. Alerts already in the database stay - they are a
   *  record of what happened, not a live setting.
   */
  protected muteSignature(alert: Alert): void {
    const sid = alert.signature_id;
    if (!sid || this.muting() !== null) return;
    if (!confirm(
      `Stop alerting on "${alert.signature}" (SID ${sid})?\n\n`
      + 'The signature is removed from the rule set and stays out after updates.\n'
      + 'Rebuilding takes about 20 seconds. Alerts already recorded are kept.\n\n'
      + 'You can bring it back on the Protection tab.',
    )) return;

    this.muting.set(sid);
    this.actionResult.set(null);
    this.api.muteSignature(sid).subscribe({
      next: (res) => this.afterMuteChange(res, sid, `"${alert.signature}" silenced`),
      error: (err) => {
        this.muting.set(null);
        this.actionResult.set({
          ok: false, text: err?.error?.detail ?? 'Could not silence the signature',
        });
      },
    });
  }

  /** Put a silenced signature back into the rule set. */
  protected unmuteSignature(alert: Alert): void {
    const sid = alert.signature_id;
    if (!sid || this.muting() !== null) return;
    this.muting.set(sid);
    this.actionResult.set(null);
    this.api.unmuteSignature(sid).subscribe({
      next: (res) => this.afterMuteChange(res, sid, `"${alert.signature}" restored`),
      error: (err) => {
        this.muting.set(null);
        this.actionResult.set({
          ok: false, text: err?.error?.detail ?? 'Could not restore the signature',
        });
      },
    });
  }

  /** Keep alerting on this signature and never drop it.
   *
   *  The way out for a signature that blocks something wanted, such as a remote
   *  access tool, without switching off the category it belongs to.
   */
  protected allowSignature(alert: Alert): void {
    const sid = alert.signature_id;
    if (!sid || this.muting() !== null) return;
    if (!confirm(
      `Never block "${alert.signature}" (SID ${sid})?\n\n`
      + 'It keeps alerting, and it is not dropped when blocking is on. Every other '
      + 'signature in its category still blocks.\n'
      + 'Rebuilding takes about 20 seconds.\n\n'
      + 'You can undo it on the Protection tab.',
    )) return;
    this.changeSignature(sid, this.api.allowSignature(sid),
      `"${alert.signature}" allowed`, 'Could not allow the signature');
  }

  /** Let the blocking policy drop an allowed signature again. */
  protected unallowSignature(alert: Alert): void {
    const sid = alert.signature_id;
    if (!sid || this.muting() !== null) return;
    this.changeSignature(sid, this.api.unallowSignature(sid),
      `"${alert.signature}" blocks again`, 'Could not change the signature');
  }

  private changeSignature(sid: number, request: Observable<ProtectionResult>,
                          done: string, failed: string): void {
    this.muting.set(sid);
    this.actionResult.set(null);
    request.subscribe({
      next: (res) => this.afterMuteChange(res, sid, done),
      error: (err) => {
        this.muting.set(null);
        this.actionResult.set({ ok: false, text: err?.error?.detail ?? failed });
      },
    });
  }

  /** Shared tail of every signature change: refresh state, then reload the engine. */
  private afterMuteChange(res: ProtectionResult, sid: number, done: string): void {
    this.setSignatureLists(res.state);
    this.loadStatus();
    if (!res.ok) {
      this.muting.set(null);
      this.actionResult.set({ ok: false, text: this.tail(res.output) });
      return;
    }
    // The rule file changed - without a reload the engine keeps to the old set.
    this.api.serviceAction('reload').subscribe({
      next: () => {
        this.muting.set(null);
        this.actionResult.set({ ok: true, text: `${done} and the engine reloaded.` });
      },
      error: () => {
        this.muting.set(null);
        this.actionResult.set({
          ok: false,
          text: `${done}, but the engine could not be reloaded. `
            + 'Do it by hand on the "Engine" tab.',
        });
      },
    });
  }

  /** Out of the suricata-update output we only want the final summary line. */
  private tail(output: string): string {
    const lines = (output ?? '').trim().split('\n').filter((l) => l.trim());
    const summary = lines.reverse().find((l) => l.includes('Writing rules to'));
    return (summary ?? lines[0] ?? '').replace(/^\S+ -- \S+ - <\w+> -- /, '');
  }

  protected rawJson(alert: Alert): string {
    return JSON.stringify(alert.raw ?? {}, null, 2);
  }

  /** The named things worth reading out of the raw EVE record.
   *
   * All of this already arrives with the alert and is already stored in the
   * raw column, so nothing here costs a byte on disk or a setting in the
   * engine. What it buys is that the answer stops being buried: the rule that
   * fires most often here is a DNS lookup, and the name it looked up was
   * sitting inside a collapsed JSON blob nobody opens.
   *
   * A field with nothing behind it is left out rather than shown empty. A
   * column of dashes reads as a broken panel, and which blocks an alert
   * carries depends entirely on the protocol it fired on.
   */
  private factsOf(alert: Alert): AlertFact[] {
    const raw = alert.raw ?? {};
    const facts: AlertFact[] = [];

    const block = (name: string): Record<string, unknown> => {
      const value = raw[name];
      return value !== null && typeof value === 'object' && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : {};
    };
    const text = (value: unknown): string =>
      typeof value === 'string' || typeof value === 'number' ? String(value) : '';
    const add = (label: string, value: string): void => {
      if (value !== '') facts.push({ label, value });
    };

    const dns = block('dns');
    const queries = Array.isArray(dns['queries']) ? (dns['queries'] as unknown[]) : [];
    const asked = queries
      .map((entry) => {
        const query = entry !== null && typeof entry === 'object'
          ? (entry as Record<string, unknown>) : {};
        const name = text(query['rrname']);
        const type = text(query['rrtype']);
        return name !== '' && type !== '' ? `${name} (${type})` : name;
      })
      .filter((entry) => entry !== '');
    add('DNS query', asked.join(', '));

    const tls = block('tls');
    add('TLS SNI', text(tls['sni']));
    add('TLS version', text(tls['version']));
    // The fingerprint is the one field that still says something about a client
    // when everything else on the connection is encrypted.
    add('JA4', text(tls['ja4']) || text(tls['ja3']));

    const http = block('http');
    add('HTTP host', text(http['hostname']));
    add('URL', text(http['url']));
    add('User agent', text(http['http_user_agent']));

    const side = (packets: unknown, bytes: unknown): string => {
      const parts: string[] = [];
      if (typeof packets === 'number') parts.push(`${packets} pkt`);
      if (typeof bytes === 'number') parts.push(formatBytes(bytes));
      return parts.join(', ');
    };
    const flow = block('flow');
    add('To server', side(flow['pkts_toserver'], flow['bytes_toserver']));
    add('To client', side(flow['pkts_toclient'], flow['bytes_toclient']));

    add('Direction', text(raw['direction']));
    const vlan = Array.isArray(raw['vlan'])
      ? (raw['vlan'] as unknown[]).map(text).filter((tag) => tag !== '')
      : [];
    add('VLAN', vlan.join(', '));
    // Always "allowed" while the engine only watches. It stops being a constant
    // the day this device is put in the path, and then it is the first thing
    // anybody looks for.
    add('Rule action', text(block('alert')['action']));

    return facts;
  }

  /** Filter the list by the clicked address - a quick "show everything from this IP". */
  protected filterByIp(ip: string | null, event: MouseEvent): void {
    event.stopPropagation();
    if (!ip) return;
    this.search.set(ip);
    this.offset.set(0);
    this.tab.set('alerts');
    this.loadAlerts();
  }

  // --- the engine ---

  /** Detection categories changed the rule set - refresh what the engine reports. */
  protected onProtectionChanged(): void {
    this.loadStatus();
    this.loadMuted();
  }

  private loadMuted(): void {
    this.api.protection().subscribe({
      next: (p) => this.setSignatureLists(p),
      error: () => {},
    });
  }

  private setSignatureLists(p: Protection): void {
    this.mutedSids.set(new Set(p.muted.map((m) => m.signature_id)));
    // Absent from a state written before allowing existed.
    this.allowedSids.set(new Set((p.allowed ?? []).map((m) => m.signature_id)));
  }

  protected isAllowed(alert: Alert): boolean {
    return alert.signature_id !== null && this.allowedSids().has(alert.signature_id);
  }

  protected isMuted(alert: Alert): boolean {
    return alert.signature_id !== null && this.mutedSids().has(alert.signature_id);
  }

  protected loadStatus(): void {
    this.api.suricataStatus().subscribe({
      next: (s) => this.live.setRestStatus(s),
      error: () => {},
    });
  }

  /** The only engine action the panel offers. Start, stop and restart are gone:
   *  on a box whose one job is detection, a button that switches detection off
   *  is a way to leave it off by accident. The engine comes up with the machine
   *  and the panel restarts it itself when a setting requires it. */
  protected serviceAction(action: 'reload'): void {
    const labels: Record<string, string> = { reload: 'reload the rules' };
    this.actionBusy.set(action);
    this.actionResult.set(null);
    this.api.serviceAction(action).subscribe({
      next: (res) => {
        this.actionBusy.set(null);
        this.actionResult.set({ ok: true, text: res.output || `Managed to ${labels[action]}.` });
        this.loadStatus();
      },
      error: (err) => {
        this.actionBusy.set(null);
        this.actionResult.set({
          ok: false,
          text: err?.error?.detail ?? err?.message ?? 'The operation failed',
        });
      },
    });
  }

  protected loadEngineLog(): void {
    this.api.engineLog(200).subscribe({
      next: (res) => this.engineLog.set(res.lines),
      error: (err) => this.engineLog.set([err?.error?.detail ?? 'Cannot read the log']),
    });
  }

  // --- template helpers ---

  protected severityLabel(sev: string | null | undefined): string {
    return severityLabel(sev);
  }

  protected severityCls(sev: string | null | undefined): string {
    return severityClass(sev);
  }

  /** The three kinds of row this list holds. A closed set, so a control.
   *
   *  "Threats" is the default and the reason the split exists: the engine's own
   *  events are a quarter of what is stored, and mixed in they made one video
   *  call outrank the week's real alerts. */
  protected readonly kindOptions = [
    { value: 'alert', label: 'Threats' },
    { value: 'diagnostic', label: 'Engine notes' },
    { value: 'all', label: 'Threats and notes' },
  ];

  /** The window as the selector beside this names it: "in the last 7d" was
   *  the URL token read out loud, two centimetres from an option reading
   *  "Last 7 days". */
  protected readonly windowPhrase = computed(() =>
    (this.windowOptions.find((o) => o.value === this.window())?.label ?? '')
      .toLowerCase());

  protected readonly windowOptions = [
    { value: '', label: 'All time' },
    { value: 'today', label: 'Today' },
    { value: 'yesterday', label: 'Yesterday' },
    { value: '1h', label: 'Last hour' },
    { value: '24h', label: 'Last 24 hours' },
    { value: '7d', label: 'Last 7 days' },
    { value: '30d', label: 'Last 30 days' },
  ];

  /** ET's own tiers, not Suricata's numbers. See ET_SEVERITIES for why. */
  protected readonly severityOptions = [
    { value: '', label: 'Any rating' },
    ...ET_SEVERITIES.map((s) => ({ value: s, label: s })),
    { value: UNRATED, label: 'Not rated by ET' },
  ];
}
