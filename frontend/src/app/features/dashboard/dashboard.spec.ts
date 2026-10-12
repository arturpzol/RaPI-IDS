import { provideRouter } from '@angular/router';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';

import { Api } from '../../core/api';
import { Live } from '../../core/live';
import { AlertSummary, GeoSummary } from '../../core/models';
import { Dashboard } from './dashboard';

function summary(overrides: Partial<AlertSummary> = {}): AlertSummary {
  return {
    window_hours: 24,
    timeline_step_hours: 1,
    total_all_time: 123,
    total_window: 5,
    unacknowledged: 5,
    pending: 5,
    today: 5,
    yesterday: 7,
    diagnostics_today: 0,
    diagnostics: 0,
    blocked: 0,
    by_severity: [{ severity: 'Major', count: 2 },
                  { severity: 'Informational', count: 3 }],
    today_by_severity: [{ severity: 'Major', count: 2 },
                        { severity: 'Informational', count: 3 }],
    yesterday_by_severity: [{ severity: 'Informational', count: 7 }],
    top_signatures: [{ signature: 'ET MALWARE Test', signature_id: 2000001,
                      severity: 'Major', count: 2 }],
    top_sources: [{ src_ip: '203.0.113.7', count: 2 }],
    top_destinations: [{ dest_ip: '192.168.1.10', count: 2 }],
    top_categories: [{ category: 'A Network Trojan was detected', count: 2 }],
    timeline: [
      { bucket: '2026-08-23T09:00', count: 0, by_severity: {} },
      { bucket: '2026-08-23T10:00', count: 5,
        by_severity: { Major: 2, Informational: 3 } },
    ],
    ...overrides,
  } as AlertSummary;
}

function metrics(overrides: Record<string, unknown> = {}) {
  return {
    timestamp: 0,
    cpu: {
      percent: 10, per_core: [10, 10, 10, 10], temperature_c: 45,
      load_avg: { '1m': 0.4, '5m': 0.3, '15m': 0.2 },
    },
    memory: { total: 8e9, used: 2e9, available: 6e9, percent: 25 },
    swap: { total: 0, used: 0, percent: 0 },
    disk: { total: 1e11, used: 5e10, free: 5e10, percent: 50 },
    throttling: null,
    uptime_seconds: 3600,
    ...overrides,
  } as any;
}

/** A status as the panel merges it: the stream half plus the REST half. */
function status(overrides: Record<string, unknown> = {}) {
  return {
    reader_alive: true,
    eve_path: '/var/log/suricata/eve.json',
    panel_started_at: '2026-08-23T09:00:00+00:00',
    lines_read: 100,
    parse_errors: 0,
    last_event_at: null,
    last_stats_at: null,
    event_counts: {},
    engine: {
      uptime_seconds: 3600, packets: 1000, bytes: 100000, kernel_packets: 1000,
      kernel_drops: 0, capture_errors: 0, drop_rate_percent: 0,
      alerts_detected: 0, flows: 10,
    },
    service: { name: 'suricata', active: 'active', running: true, enabled: 'enabled', version: '8.0.1' },
    ...overrides,
  } as any;
}

function geo(overrides: Partial<GeoSummary> = {}): GeoSummary {
  return {
    countries: [{ code: 'US', name: 'United States', count: 2, sources: 1, severity: 'Major', lat: 39, lon: -98, last_seen: '' }],
    unplaced: [],
    local: { home: 0, private: 0, unknown: 0 },
    database: { available: true, updated: '2026-07-01', path: '/usr/share/GeoIP/GeoIP.dat' },
    ...overrides,
  } as GeoSummary;
}

describe('Dashboard', () => {
  let fixture: ComponentFixture<Dashboard>;
  let component: any;
  let api: jasmine.SpyObj<Api>;

  function build() {
    fixture = TestBed.createComponent(Dashboard);
    component = fixture.componentInstance;
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  beforeEach(() => {
    api = jasmine.createSpyObj<Api>('Api', [
      'summary', 'geo', 'systemMetrics', 'suricataStatus', 'topology', 'alerts',
    ]);
    api.alerts.and.returnValue(of({ total: 0, limit: 6, offset: 0, items: [] }));
    api.summary.and.returnValue(of(summary()));
    api.geo.and.returnValue(of(geo()));
    api.systemMetrics.and.returnValue(of(metrics()));
    api.suricataStatus.and.returnValue(of(status()));
    api.topology.and.returnValue(of({ current: { profile: 'self' } } as any));
    TestBed.configureTestingModule({
      providers: [{ provide: Api, useValue: api }, Live, provideRouter([])],
    });
  });

  afterEach(() => fixture?.destroy());

  it('asks how the Pi is wired and says so when nobody has said', () => {
    // An empty map and an empty alert list look the same whether the network is
    // quiet or nothing is reaching the sensor. This is the screen where that
    // difference shows.
    api.topology.and.returnValue(of({ current: { profile: '' } } as any));
    const dom = build();
    expect(component.layoutUnknown()).toBeTrue();
    expect(dom.querySelector('a[href="/setup"]')).not.toBeNull();
  });

  /** The advice for provoking an alert is only true for a sensor watching its
   *  own traffic. On a mirror it sends the reader chasing a test that cannot
   *  work, and a silent result there reads as a broken sensor. */
  it('tells you where to run the detection test, given where the sensor stands', () => {
    api.topology.and.returnValue(
      of({ current: { profile: 'mirror', roles: { capture: 'eth0' } } } as any));
    const dom = build();
    const hint = dom.querySelector('.empty-cmd')!.textContent!.replace(/\s+/g, ' ');
    expect(hint).toContain('in the segment being watched');
    expect(hint).toContain('eth0');
  });

  it('keeps the plain advice when the sensor watches its own traffic', () => {
    api.topology.and.returnValue(of({ current: { profile: 'self' } } as any));
    const dom = build();
    const hint = dom.querySelector('.empty-cmd')!.textContent!.replace(/\s+/g, ' ');
    expect(hint).toContain('To test detection, run');
    expect(hint).not.toContain('segment being watched');
  });

  it('says nothing about the wiring once it has been recorded', () => {
    build();
    expect(component.layoutUnknown()).toBeFalse();
  });

  /** The failure this panel exists to make impossible to miss. Suricata reports
   *  itself as running with its capture interface down, the counters simply
   *  stop moving, and the screen renders a quiet night. */
  it('says so on the dashboard when nothing can reach the engine', () => {
    api.suricataStatus.and.returnValue(of(status({
      capture: {
        interfaces: [{ name: 'eth0', present: true, up: false, carrier: false,
                       operstate: 'down' }],
        state: 'bad',
        problem: 'eth0 is down, so nothing reaches the engine.',
      },
    })));
    const dom = build();
    const note = dom.querySelector('.capture-note')!;
    expect(note).not.toBeNull();
    expect(note.textContent).toContain('eth0 is down');
    expect(note.classList).toContain('bad');
    // Above the numbers, because every one of them is meaningless while this
    // is true - a warning underneath a reassuring "0 alerts" is worth nothing.
    const tiles = dom.querySelector('.tiles-row')!;
    expect(note.compareDocumentPosition(tiles) & Node.DOCUMENT_POSITION_FOLLOWING)
      .toBeTruthy();
  });

  it('separates a missing cable from an interface nobody brought up', () => {
    // The panel did its part in this one: what is missing is at the far end,
    // so it is a warning and it does not borrow the danger colour.
    api.suricataStatus.and.returnValue(of(status({
      capture: {
        interfaces: [{ name: 'eth0', present: true, up: true, carrier: false,
                       operstate: 'up' }],
        state: 'warn',
        problem: 'eth0 is up but has no carrier.',
      },
    })));
    const dom = build();
    expect(dom.querySelector('.capture-note')!.classList).not.toContain('bad');
  });

  it('stays quiet while the capture interface is live', () => {
    // A banner that is always there is a banner nobody reads on the day it
    // means something.
    api.suricataStatus.and.returnValue(of(status({
      capture: {
        interfaces: [{ name: 'eth0', present: true, up: true, carrier: true,
                       operstate: 'up' }],
        state: 'ok', problem: null,
      },
    })));
    const dom = build();
    expect(dom.querySelector('.capture-note')).toBeNull();
  });

  it('splits the timeline by severity so a spike says whether it matters', () => {
    build();
    const bars = component.timeline();
    expect(bars.length).toBe(2);
    expect(bars[1].value).toBe(5);
    expect(bars[1].segments.reduce((sum: number, s: any) => sum + s.value, 0)).toBe(5);
  });

  it('lists only the ratings that actually occur', () => {
    // A legend full of empty classes reads as broken rather than quiet.
    build();
    expect(component.timelineLegend().map((l: any) => l.label))
      .toEqual(['Informational', 'Major']);
  });

  it('names a rule ET never rated instead of grading it', () => {
    // '' is not a severity. Folding it into one would put GPL and Suricata's
    // own stream events on the same footing as a rule ET actually looked at.
    api.summary.and.returnValue(of(summary({
      by_severity: [{ severity: null, count: 4 }],
      timeline: [{ bucket: '2026-08-23T10:00', count: 4, by_severity: { '': 4 } }],
    })));
    build();
    // And by the one name the rest of the panel uses for it: the badge in the
    // table said "unrated", the tile "Not rated" and the filter "Not rated by
    // ET", for one and the same thing.
    expect(component.timelineLegend().map((l: any) => l.label)).toEqual(['Not rated']);
  });

  it('does not call unplaceable public addresses "inside the network"', () => {
    // geo.local.unknown is public addresses the database has no entry for. The
    // chips below the map call that bucket "Not located"; the empty text
    // called the same rows local.
    api.geo.and.returnValue(of(geo({
      countries: [], local: { home: 0, private: 0, unknown: 12 },
    })));
    build();
    expect(component.mapEmptyText()).not.toContain('inside the network');
    expect(component.mapEmptyText()).toContain('could be put on the map');
  });

  it('does not say "no alerts" over countries the map cannot draw', () => {
    // They are alerts, and the chips below the map name them one by one.
    api.geo.and.returnValue(of(geo({
      countries: [], unplaced: [{ code: 'ZZ', name: 'Somewhere', count: 7 }] as any,
      local: { home: 0, private: 0, unknown: 0 },
    })));
    build();
    expect(component.mapEmptyText()).not.toBe('No alerts in this period');
    expect(component.mapEmptyText()).toContain('could be put on the map');
  });

  it('drops the unit with the reading it belongs to', () => {
    api.systemMetrics.and.returnValue(of(metrics({
      cpu: { ...metrics().cpu, temperature_c: null },
    })));
    const dom = build();
    const row = dom.querySelector('.kv.temp')!.textContent!;
    expect(row).toContain('no reading');
    expect(row).not.toContain('\u00b0C');
  });

  it('does not report a board with no thermal sensor as running normally', () => {
    // `?? 0` turned "no reading" into a reading of zero degrees, described as
    // normal, on a tile whose whole job is to say when the board is too hot.
    api.systemMetrics.and.returnValue(of(metrics({
      cpu: { ...metrics().cpu, temperature_c: null },
    })));
    build();
    expect(component.tempAlarm()).toBeFalse();
    expect(component.tempHint()).toContain('no reading');
    expect(component.tempHint()).not.toContain('normal');
  });

  it('tells an empty map from one whose alerts were all local', () => {
    build();
    expect(component.mapEmptyText()).toBe('No alerts in this period');

    api.geo.and.returnValue(of(geo({ countries: [], local: { home: 4, private: 0, unknown: 0 } })));
    const second = TestBed.createComponent(Dashboard);
    second.detectChanges();
    expect((second.componentInstance as any).mapEmptyText())
      .toContain('came from inside the network');
    second.destroy();
  });

  it('says when there is no geo database at all', () => {
    api.geo.and.returnValue(of(geo({ database: { available: false } as any })));
    build();
    expect(component.mapEmptyText()).toContain('No geo database');
    expect(component.geoCaption()).toContain('no geo database');
  });

  it('does not put the database build date on the map', () => {
    // It reads as a defect to act on, and there is no action: the data comes
    // from Debian every few months and a gap changes no country on this map.
    build();
    expect(component.geoCaption()).toBe('country level');
    expect(component.geoCaption()).not.toContain('2026-07-01');
  });

  it('drops the chips that would show a zero', () => {
    api.geo.and.returnValue(of(geo({ local: { home: 3, private: 0, unknown: 1 } })));
    build();
    expect(component.geoChips().map((c: any) => c.code)).toEqual(['home', 'unknown']);
  });

  it('treats counters as unknown until the engine has reported once', () => {
    // Before the first report every figure derived from them is unknown, not
    // zero, and a drop rate of "0%" would be a claim nobody has made.
    build();
    expect(component.hasStats()).toBeFalse();
    expect(component.dropAlarm()).toBeFalse();
  });

  it('takes the drop verdict from the device, not from its own threshold', () => {
    // Two copies of "> 1" is how the tile and the card end up disagreeing. The
    // backend decides; a percentage with no verdict beside it is not an alarm.
    api.suricataStatus.and.returnValue(of(status({
      last_stats_at: '2026-08-23T10:00:00+0200',
      engine: { ...status().engine, drop_rate_percent: 4,
                loss_measured: true, sensor_problem: null },
    })));
    build();
    expect(component.dropAlarm()).toBeFalse();
  });

  it('says n/a rather than 0.00 when the engine reports no capture counters', () => {
    // Inline on a netfilter queue there is no ring to overflow and no
    // kernel_drops at all. hasStats() is true there - a stats record does
    // arrive - so this tile passed its own "is it known yet" test and printed
    // a clean measurement nobody had taken.
    api.suricataStatus.and.returnValue(of(status({
      last_stats_at: '2026-08-23T10:00:00+0200',
      engine: { ...status().engine, loss_measured: false, capture_mode: 'nfqueue',
                  blocking: true,
                kernel_drops: null, kernel_packets: null, drop_rate_percent: null,
                blocked: 266, blocked_by_rules: 0 },
    })));
    const dom = build();
    expect(component.lossMeasured()).toBeFalse();
    expect(component.lossHint()).toContain('not reported');
    // It reads in the engine card now, next to the counters it comes from,
    // rather than as a tile between two figures about alerts.
    const label = Array.from(dom.querySelectorAll('.kv > span'))
      .find((t) => t.textContent?.trim() === 'Capture loss')!;
    const reading = label.nextElementSibling!;
    expect(reading.textContent).toContain('n/a');
    expect(reading.textContent).not.toContain('0.00');
    expect(reading.textContent).toContain('not reported');
  });

  it('does not call 80 degrees normal', () => {
    // The tile coloured itself off temperature or throttling and then took its
    // words from throttling alone, so a hot board rendered red and said normal.
    api.systemMetrics.and.returnValue(of(metrics({
      cpu: { ...metrics().cpu, temperature_c: 80 },
      throttling: { under_voltage_now: false, throttled_now: false } as any,
    })));
    build();
    expect(component.tempAlarm()).toBeTrue();
    expect(component.tempHint()).toBe('hot');
  });

  it('does not claim a normal throttling state it cannot read', () => {
    // vcgencmd missing or failing gives null, which is not the same as knowing
    // there is nothing wrong.
    api.systemMetrics.and.returnValue(of(metrics({ throttling: null })));
    build();
    expect(component.tempHint()).toContain('no throttling data');
  });

  it('shows stored alerts before the stream has delivered anything', () => {
    // The card read only the WebSocket buffer, which is empty on every page
    // load, after every reconnect and while the stream is paused - and then
    // printed "Silence here is good news" over a database full of alerts.
    api.alerts.and.returnValue(of({
      total: 900, limit: 6, offset: 0,
      items: [{ id: 7, signature: 'ET MALWARE Stored', ts: '2026-08-23T10:00:00+0200' }],
    } as any));
    const dom = build();
    expect(component.recentAlerts().length).toBe(1);
    expect(dom.textContent).toContain('ET MALWARE Stored');
    expect(dom.textContent).not.toContain('No recent alerts');
  });

  it('still says nothing is there when nothing is there', () => {
    const dom = build();
    expect(component.recentAlerts().length).toBe(0);
    expect(dom.textContent).toContain('No recent alerts');
  });

  it('does not call an empty list good news', () => {
    // It is just as empty with the engine stopped or no traffic arriving, so
    // it sends the reader to the sensor instead of reassuring them.
    const dom = build();
    expect(dom.textContent).not.toContain('good news');
    expect(dom.textContent).toContain('Check that the engine is running and sees traffic');
  });

  it('raises the alarms that mean the device is losing traffic', () => {
    api.suricataStatus.and.returnValue(of(status({
      last_stats_at: '2026-08-23T10:00:00+0200',
      engine: { ...status().engine, kernel_drops: 400, drop_rate_percent: 4,
                loss_measured: true, sensor_problem: 'drops' },
    })));
    api.systemMetrics.and.returnValue(of(metrics({
      cpu: { ...metrics().cpu, temperature_c: 80 },
      throttling: { under_voltage_now: true, throttled_now: false } as any,
    })));
    build();
    expect(component.dropAlarm()).toBeTrue();
    expect(component.tempAlarm()).toBeTrue();
    expect(component.throttleAlarm()).toBeTrue();
  });

  it('reports a backend it cannot reach once, not once per panel', () => {
    api.summary.and.returnValue(throwError(() => ({ message: 'Http failure' })));
    api.geo.and.returnValue(throwError(() => ({ message: 'Http failure' })));
    build();
    expect(component.loadError()).toContain('Http failure');
  });

  describe('the two headline tiles', () => {
    it('makes the queue the headline, and the queue has no window', () => {
      // Measured on the device: 22 alerts an hour left a 24 h window, so the
      // old headline counted down through a quiet night with nobody touching
      // it. A number that falls on its own cannot be the answer to "is
      // anything waiting for me".
      api.summary.and.returnValue(of(summary({ pending: 12362, total_window: 302 })));
      const dom = build();
      const labels = Array.from(dom.querySelectorAll('.tile-label'))
        .map((t) => t.textContent ?? '');
      expect(labels[0]).toBe('Needs review');
      expect(labels).not.toContain('Alerts (last 24 h)');
      const value = dom.querySelectorAll('.tile-value')[0]?.textContent ?? '';
      expect(value.replace(/\s/g, '')).toContain('12,362');
    });

    it('does not move the queue when the window changes', () => {
      // The selector governs the chart and the lists. If it reached the queue
      // too, the tile would fall by itself again the moment somebody used it.
      api.summary.and.returnValue(of(summary({ pending: 40, total_window: 5 })));
      const dom = build();
      component.setWindow('30d');
      fixture.detectChanges();
      const value = dom.querySelectorAll('.tile-value')[0]?.textContent ?? '';
      expect(value.replace(/\s/g, '')).toContain('40');
    });

    it('opens the same rows it counted, not a windowed subset', () => {
      // An all-time number linking into a 24 h list is the same fault in a
      // different place: two figures on two screens called the same thing.
      const dom = build();
      const href = dom.querySelector('a.tile')?.getAttribute('href') ?? '';
      expect(href).toContain('unacked=1');
      expect(href).toContain('since=all');
    });

    it('sets the backlog against everything ever stored', () => {
      api.summary.and.returnValue(of(summary({ pending: 3, total_all_time: 40 })));
      build();
      expect(component.pendingHint()).toContain('40');
      expect(component.pendingHint()).toContain('ages out');
    });

    it('says the queue is empty rather than printing a bare zero', () => {
      api.summary.and.returnValue(of(summary({ pending: 0, total_all_time: 40 })));
      build();
      expect(component.pendingHint()).toContain('empty');
    });

    it('says how bad, not only how many', () => {
      // A total counts, a rating judges. 417 alerts is a bad morning or a dull
      // one depending entirely on whether one of them is Critical, and that
      // breakdown used to sit in a rank list below the fold.
      api.summary.and.returnValue(of(summary({
        today_by_severity: [{ severity: 'Critical', count: 2 },
                            { severity: 'Informational', count: 415 }],
      })));
      const dom = build();
      const labels = Array.from(dom.querySelectorAll('.tile-label'))
        .map((t) => t.textContent ?? '');
      expect(labels).toEqual(
        ['Needs review', 'Critical', 'Major', 'Minor', 'Informational']);
      const tiles = component.ratingTiles();
      expect(tiles[0].value).toBe('2');
      expect(tiles[3].value).toBe('415');
    });

    it('prints a dash where a rating has nothing, not a zero', () => {
      // "0" reads as a measurement somebody took. On the Critical tile that is
      // the wrong impression to leave when the engine has been down all day.
      api.summary.and.returnValue(of(summary({ today_by_severity: [] })));
      build();
      expect(component.ratingTiles().map((t: any) => t.value))
        .toEqual(['-', '-', '-', '-']);
    });

    it('carries yesterday in the hint, because one day says nothing', () => {
      api.summary.and.returnValue(of(summary({
        today_by_severity: [{ severity: 'Critical', count: 2 }],
        yesterday_by_severity: [{ severity: 'Critical', count: 31 }],
      })));
      build();
      expect(component.ratingTiles()[0].hint).toBe('31 yesterday');
      expect(component.ratingTiles()[1].hint).toBe('none yesterday');
    });

    it('colours the tile only when the rating has something in it', () => {
      // Colour is the message here. A row where every tier is tinted says
      // nothing, so the tint arrives with the first alert of that rating.
      api.summary.and.returnValue(of(summary({
        today_by_severity: [{ severity: 'Critical', count: 1 }],
      })));
      build();
      const [critical, major] = component.ratingTiles();
      expect(critical.tone).toBe('rating sev-1 lit');
      expect(major.tone).toBe('rating sev-2');
    });

    it('shows the unrated tier only when it holds something', () => {
      // Not one of ET's tiers: it is the rules ET never graded. A permanent
      // empty tile would be the fifth thing to read before the first one that
      // matters, and hiding it while it is empty hides nothing.
      build();
      expect(component.ratingTiles().length).toBe(4);
      api.summary.and.returnValue(of(summary({
        today_by_severity: [{ severity: null, count: 9 }],
      })));
      build();
      const last = component.ratingTiles()[4];
      expect(last.label).toBe('Not rated');
      expect(last.value).toBe('9');
      expect(last.tone).toContain('sev-none');
    });

    it('opens the day and the rating that was clicked', () => {
      // The tile counts today by rating. A link into a rolling window, or one
      // that dropped the rating, would open a list disagreeing with the number
      // under the finger that pressed it.
      api.summary.and.returnValue(of(summary({
        today_by_severity: [{ severity: 'Critical', count: 2 }],
      })));
      const dom = build();
      const href = Array.from(dom.querySelectorAll('a.tile'))
        .map((a) => a.getAttribute('href') ?? '')
        .find((h) => h.includes('severity=Critical'));
      expect(href).toContain('since=today');
      expect(href).toContain('tab=alerts');
    });

    it('opens each day from the line under the chart', () => {
      const dom = build();
      const hrefs = Array.from(dom.querySelectorAll('.day-line a'))
        .map((a) => a.getAttribute('href') ?? '');
      expect(hrefs.some((h) => h.includes('since=today'))).toBeTrue();
      expect(hrefs.some((h) => h.includes('since=yesterday'))).toBeTrue();
    });

    it('puts the day totals beside the chart they belong to', () => {
      // On a tile they were a number without a reason. Here the shape under
      // them is the reason.
      api.summary.and.returnValue(of(summary({ today: 417, yesterday: 173 })));
      const dom = build();
      const line = dom.querySelector('.day-line')?.textContent ?? '';
      expect(line).toContain('today 417');
      expect(line).toContain('yesterday 173');
    });

    it('names the engine events every figure here leaves out', () => {
      // A quarter of what is stored on this sensor. Leaving them out silently
      // would be the worse of the two faults, and a number nobody can open is
      // one nobody can check.
      api.summary.and.returnValue(of(summary({ diagnostics_today: 1176 })));
      const dom = build();
      expect(component.notesToday()).toContain('1,176');
      const link = Array.from(dom.querySelectorAll('.day-line a'))
        .find((a) => (a.textContent ?? '').includes('engine notes'));
      expect(link!.getAttribute('href')).toContain('kind=diagnostic');
    });

    it('counts those notes over the same day as the totals beside them', () => {
      // The windowed count used to be printed under a lifetime total, which on
      // a month-old database asserted that a month and a day add up.
      api.summary.and.returnValue(
        of(summary({ diagnostics_today: 7, diagnostics: 999 })));
      build();
      expect(component.notesToday()).toContain('7');
      expect(component.notesToday()).not.toContain('999');
    });

    it('says nothing about them when there are none', () => {
      api.summary.and.returnValue(of(summary({ diagnostics_today: 0 })));
      build();
      expect(component.notesToday()).toBe('');
    });
  });

  describe('what the engine stopped', () => {
    it('is a tile with a number, not a badge somebody has to scroll for', () => {
      // The verdict was on every row already and the list badged it, but the
      // only way to find out whether blocking had ever stopped anything was to
      // read the list.
      api.summary.and.returnValue(of(summary({ blocked: 12 })));
      const dom = build();
      const tile = Array.from(dom.querySelectorAll('.tile'))
        .find((t) => t.textContent?.includes('Blocked'));
      expect(tile).toBeTruthy();
      expect(tile!.textContent).toContain('12');
    });

    it('stands beside the queue, not after the ratings', () => {
      // Last in the row it read as a sixth tier of a five tier scale, and on a
      // narrow screen it fell into the next line entirely.
      api.summary.and.returnValue(of(summary({ blocked: 12 })));
      const dom = build();
      // The first child node only: the badge is a span inside the same label.
      const labels = Array.from(dom.querySelectorAll('.tiles-row .tile-label'))
        .map((l) => l.firstChild!.textContent!.trim());
      expect(labels.slice(0, 3)).toEqual(['Needs review', 'Blocked', 'Critical']);
    });

    it('rises into place like the tiles on every other screen', () => {
      // The frame is a wrapper the global entry animation did not know about,
      // so the strip appeared fully formed while System and IDS animated.
      api.summary.and.returnValue(of(summary({ blocked: 12 })));
      const dom = build();
      const tile = dom.querySelector('.group-state stat-tile')!;
      expect(getComputedStyle(tile).animationName).toBe('rise');
    });

    it('keeps the two state tiles side by side while blocking is on', () => {
      // The frame is sized by its own contents, and a grid asked to size that
      // way collapses to one column: the pair stood one above the other while
      // the ratings beside them stayed in a row.
      api.summary.and.returnValue(of(summary({ blocked: 12 })));
      const dom = build();
      const tiles = Array.from(dom.querySelectorAll('.group-state .tile'))
        .map((t) => (t as HTMLElement).getBoundingClientRect());
      expect(tiles.length).toBe(2);
      // Within a pixel, not to the fraction: layout rounds subpixel positions
      // differently from one run to the next (272.484 against 272.5 was seen),
      // and a test that fails on that says nothing about the layout.
      expect(Math.abs(tiles[0].top - tiles[1].top)).toBeLessThan(1);
      expect(tiles[0].right).toBeLessThanOrEqual(tiles[1].left + 1);
      // And the same width: sized by their own text, "306" and "73" gave the
      // pair two different widths inside one frame.
      expect(Math.abs(tiles[0].width - tiles[1].width)).toBeLessThan(1);
    });

    it('does not stretch the queue tile across the strip in detection mode', () => {
      // Blocked is hidden while the engine only reads a copy, so the frame
      // holds one tile. Claiming a fixed share of the row then spread that
      // one number across a third of the screen.
      api.summary.and.returnValue(of(summary({ blocked: 0 })));
      const dom = build();
      const inState = dom.querySelectorAll('.group-state .tile');
      expect(inState.length).toBe(1);
      const queue = (inState[0] as HTMLElement).getBoundingClientRect().width;
      const rating = (dom.querySelector('.group-rating .tile') as HTMLElement)
        .getBoundingClientRect().width;
      // Neither stretched across the strip nor squeezed under the numbers it
      // stands beside: one tile, about as wide as the tiles next to it.
      expect(queue).toBeLessThan(rating * 1.6);
      expect(queue).toBeGreaterThan(rating * 0.8);
    });

    it('is framed with the queue, apart from the rating scale', () => {
      api.summary.and.returnValue(of(summary({ blocked: 12 })));
      const dom = build();
      const inState = Array.from(dom.querySelectorAll('.group-state .tile-label'))
        .map((l) => l.firstChild!.textContent!.trim());
      const inRatings = Array.from(dom.querySelectorAll('.group-rating .tile-label'))
        .map((l) => l.firstChild!.textContent!.trim());
      expect(inState).toEqual(['Needs review', 'Blocked']);
      expect(inRatings).toContain('Critical');
      expect(inRatings).not.toContain('Blocked');
    });

    it('is not dressed as a rating, and says which mode it belongs to', () => {
      api.summary.and.returnValue(of(summary({ blocked: 12 })));
      const dom = build();
      const tile = Array.from(dom.querySelectorAll('.tile'))
        .find((t) => t.textContent?.includes('Blocked'))!;
      expect(tile.classList).toContain('blocking');
      expect(tile.classList).toContain('lit');
      expect(tile.classList).not.toContain('rating');
      expect(tile.querySelector('.tile-badge')!.textContent!.trim()).toBe('IPS');
    });

    it('is not lit when the engine has stopped nothing', () => {
      api.summary.and.returnValue(of(summary({ blocked: 0 })));
      api.suricataStatus.and.returnValue(of(status({
        last_stats_at: '2026-08-23T10:00:00+0200',
        engine: { ...status().engine, capture_mode: 'nfqueue', loss_measured: false,
                  blocking: true },
      })));
      const dom = build();
      const tile = Array.from(dom.querySelectorAll('.tile'))
        .find((t) => t.textContent?.includes('Blocked'))!;
      expect(tile.classList).toContain('blocking');
      expect(tile.classList).not.toContain('lit');
    });

    it('opens exactly those rows', () => {
      api.summary.and.returnValue(of(summary({ blocked: 12 })));
      const dom = build();
      const link = Array.from(dom.querySelectorAll('a.tile'))
        .find((t) => t.textContent?.includes('Blocked')) as HTMLAnchorElement;
      expect(link).toBeTruthy();
      expect(link.getAttribute('href')).toContain('blocked=1');
    });

    it('is absent while the engine only reads a copy', () => {
      // Nothing is ever blocked there, and a tile permanently reading zero is
      // a tile nobody reads on the day it is not.
      api.summary.and.returnValue(of(summary({ blocked: 0 })));
      const dom = build();
      const tile = Array.from(dom.querySelectorAll('.tile'))
        .find((t) => t.textContent?.includes('Blocked'));
      expect(tile).toBeUndefined();
    });

    it('stays on the screen at zero while the engine is inline', () => {
      // "Blocking is on" and "blocking is doing anything" are different
      // statements, and with no tile the first one reads as the second.
      api.summary.and.returnValue(of(summary({ blocked: 0 })));
      api.suricataStatus.and.returnValue(of(status({
        last_stats_at: '2026-08-23T10:00:00+0200',
        engine: { ...status().engine, capture_mode: 'nfqueue',
                  loss_measured: false, blocking: true },
      })));
      const dom = build();
      const tile = Array.from(dom.querySelectorAll('.tile'))
        .find((t) => t.textContent?.includes('Blocked'));
      expect(tile).toBeTruthy();
      expect(tile!.textContent).toContain('0');
    });

    it('says which kind of zero it is', () => {
      api.summary.and.returnValue(of(summary({ blocked: 0 })));
      api.suricataStatus.and.returnValue(of(status({
        last_stats_at: '2026-08-23T10:00:00+0200',
        engine: { ...status().engine, capture_mode: 'nfqueue', blocking: true },
      })));
      build();
      expect(component.blockedHint()).toContain('blocking is on');
      expect(component.blockedHint()).toContain('nothing stopped');
    });

    it('says what a number means when there is one', () => {
      api.summary.and.returnValue(of(summary({ blocked: 12 })));
      build();
      expect(component.blockedHint()).toContain('stopped by the engine');
    });
  });

  describe('the window every card is labelled with', () => {
    it('names the selected window, not a fixed one', () => {
      // Five titles had "(24 h)" typed into them while the numbers under them
      // came from the selector. On 30 days a month of signature counts read as
      // a day's, which badly overstates what is happening now.
      const dom = build();
      component.setWindow('30d');
      fixture.detectChanges();
      const titles = Array.from(dom.querySelectorAll('.card-title'))
        .map((t) => t.textContent ?? '');
      const labelled = titles.filter((t) => t.includes('h)') || t.includes('d)'));
      expect(labelled.length).toBeGreaterThanOrEqual(4);
      for (const title of labelled) {
        expect(title).toContain('30 d');
        expect(title).not.toContain('24 h');
      }
    });

    /** The three sentences sit on the selector that raises the question: true,
     *  read once, and three lines tall above the numbers they explain. */
    function help(dom: HTMLElement): string {
      return dom.querySelector('.head-row select')!.getAttribute('title') ?? '';
    }

    it('says the window slides, which is why a count falls untouched', () => {
      // Reported from the device: 22 alerts a day leave a 24 hour window every
      // hour, so through a quiet night the tile counts down on its own. With
      // the screen saying only "(24 h)" that reads as the panel losing rows.
      const dom = build();
      const text = help(dom);
      expect(text).toContain('the last 24 hours');
      expect(text).toContain('counted back from now');
      expect(text).toMatch(/fall|age out/);
    });

    it('moves that sentence with the selector', () => {
      const dom = build();
      component.setWindow('7d');
      fixture.detectChanges();
      const text = help(dom);
      expect(text).toContain('the last 7 days');
      expect(text).not.toContain('24 hours');
    });

    it('does not promise the rating tiles move only when somebody acts', () => {
      // They count today against yesterday, so they start again at midnight
      // and an acknowledgement does not touch them.
      const dom = build();
      const text = help(dom);
      expect(text).toContain('midnight');
      expect(text).toContain('map');
    });

    it('says which figures move with the window and which do not', () => {
      // The window governs the chart, the lists and the blocked count. Saying
      // "the tiles do not move on their own" covered a tile that does: Blocked
      // is counted inside the window and falls as those alerts age out of it.
      const dom = build();
      const text = help(dom);
      expect(text).toContain('review queue');
      expect(text).toContain('blocked count');
      expect(text).not.toContain('tiles do not move');
    });

    it('keeps the explanation off the page until somebody asks the control', () => {
      // Three lines of explanation above the numbers they explain pushed the
      // numbers down the screen for everybody who already knew.
      const dom = build();
      const intro = dom.querySelector('.page-head p.muted')!.textContent!;
      expect(intro.trim()).toBe('Intrusion detection state and device health.');
      expect(dom.querySelector('.page-head')!.textContent).not.toContain('counted back');
      // And the selector still says what it is, for anyone not using a mouse.
      expect(dom.querySelector('.head-row select')!.getAttribute('aria-label'))
        .toBe('Time window');
    });

    it('calls the chart bars what the server actually sent', () => {
      // Above 48 hours the backend switches to one bar per day. The title said
      // "per hour" over thirty daily bars, and the client already knew better.
      api.summary.and.returnValue(of(summary({ timeline_step_hours: 24 })));
      const dom = build();
      expect(component.timelineUnit()).toBe('day');
      const title = Array.from(dom.querySelectorAll('.card-title'))
        .map((t) => t.textContent ?? '').find((t) => t.includes('Alerts per'));
      expect(title).toContain('per day');
    });

    it('says per hour while the bars are hourly', () => {
      const dom = build();
      expect(component.timelineUnit()).toBe('hour');
      const title = Array.from(dom.querySelectorAll('.card-title'))
        .map((t) => t.textContent ?? '').find((t) => t.includes('Alerts per'));
      expect(title).toContain('per hour');
    });
  });

  it('a country on the map opens the alert list already filtered', () => {
    build();
    const navigate = spyOn((component as any).router, 'navigate');
    component.openCountry('US');
    expect(navigate).toHaveBeenCalledWith(['/ids'], { queryParams: { tab: 'alerts', cc: 'US' } });
  });

  /** The rank cards are compared against each other, so they have to sit in
   *  one line. The grid around them changes column count with the viewport,
   *  which a test cannot set; what it can set is the width the row is given, and
   *  the row is built to follow that instead.
   *
   *  Two of them now, not three: the ratings left this row for the top strip,
   *  where they are the first thing read rather than the last. */
  it('keeps the rank cards in one row', () => {
    const dom = build();
    (dom as HTMLElement).style.width = '1200px';

    const titles = ['Top signatures (24 h)', 'Busiest sources (24 h)'];
    const cards = Array.from(
      dom.querySelectorAll<HTMLElement>('.card-row > .card'));
    expect(cards.map(c => c.querySelector('.card-title')!.textContent!.trim()))
      .toEqual(titles);

    const tops = cards.map(c => c.offsetTop);
    expect(tops.every(top => top === tops[0])).toBeTrue();

    const lefts = cards.map(c => c.offsetLeft);
    expect(lefts[0]).toBeLessThan(lefts[1]);

    // Equal shares: one card left wider than the others would read as the one
    // that matters, which is not a claim this row makes.
    const widths = cards.map(c => c.offsetWidth);
    expect(Math.max(...widths) - Math.min(...widths)).toBeLessThanOrEqual(1);
  });

  // --- the window every figure on the screen belongs to ------------------
  //
  // The tile, the chart and all three lists share one window, so a burst that
  // ages past the end of it leaves every one of them in the same instant and
  // nothing is left saying it happened. That is what the selector is for.

  it('asks for the window that is selected, not the one it started on', () => {
    build();
    expect(api.summary).toHaveBeenCalledWith(24);

    component.setWindow('7d');
    expect(api.summary).toHaveBeenCalledWith(168);
    // The map is windowed too. Left behind it would show a week of countries
    // beside a day of counts, or the reverse, with nothing saying so.
    expect(api.geo).toHaveBeenCalledWith(168);
  });

  it('moves the whole screen at once rather than waiting for the poll', () => {
    build();
    const summaries = api.summary.calls.count();
    const geos = api.geo.calls.count();
    component.setWindow('30d');
    expect(api.summary.calls.count()).toBe(summaries + 1);
    expect(api.geo.calls.count()).toBe(geos + 1);
  });

  it('refuses a window it does not offer', () => {
    build();
    component.setWindow('all-of-it');
    expect(component.window()).toBe('24h');
    expect(api.summary).toHaveBeenCalledWith(24);
  });

  it('keeps the window off the headline tile and out of its link', () => {
    // This tile used to carry the window, and a number that silently means
    // something different from what it meant a moment ago is the complaint
    // this whole screen was rebuilt for. The queue has no window at all, so
    // neither its label nor its link may pick one up from the selector.
    const dom = build();
    component.setWindow('7d');
    fixture.detectChanges();
    const tile = dom.querySelector('.tiles-row stat-tile')!;
    expect(tile.textContent).not.toContain('7 d');
    expect(tile.textContent).not.toContain('24 h');
    expect(tile.querySelector('a')!.getAttribute('href')).toContain('since=all');
  });

  it('labels the axis by day when the server bucketed by day', () => {
    // "07" is an hour on one window and a day of the month on another, and the
    // bucket string alone does not say which.
    api.summary.and.returnValue(of(summary({
      timeline_step_hours: 24,
      timeline: [
        { bucket: '2026-08-30', count: 2, by_severity: { Major: 2 } },
        { bucket: '2026-08-31', count: 0, by_severity: {} },
      ],
    })));
    build();
    expect(component.timeline().map((d: any) => d.label)).toEqual(['30', '31']);
    expect(component.timeline()[0].title).toBe('30/08');
  });

  it('still labels the axis by hour on the short window', () => {
    build();
    expect(component.timeline().map((d: any) => d.label)).toEqual(['09', '10']);
    expect(component.timeline()[1].title).toBe('23/08, 10:00');
  });

  it('stops polling when the view goes away', () => {
    build();
    expect(component.timers.length).toBeGreaterThan(0);
    fixture.destroy();
    expect(component.timers.length).toBe(0);
  });
});
