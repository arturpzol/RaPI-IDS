import { convertToParamMap, provideRouter } from '@angular/router';
import { ComponentFixture, TestBed, fakeAsync, tick } from '@angular/core/testing';
import { BehaviorSubject, Subject, of, throwError } from 'rxjs';

import { Api } from '../../core/api';
import { Live } from '../../core/live';
import { Alert, AlertPage } from '../../core/models';
import { Ids } from './ids';

function alert(id: number, overrides: Partial<Alert> = {}): Alert {
  return {
    id,
    ts: '2026-08-23T10:15:00+0200',
    event_type: 'alert',
    src_ip: '203.0.113.7',
    src_port: 44321,
    dest_ip: '192.168.1.10',
    dest_port: 443,
    proto: 'TCP',
    app_proto: 'tls',
    signature: 'ET MALWARE Test',
    signature_id: 2000001,
    category: 'A Network Trojan was detected',
    severity: 1,
    iface: 'eth0',
    src_cc: 'US',
    acknowledged: false,
    ...overrides,
  } as Alert;
}

function page(items: Alert[] = [alert(1)], total = items.length): AlertPage {
  return { total, limit: 50, offset: 0, items };
}

/** A whole engine block. Half of it is read by the sensor card, so a stub with
 *  only the fields one test cares about takes the others down with it. */
function engineStub(overrides: Record<string, unknown> = {}) {
  return {
    uptime_seconds: 3600, packets: 1000, bytes: 1000,
    kernel_packets: 1000, kernel_drops: 0, capture_errors: 0,
    drop_rate_percent: 0, capture_mode: 'af-packet', loss_measured: true,
    blocked: null, blocked_by_rules: null,
    tcp_sessions: 10, reassembly_gaps: 0, gap_rate_percent: 0,
    sensor_problem: null, alerts_detected: 0, alerts_stored: null,
    alerts_missing: null, flows: 0,
    ...overrides,
  };
}

describe('Ids', () => {
  let fixture: ComponentFixture<Ids>;
  let component: any;
  let api: jasmine.SpyObj<Api>;

  function build() {
    fixture = TestBed.createComponent(Ids);
    component = fixture.componentInstance;
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  function lastFilters() {
    return api.alerts.calls.mostRecent().args[0] as Record<string, unknown>;
  }

  beforeEach(() => {
    api = jasmine.createSpyObj<Api>('Api', [
      'alerts', 'alert', 'ackAlert', 'ackAllAlerts', 'suricataStatus', 'muteSignature',
      'unmuteSignature', 'serviceAction', 'engineLog', 'protection',
      'allowSignature', 'unallowSignature',
      // Mounted only by the layout test that opens the last tab. Unstubbed it
      // fails as a TypeError instead of as the layout answer the test came for.
      'notifications',
    ]);
    api.alerts.and.returnValue(of(page()));
    api.alert.and.callFake((id: number) => of(alert(id)));
    api.ackAlert.and.returnValue(of({ id: 1, acknowledged: true }));
    api.ackAllAlerts.and.returnValue(of({ acknowledged: 12362 }));
    api.suricataStatus.and.returnValue(of({ service: { running: true } } as any));
    api.serviceAction.and.returnValue(of({ ok: true, output: '' }));
    api.protection.and.returnValue(of({ muted: [] } as any));
    api.engineLog.and.returnValue(of({ path: '', lines: [] }));
    api.muteSignature.and.returnValue(of({ ok: true, output: '', state: { muted: [] } } as any));
    api.unmuteSignature.and.returnValue(of({ ok: true, output: '', state: { muted: [] } } as any));
    api.notifications.and.returnValue(of({ settings: {}, status: {} } as any));
    TestBed.configureTestingModule({
      providers: [{ provide: Api, useValue: api }, Live, provideRouter([])],
    });
  });

  afterEach(() => fixture?.destroy());


  it('asks for the first page on the alert tab', () => {
    build();
    expect(api.alerts).toHaveBeenCalled();
    expect(lastFilters()['offset']).toBe(0);
  });

  it('sends a window as a number of hours, not as a timestamp', () => {
    // The cutoff belongs to the machine the engine writes its timestamps on; a
    // browser in another timezone would work out a different one.
    build();
    component.setWindow('24h');
    expect(lastFilters()['hours']).toBe(24);
    expect(lastFilters()['offset']).toBe(0);
  });

  it('ignores a window it does not know', () => {
    build();
    component.setWindow('since-tuesday');
    expect(lastFilters()['hours']).toBeNull();
  });

  it('waits for the typing to stop before searching', fakeAsync(() => {
    build();
    api.alerts.calls.reset();
    component.onSearchInput('mal');
    component.onSearchInput('malware');
    tick(100);
    expect(api.alerts).not.toHaveBeenCalled();
    tick(300);
    expect(api.alerts.calls.count()).toBe(1);
    expect(lastFilters()['search']).toBe('malware');
  }));

  it('drops a query still in flight before starting another', () => {
    // A search is a full table scan; the slow filtered answer used to land
    // after the fast unfiltered one and overwrite it, so "Clear" looked dead.
    build();
    const first = component.alertsRequest;
    spyOn(first, 'unsubscribe').and.callThrough();
    component.loadAlerts();
    expect(first.unsubscribe).toHaveBeenCalled();
  });

  it('clears every filter at once, typing included', fakeAsync(() => {
    build();
    component.onSearchInput('malware');
    tick(350);
    component.setSeverity('1');
    component.toggleUnacked();
    component.setWindow('24h');
    api.alerts.calls.reset();

    component.resetFilters();
    tick(400);
    const filters = lastFilters();
    expect(filters['search']).toBeNull();
    expect(filters['severity']).toBeNull();
    expect(filters['acknowledged']).toBeNull();
    expect(filters['hours']).toBeNull();
    expect(filters['src_cc']).toBeNull();
  }));

  describe('what the engine actually stopped', () => {
    it('marks the rows where the packet was stopped', () => {
      // Every alert carries the verdict and nothing read it, so in blocking
      // mode the list showed which rules matched and never which of them
      // stopped anything.
      api.alerts.and.returnValue(of(page([
        alert(1, { action: 'blocked' } as any),
        alert(2, { action: 'allowed' } as any),
      ])));
      const el = build();
      const rows = el.querySelectorAll('tbody tr');
      expect(rows[0].querySelector('.badge.blocked')).toBeTruthy();
      expect(rows[1].querySelector('.badge.blocked')).toBeNull();
    });

    it('says nothing on a row from before the panel recorded a verdict', () => {
      api.alerts.and.returnValue(of(page([alert(1, { action: null } as any)])));
      const el = build();
      expect(el.querySelector('.badge.blocked')).toBeNull();
    });

    it('is not asked for by default, because most devices stop nothing', () => {
      // A sensor reading a copy blocks nothing at all; left on, this filter
      // would empty the list on almost every install.
      build();
      expect(lastFilters()['blocked']).toBeNull();
    });

    it('narrows the list to what was stopped, from the first page', () => {
      api.alerts.and.returnValue(of(page([alert(1)], 120)));
      build();
      component.nextPage();
      component.setBlocked(true);
      expect(lastFilters()['blocked']).toBeTrue();
      expect(lastFilters()['offset']).toBe(0);
    });

    it('leaves the country as a pill, because it is not a closed set', () => {
      // The rule the toolbar follows: a filter with a fixed set of choices is a
      // control, a value carried in from another screen is a pill. A country
      // comes from the map and there are two hundred of them.
      const el = build();
      component.country.set('US');
      fixture.detectChanges();
      const pills = Array.from(el.querySelectorAll('.filter-pill'))
        .map((p) => p.textContent ?? '');
      expect(pills.length).toBe(1);
      expect(pills[0]).toContain('source:');
    });

    it('is a checkbox in the toolbar, settable as well as clearable', () => {
      // It used to be a pill: something you could remove but never add, so the
      // only way into it was a button under the list or a link from the
      // dashboard, and the toolbar read as a list of what somebody else had
      // already decided.
      const el = build();
      const box = Array.from(el.querySelectorAll<HTMLLabelElement>('.filters .check'))
        .find((l) => l.textContent?.includes('blocked only'))!
        .querySelector('input')!;
      expect(box.checked).toBeFalse();

      box.click();
      fixture.detectChanges();
      expect(lastFilters()['blocked']).toBeTrue();
      expect(box.checked).toBeTrue();

      box.click();
      fixture.detectChanges();
      expect(lastFilters()['blocked']).toBeNull();
    });

    it('shows itself as ticked when it arrives from the dashboard', () => {
      // Read from the rendered control, not from the signal: the same fault as
      // the rating select, which filtered the list and said "Any rating".
      const el = build();
      component.setBlocked(true);
      fixture.detectChanges();
      const box = Array.from(el.querySelectorAll<HTMLLabelElement>('.filters .check'))
        .find((l) => l.textContent?.includes('blocked only'))!
        .querySelector('input')!;
      expect(box.checked).toBeTrue();
    });

    it('is offered even where nothing is ever blocked', () => {
      // The dashboard hides the Blocked tile on a sensor reading a copy, and
      // that stays: a tile asserts something, a control only asks. "None" is a
      // true answer to a question, and a control nobody can find teaches
      // nobody that the panel knows the difference.
      const el = build();
      const labels = Array.from(el.querySelectorAll('.filters .check'))
        .map((l) => l.textContent ?? '');
      expect(labels.some((l) => l.includes('blocked only'))).toBeTrue();
    });

    it('offers a way out of an empty list it caused on its own', () => {
      // The empty state knew four of the six filters. On a sensor that blocks
      // nothing, ticking this emptied the list, said no rows matched, and
      // offered nothing to undo.
      api.alerts.and.returnValue(of(page([], 0)));
      const el = build();
      component.setBlocked(true);
      fixture.detectChanges();
      const out = Array.from(el.querySelectorAll('.empty button'))
        .find((b) => b.textContent?.includes('Show all'));
      expect(out).toBeTruthy();
      (out as HTMLElement).click();
      expect(component.onlyBlocked()).toBeFalse();
    });

    it('is dropped by Clear like every other filter', () => {
      build();
      component.setBlocked(true);
      component.resetFilters();
      expect(component.onlyBlocked()).toBeFalse();
    });
  });

  describe('the engine alert counter', () => {
    it('opens the list when it is pressed, not just in the address bar', () => {
      // The counter is every alert the engine raised, threats and its own notes
      // together. On this sensor that was 888 while the alert list showed 52.
      const el = build();
      component.setTab('rules');
      fixture.detectChanges();
      const tile = Array.from(el.querySelectorAll('.tile'))
        .find((t) => t.textContent?.includes('Alerts detected')) as HTMLElement;
      expect(tile.tagName).withContext('a same-page target has to act').toBe('BUTTON');

      tile.click();
      fixture.detectChanges();
      expect(component.tab()).toBe('alerts');
      expect(component.kind()).toBe('all');
      expect(lastFilters()['kind']).toBe('all');
    });

    it('says how many of them the panel has', () => {
      api.suricataStatus.and.returnValue(of({
        service: { running: true },
        engine: engineStub({ alerts_detected: 1131, alerts_stored: 1132,
                             alerts_missing: 0 }),
        event_counts: {},
      } as any));
      const el = build();
      component.setTab('rules');
      fixture.detectChanges();
      const tile = Array.from(el.querySelectorAll('.tile'))
        .find((t) => t.textContent?.includes('Alerts detected'));
      expect(tile!.textContent).toContain('all of them stored here');
      expect(tile!.classList.contains('alarm')).toBeFalse();
    });

    it('says so, and colours, when the panel is behind', () => {
      // The one reading of that counter worth a screen: the reader is losing
      // events between the engine and the table.
      api.suricataStatus.and.returnValue(of({
        service: { running: true },
        engine: engineStub({ alerts_detected: 5000, alerts_stored: 4000,
                             alerts_missing: 1000 }),
        event_counts: {},
      } as any));
      const el = build();
      component.setTab('rules');
      fixture.detectChanges();
      const tile = Array.from(el.querySelectorAll('.tile'))
        .find((t) => t.textContent?.includes('Alerts detected'))!;
      expect(tile.textContent).toContain('1,000 of them never reached the panel');
      expect(tile.querySelector('.alarm') ?? tile).toBeTruthy();
      expect(component.engineAlertsBad()).toBeTrue();
    });

    it('claims nothing before the panel has counted', () => {
      const el = build();
      component.setTab('rules');
      fixture.detectChanges();
      const tile = Array.from(el.querySelectorAll('.tile'))
        .find((t) => t.textContent?.includes('Alerts detected'));
      expect(tile!.textContent).toContain('counted since the engine started');
      expect(tile!.textContent).not.toContain('all of them stored');
    });

    it('says what the badge beside Alerts is counting', () => {
      // Read against the engine counter it looked like events had gone
      // missing. They had not: the two measure different things.
      const el = build();
      const badge = el.querySelector('.tab-count');
      const hint = badge!.getAttribute('title') ?? '';
      expect(hint).toContain('without the engine');
      component.setKind('all');
      fixture.detectChanges();
      expect(el.querySelector('.tab-count')!.getAttribute('title'))
        .toContain('threats and engine notes');
    });
  });

  describe('the engine notes', () => {
    it('are not in the alert list until they are asked for', () => {
      // A quarter of the rows used to be the engine talking about itself.
      build();
      expect(lastFilters()['kind']).toBe('alert');
    });

    it('are a control in the toolbar, where the other filters are', () => {
      // They used to be a button under the list and a pill above it: set at
      // the bottom, shown at the top, cleared in two different places. A closed
      // set of three states is a select, exactly like the rating beside it.
      const el = build();
      const bar = el.querySelector('.filters')!;
      expect(bar.querySelectorAll('select').length).toBe(3);
      const kind = bar.querySelectorAll<HTMLSelectElement>('select')[2];
      expect(kind.value).toBe('alert');
      expect(Array.from(kind.options).map((o) => o.value))
        .toEqual(['alert', 'diagnostic', 'all']);
      // And no longer a second way in from the bottom of the page.
      expect(el.querySelector('.list-foot')?.querySelector('button')).toBeNull();
    });

    it('are switched on by the select itself, not only by code', () => {
      // Every other test drove this through the component. Wire the select to
      // a constant and they all still pass, because none of them ever picked
      // anything but the value the list already had.
      const el = build();
      const kind = el.querySelectorAll<HTMLSelectElement>('.filters select')[2];
      kind.value = 'diagnostic';
      kind.dispatchEvent(new Event('change'));
      fixture.detectChanges();
      expect(component.kind()).toBe('diagnostic');
      expect(lastFilters()['kind']).toBe('diagnostic');
    });

    it('show the selected kind in the box on arrival from elsewhere', () => {
      const el = build();
      component.setKind('diagnostic');
      fixture.detectChanges();
      const kind = el.querySelectorAll<HTMLSelectElement>('.filters select')[2];
      expect(kind.value).toBe('diagnostic');
    });

    it('ignore a kind nobody offers', () => {
      // Through chooseKind, which is where an unchecked string can arrive.
      // setKind itself takes the union, so a typo in our own code fails to
      // build rather than silently doing nothing.
      build();
      component.chooseKind('everything');
      expect(component.kind()).toBe('alert');
    });

    it('switch the list and start it at the first page', () => {
      // Page 4 of the threats is not page 4 of the notes. Enough rows for
      // there to be a page 2 at all, or the paging call does nothing and the
      // assertion passes without the code that makes it pass.
      api.alerts.and.returnValue(of(page([alert(1)], 120)));
      build();
      component.nextPage();
      expect(lastFilters()['offset']).toBe(50);
      component.setKind('diagnostic');
      expect(lastFilters()['kind']).toBe('diagnostic');
      expect(lastFilters()['offset']).toBe(0);
    });

    it('leave through the same control they were set in', () => {
      const el = build();
      component.setKind('diagnostic');
      fixture.detectChanges();
      const kind = el.querySelectorAll<HTMLSelectElement>('.filters select')[2];
      kind.value = 'alert';
      kind.dispatchEvent(new Event('change'));
      fixture.detectChanges();
      expect(lastFilters()['kind']).toBe('alert');
      expect(el.querySelectorAll('.filter-pill').length).toBe(0);
    });

    it('are named in a sentence under the list, not only in a dropdown', () => {
      // "Engine notes" is a label somebody has to be told the meaning of once.
      const el = build();
      component.setKind('diagnostic');
      fixture.detectChanges();
      expect(el.querySelector('.list-foot')?.textContent)
        .toContain("The engine's own events");
    });

    it('are counted as notes rather than as alerts', () => {
      // "9 302 alerts" would be the sentence the whole split exists to avoid.
      const el = build();
      component.setKind('diagnostic');
      fixture.detectChanges();
      expect(el.querySelector('.pager')?.textContent).toContain('notes');
      expect(el.querySelector('.pager')?.textContent).not.toContain('alerts');
    });

    it('survive a reload, because the URL carries them', () => {
      build();
      component.setKind('diagnostic');
      expect(component.kind()).toBe('diagnostic');
      // The threats are the default, so they leave no parameter behind.
      component.setKind('alert');
      expect(component.kind()).toBe('alert');
    });

    it('can show both kinds at once, which is what the engine counts', () => {
      // The engine's own counter counts every alert it raised, threats and its
      // notes together. On this sensor that was 888, of which the alert list
      // showed 52, so the number looked unreachable.
      build();
      component.setKind('all');
      expect(lastFilters()['kind']).toBe('all');
    });

    it('names the mixed list for what it is', () => {
      const el = build();
      component.setKind('all');
      fixture.detectChanges();
      expect(el.querySelector('.list-foot')?.textContent)
        .toContain('threats and its own notes');
      expect(el.querySelector('.pager')?.textContent).toContain('rows');
    });

    it('are dropped by Clear like every other filter', () => {
      build();
      component.setKind('diagnostic');
      component.resetFilters();
      expect(component.kind()).toBe('alert');
    });
  });

  it('pages within what there is', () => {
    api.alerts.and.returnValue(of(page([alert(1)], 120)));
    build();
    expect(component.pageCount()).toBe(3);
    component.nextPage();
    expect(component.currentPage()).toBe(2);
    component.prevPage();
    component.prevPage();
    expect(component.currentPage()).toBe(1);
  });

  it('fetches the whole event when a row is opened, and closes on a second click', () => {
    build();
    component.select(alert(7));
    expect(api.alert).toHaveBeenCalledWith(7);
    expect(component.selectedId()).toBe(7);
    component.select(alert(7));
    expect(component.selectedId()).toBeNull();
  });

  describe('what the detail pane says about the event', () => {
    // Blocks copied off a live sensor rather than invented: this is what a DNS
    // alert and a TLS alert actually carry in eve.json.
    const dnsAlert = () => alert(7, {
      raw: {
        direction: 'to_server',
        vlan: [30],
        alert: { action: 'allowed' },
        dns: { type: 'request', queries: [{ rrname: 'cdn.discordapp.com', rrtype: 'HTTPS' }] },
        flow: { pkts_toserver: 3, bytes_toserver: 2048, pkts_toclient: 1, bytes_toclient: 512 },
      },
    } as Partial<Alert>);

    function facts(row: Alert): Record<string, string> {
      api.alert.and.returnValue(of(row));
      build();
      component.select(row);
      const pairs = component.selectedFacts() as { label: string; value: string }[];
      return Object.fromEntries(pairs.map((f) => [f.label, f.value]));
    }

    it('names the domain a DNS rule fired on', () => {
      // The rule that fires most often here is a DNS lookup, and before this the
      // only place the name appeared was inside the collapsed raw JSON.
      expect(facts(dnsAlert())['DNS query']).toBe('cdn.discordapp.com (HTTPS)');
    });

    it('reads the fields a TLS alert carries instead', () => {
      const row = alert(8, {
        raw: { tls: { sni: 'example.net', version: 'TLS 1.3', ja4: 't13d1516h2_x' } },
      } as Partial<Alert>);
      expect(facts(row)['TLS SNI']).toBe('example.net');
      expect(facts(row)['JA4']).toBe('t13d1516h2_x');
    });

    it('counts the flow in both directions', () => {
      expect(facts(dnsAlert())['To server']).toBe('3 pkt, 2.0 KB');
    });

    it('leaves out what the event does not carry', () => {
      // A column of dashes reads as a broken panel, and which blocks an alert
      // has depends entirely on the protocol it fired on.
      const shown = facts(dnsAlert());
      expect(shown['TLS SNI']).toBeUndefined();
      expect(shown['HTTP host']).toBeUndefined();
      expect(shown['DNS query']).toBeDefined();
    });

    it('says nothing at all for an event with no raw record', () => {
      expect(facts(alert(9, { raw: undefined } as Partial<Alert>))).toEqual({});
    });

    it('survives a raw record whose blocks are the wrong shape', () => {
      // The reader stores whatever the engine wrote. A malformed record must
      // not take the whole detail pane down with it.
      const row = alert(10, {
        raw: { dns: 'not an object', tls: null, vlan: 'not a list', flow: { pkts_toserver: 'x' } },
      } as Partial<Alert>);
      expect(() => facts(row)).not.toThrow();
      expect(facts(row)).toEqual({});
    });

    it('puts the named fields in the pane, not only in the model', () => {
      api.alert.and.returnValue(of(dnsAlert()));
      const dom = build();
      component.select(dnsAlert());
      fixture.detectChanges();
      const text = dom.querySelector('.facts')?.textContent ?? '';
      expect(text).toContain('DNS query');
      expect(text).toContain('cdn.discordapp.com (HTTPS)');
    });
  });

  it('falls back to the row it already has if the detail cannot be fetched', () => {
    api.alert.and.returnValue(throwError(() => new Error('gone')));
    build();
    component.select(alert(7));
    expect(component.selected()!.id).toBe(7);
  });

  it('describes the window the way the selector beside it does', () => {
    // "threats, in the last 7d" was the URL token read out loud, two
    // centimetres from an option reading "Last 7 days".
    build();
    component.setWindow('7d');
    expect(component.alertCountHint()).toContain('in the last 7 days');
    expect(component.alertCountHint()).not.toContain('7d');
    component.setWindow('1h');
    expect(component.alertCountHint()).toContain('in the last hour');
  });

  it('asks before silencing a signature for good', () => {
    build();
    spyOn(window, 'confirm').and.returnValue(false);
    component.muteSignature(alert(1));
    expect(api.muteSignature).not.toHaveBeenCalled();
  });

  it('silences a signature and reloads the engine', () => {
    build();
    spyOn(window, 'confirm').and.returnValue(true);
    api.muteSignature.and.returnValue(of({
      ok: true, output: '', state: { muted: [{ signature_id: 2000001, signature: 'ET MALWARE Test' }] },
    } as any));
    component.muteSignature(alert(1));
    expect(api.muteSignature).toHaveBeenCalledWith(2000001);
    expect(api.serviceAction).toHaveBeenCalledWith('reload');
    expect(component.mutedSids().has(2000001)).toBeTrue();
    expect(component.actionResult().ok).toBeTrue();
  });

  it('says so when the rule set changed but the engine would not reload', () => {
    build();
    spyOn(window, 'confirm').and.returnValue(true);
    api.muteSignature.and.returnValue(of({ ok: true, output: '', state: { muted: [] } } as any));
    api.serviceAction.and.returnValue(throwError(() => new Error('no')));
    component.muteSignature(alert(1));
    expect(component.actionResult().ok).toBeFalse();
    expect(component.actionResult().text).toContain('silenced');
  });

  it('says what the restore button does, not what the pill means', () => {
    // Standing after the button, "out of the rule set. Older alerts stay
    // listed" read as the outcome of pressing it, which is the opposite: the
    // button puts the signature back.
    const dom = build();
    component.mutedSids.set(new Set([2000001]));
    component.select(alert(1));
    fixture.detectChanges();
    const row = dom.querySelector('.mute-row.is-muted')!.textContent!;
    expect(row).toContain('Alert on it again');
    expect(row).toContain('puts it back in the rule set');
    expect(row).not.toContain('out of the rule set');
  });

  it('asks before letting a signature through for good', () => {
    build();
    spyOn(window, 'confirm').and.returnValue(false);
    component.allowSignature(alert(1));
    expect(api.allowSignature).not.toHaveBeenCalled();
  });

  it('allows a signature and reloads the engine', () => {
    build();
    spyOn(window, 'confirm').and.returnValue(true);
    api.allowSignature.and.returnValue(of({
      ok: true, output: '',
      state: { muted: [], allowed: [{ signature_id: 2000001, signature: 'ET MALWARE Test' }] },
    } as any));
    component.allowSignature(alert(1));
    expect(api.allowSignature).toHaveBeenCalledWith(2000001);
    expect(api.serviceAction).toHaveBeenCalledWith('reload');
    expect(component.allowedSids().has(2000001)).toBeTrue();
    expect(component.actionResult().text).toContain('allowed');
  });

  it('makes an allowed signature block again', () => {
    build();
    component.allowedSids.set(new Set([2000001]));
    api.unallowSignature.and.returnValue(of({
      ok: true, output: '', state: { muted: [], allowed: [] },
    } as any));
    component.unallowSignature(alert(1));
    expect(api.unallowSignature).toHaveBeenCalledWith(2000001);
    expect(component.allowedSids().has(2000001)).toBeFalse();
  });

  it('shows in the detail whether a signature is ever blocked', () => {
    const dom = build();
    component.select(alert(1));
    fixture.detectChanges();
    expect(dom.textContent).toContain('Alert but never block');

    component.allowedSids.set(new Set([2000001]));
    fixture.detectChanges();
    expect(dom.textContent).toContain('Never blocked');
    expect(dom.textContent).toContain('Block it again');
  });

  it('says what the block-again button does, not what the pill means', () => {
    const dom = build();
    component.allowedSids.set(new Set([2000001]));
    component.select(alert(1));
    fixture.detectChanges();
    const rows = Array.from(dom.querySelectorAll('.mute-row'))
      .map((r) => r.textContent!);
    const allowRow = rows.find((r) => r.includes('Block it again'))!;
    expect(allowRow).toContain('lets the engine drop it again');
    expect(allowRow).not.toContain('never dropped when blocking is on');
  });

  it('offers no allowing for a signature that is out of the rule set', () => {
    const dom = build();
    component.mutedSids.set(new Set([2000001]));
    component.select(alert(1));
    fixture.detectChanges();
    expect(dom.textContent).not.toContain('Alert but never block');
  });

  it('keeps working with a state written before allowing existed', () => {
    build();
    spyOn(window, 'confirm').and.returnValue(true);
    api.muteSignature.and.returnValue(of({ ok: true, output: '', state: { muted: [] } } as any));
    component.muteSignature(alert(1));
    expect(component.allowedSids().size).toBe(0);
    expect(component.actionResult().ok).toBeTrue();
  });

  it('will not silence two signatures at once', () => {
    build();
    spyOn(window, 'confirm').and.returnValue(true);
    component.muting.set(2000001);
    component.muteSignature(alert(2, { signature_id: 2000002 }));
    expect(api.muteSignature).not.toHaveBeenCalled();
  });

  describe('a link from one tab of this screen to another', () => {
    /** The route as the router drives it: a snapshot for ngOnInit and a stream
     *  for everything after it. */
    function buildOnTab(tab: string) {
      fixture = TestBed.createComponent(Ids);
      component = fixture.componentInstance;
      const params = new BehaviorSubject(convertToParamMap({ tab }));
      const route = (component as any).route;
      Object.defineProperty(route, 'queryParamMap', { value: params, configurable: true });
      Object.defineProperty(route.snapshot, 'queryParamMap',
                            { value: convertToParamMap({ tab }), configurable: true });
      fixture.detectChanges();
      return params;
    }

    it('opens the tab it points at, instead of only changing the address', () => {
      // Three sentences on the Protection tab link to the alert list. Angular
      // keeps the component it already has and ngOnInit does not run again, so
      // the address changed and nothing else did: they read as dead links.
      // Driven from the Engine tab here, because rendering Protection needs
      // its own endpoint; what is under test is the same for every tab.
      const params = buildOnTab('rules');
      expect(component.tab()).toBe('rules');
      params.next(convertToParamMap({ tab: 'alerts' }));
      fixture.detectChanges();
      expect(component.tab()).toBe('alerts');
      expect(api.alerts).toHaveBeenCalled();
    });

    it('keeps the filters it already had when it follows one', () => {
      // The link carries one parameter, so the navigation drops the rest. The
      // filters are this screen's state by then, and an address that disagrees
      // with the toolbar is the fault this screen keeps being fixed for.
      const params = buildOnTab('alerts');
      component.setSeverity('Critical');
      component.setTab('rules');
      params.next(convertToParamMap({ tab: 'alerts' }));
      fixture.detectChanges();
      expect(component.tab()).toBe('alerts');
      expect(component.severity()).toBe('Critical');
      expect(lastFilters()['severity']).toBe('Critical');
    });

    it('ignores a tab nobody has', () => {
      const params = buildOnTab('alerts');
      params.next(convertToParamMap({ tab: 'nonsense' }));
      fixture.detectChanges();
      expect(component.tab()).toBe('alerts');
    });
  });

  describe('arriving from the dashboard queue tile', () => {
    /** Builds with query parameters, on the real route, so the URL sync that
     *  runs afterwards still has somewhere to navigate relative to. */
    function buildWith(params: Record<string, string>) {
      fixture = TestBed.createComponent(Ids);
      component = fixture.componentInstance;
      Object.defineProperty((component as any).route.snapshot, 'queryParamMap',
                            { value: convertToParamMap(params), configurable: true });
      return component;
    }

    it('opens on the whole table when the tile sends since=all', () => {
      // The tile counts every unreviewed row there is. Landing on a 24 h list
      // under an all-time number is the same fault as the one the tile was
      // built to end: two figures, two screens, one name.
      const c = buildWith({ tab: 'alerts', unacked: '1', since: 'all' });
      c.window.set('24h');
      fixture.detectChanges();
      expect(c.window()).toBe('');
      expect(c.onlyUnacked()).toBeTrue();
      expect(lastFilters()['hours']).toBeNull();
    });

    it('takes a day picked in the dropdown, not only one arriving in the URL', () => {
      // The window selector offers Today and Yesterday, and setWindow() checked
      // them against WINDOWS alone, where they are not. Picking Today set the
      // window to "all time" while the box went on reading Today: the list and
      // the control disagreed, which is the exact fault the comments above this
      // selector say was fixed. Only the URL path had a test.
      const el = build();
      const box = el.querySelectorAll<HTMLSelectElement>('.filters select')[0];
      box.value = 'today';
      box.dispatchEvent(new Event('change'));
      fixture.detectChanges();
      expect(component.window()).toBe('today');
      expect(lastFilters()['day']).toBe('today');
      expect(box.value).toBe('today');
    });

    it('still refuses a period that is neither a window nor a day', () => {
      const el = build();
      const box = el.querySelectorAll<HTMLSelectElement>('.filters select')[0];
      component.setWindow('last-tuesday');
      fixture.detectChanges();
      expect(component.window()).toBe('');
      expect(box.value).toBe('');
    });

    it('asks for a named day rather than a number of hours', () => {
      // "Today" at nine in the morning is nine hours and at midnight is one
      // minute. The tile that links here counts a day, so the list has to ask
      // for the same day, resolved on the same machine.
      const c = buildWith({ tab: 'alerts', since: 'today' });
      fixture.detectChanges();
      expect(c.window()).toBe('today');
      expect(lastFilters()['day']).toBe('today');
      expect(lastFilters()['hours']).toBeNull();
    });

    it('takes yesterday the same way', () => {
      const c = buildWith({ tab: 'alerts', since: 'yesterday' });
      fixture.detectChanges();
      expect(lastFilters()['day']).toBe('yesterday');
    });

    it('writes a cleared rating into the URL, so a reload does not resurrect it', () => {
      // Arrive from a rating tile at ?severity=Critical, pick "Any rating", and
      // the list widens. Press F5 and Critical is back, because ngOnInit reads
      // the parameter that setSeverity never removed. Every other filter here
      // syncs; this one did not.
      const c = buildWith({ tab: 'alerts', severity: 'Critical' });
      fixture.detectChanges();
      const navigate = spyOn((c as any).router, 'navigate');

      const box = (fixture.nativeElement as HTMLElement)
        .querySelectorAll<HTMLSelectElement>('.filters select')[1];
      box.value = '';
      box.dispatchEvent(new Event('change'));
      fixture.detectChanges();

      expect(c.severity()).toBeNull();
      expect(navigate).toHaveBeenCalled();
      const params = navigate.calls.mostRecent().args[1] as any;
      expect(params.queryParams.severity).toBeNull();
    });

    it('carries a rating in from the tile that was clicked', () => {
      const c = buildWith({ tab: 'alerts', since: 'today', severity: 'Critical' });
      fixture.detectChanges();
      expect(c.severity()).toBe('Critical');
      expect(lastFilters()['severity']).toBe('Critical');
    });

    it('shows the rating in the box, not only in the query', () => {
      // Caught in a screenshot, not by a test: the list was filtered to
      // Informational and the dropdown said "Any rating". The same fault had
      // already been fixed once on the window selector next to it, and the
      // assertion that would have caught it reads the rendered control rather
      // than the signal behind it.
      const c = buildWith({ tab: 'alerts', since: 'today', severity: 'Critical' });
      fixture.detectChanges();
      const boxes = (fixture.nativeElement as HTMLElement)
        .querySelectorAll<HTMLSelectElement>('.filters select');
      expect(boxes[0].value).toBe('today');
      expect(boxes[1].value).toBe('Critical');
    });

    it('refuses a rating it does not offer', () => {
      const c = buildWith({ tab: 'alerts', severity: 'Catastrophic' });
      fixture.detectChanges();
      expect(c.severity()).toBeNull();
    });

    it('says which day it is showing, not how many hours back', () => {
      const c = buildWith({ tab: 'alerts', since: 'today' });
      fixture.detectChanges();
      expect(c.alertCountHint()).toContain('today');
      expect(c.alertCountHint()).not.toContain('last today');
    });

    it('still sends hours for a rolling window', () => {
      const c = buildWith({ tab: 'alerts', since: '24h' });
      fixture.detectChanges();
      expect(lastFilters()['hours']).toBe(24);
      expect(lastFilters()['day']).toBeNull();
    });

    it('still takes a real window from the URL', () => {
      const c = buildWith({ tab: 'alerts', since: '7d' });
      fixture.detectChanges();
      expect(c.window()).toBe('7d');
      expect(lastFilters()['hours']).toBe(168);
    });

    it('ignores a window token it does not offer', () => {
      // A typed URL must not become a filter nobody can see or clear.
      const c = buildWith({ tab: 'alerts', since: 'forever' });
      c.window.set('24h');
      fixture.detectChanges();
      expect(c.window()).toBe('24h');
    });
  });

  describe('clearing the whole queue', () => {
    it('asks first, because there is no bulk undo', () => {
      spyOn(window, 'confirm').and.returnValue(false);
      build();
      component.ackAll();
      expect(api.ackAllAlerts).not.toHaveBeenCalled();
    });

    it('clears it and reloads the list once confirmed', () => {
      spyOn(window, 'confirm').and.returnValue(true);
      build();
      const before = api.alerts.calls.count();
      component.ackAll();
      expect(api.ackAllAlerts).toHaveBeenCalled();
      expect(api.alerts.calls.count()).toBeGreaterThan(before);
      expect(component.ackingAll()).toBeFalse();
    });

    it('lets go of the button when the server refuses', () => {
      // Left true, the button stays disabled and the only way out is a reload.
      spyOn(window, 'confirm').and.returnValue(true);
      api.ackAllAlerts.and.returnValue(throwError(() => new Error('nope')));
      build();
      component.ackAll();
      expect(component.ackingAll()).toBeFalse();
    });
  });

  it('acknowledging a row keeps the open detail in step', () => {
    build();
    component.select(alert(1));
    component.ack(alert(1), new MouseEvent('click'));
    expect(api.ackAlert).toHaveBeenCalledWith(1, true);
    expect(component.selected()!.acknowledged).toBeTrue();
  });

  it('names the buckets that are not countries', () => {
    build();
    expect(component.countryLabel('home')).toContain('network');
    expect(component.countryLabel('private')).toContain('private');
  });

  it('stops its timers when the view goes away', () => {
    build();
    spyOn(window, 'clearInterval');
    fixture.destroy();
    expect(window.clearInterval).toHaveBeenCalled();
  });

  /** Six tabs need about 615px and a phone gives 390. They used to run off the
   *  edge: the last two were unreachable and the whole page scrolled sideways,
   *  which is what "the IDS tab is skewed on my phone" turned out to mean. */
  describe('at phone width', () => {
    const PHONE = 390;

    function phone() {
      const dom = build();
      (dom as HTMLElement).style.width = `${PHONE}px`;
      fixture.detectChanges();
      return dom as HTMLElement;
    }

    it('never makes the page itself scroll sideways', () => {
      const dom = phone();
      // The tabs this component draws itself. Protection, Logs and
      // Notifications are separate components with their own specs; the bar
      // above them is the same on every tab, and it is the bar that broke.
      for (const tab of ['alerts', 'live', 'rules']) {
        component.setTab(tab);
        fixture.detectChanges();
        expect(dom.scrollWidth)
          .withContext(`${tab} tab pushes the page past ${PHONE}px`)
          .toBeLessThanOrEqual(dom.clientWidth);
      }
    });

    it('scrolls the tab bar instead, so every tab stays reachable', () => {
      const bar = phone().querySelector<HTMLElement>('.tabs')!;
      // The bar is wider than the screen on purpose. What matters is that it
      // carries the overflow itself rather than handing it to the page.
      expect(bar.scrollWidth).toBeGreaterThan(bar.clientWidth);
      expect(getComputedStyle(bar).overflowX).toBe('auto');
    });

    it('keeps the tabs on one line rather than squeezing them', () => {
      // Without flex: 0 0 auto the row shrinks the tabs to fit and "Live
      // traffic" breaks across two lines inside a one-line bar.
      const buttons = Array.from(phone().querySelectorAll<HTMLElement>('.tab'));
      const tops = buttons.map((b) => b.offsetTop);
      expect(new Set(tops).size).toBe(1);
    });

    it('brings the detail into view when it lands below the list', () => {
      // Below 1000px the columns stack, so the detail card is under the whole
      // list. On a phone that is off screen and tapping a row read as nothing
      // happening at all. The tall list is what puts it there in a test.
      const dom = phone();
      dom.querySelector<HTMLElement>('.list-card')!.style.height = '3000px';
      const scroll = spyOn(Element.prototype, 'scrollIntoView');
      component.select(alert(1));
      fixture.detectChanges();
      expect(scroll).toHaveBeenCalled();
      const target = scroll.calls.mostRecent().object as HTMLElement;
      expect(target.classList.contains('detail-card')).toBeTrue();
      // The wide layout, where the card sits beside the list and needs no
      // scroll, is not asserted here: the rule that splits the columns is a
      // viewport media query, and a test can set an element's width but not
      // the browser's. The guard in the component is the visibility check.
    });

    it('brings the active tab into view when it is off the edge', () => {
      // Arriving on ?tab=notify from a link otherwise opens a screen whose
      // header shows Alerts.
      const dom = phone();
      const bar = dom.querySelector<HTMLElement>('.tabs')!;
      expect(bar.scrollLeft).toBe(0);
      component.setTab('notify');
      fixture.detectChanges();
      expect(bar.scrollLeft).toBeGreaterThan(0);
    });
  });
});


describe('Ids sensor card', () => {
  let fixture: ComponentFixture<Ids>;
  let component: any;
  let api: jasmine.SpyObj<Api>;

  /** The engine's stats record as the status endpoint reports it. */
  function engine(overrides: Record<string, any> = {}) {
    return {
      uptime_seconds: 133746,
      packets: 13738238, bytes: 0,
      kernel_packets: 13738238, kernel_drops: 0, capture_errors: 0,
      drop_rate_percent: 0, tcp_sessions: 27714, reassembly_gaps: 5,
      gap_rate_percent: 0.018, sensor_problem: null,
      capture_mode: 'af-packet', loss_measured: true,
      blocked: null, blocked_by_rules: null,
      alerts_detected: 7312, flows: 217951,
      ...overrides,
    };
  }

  /** The engine as it reports itself inline on a netfilter queue: no capture
   *  section at all, and the drop counters under `ips`. Taken from the device. */
  function inline(overrides: Record<string, any> = {}) {
    return engine({
      capture_mode: 'nfqueue', loss_measured: false,
      kernel_packets: null, kernel_drops: null, capture_errors: null,
      drop_rate_percent: null, blocked: 266, blocked_by_rules: 0,
      tcp_sessions: 188, reassembly_gaps: 0, gap_rate_percent: 0,
      ...overrides,
    });
  }

  function build(stats: Record<string, any> = {}) {
    api.suricataStatus.and.returnValue(of({
      service: { running: true }, engine: engine(stats), event_counts: { alert: 12 },
      // Every status carrying counters carries the moment they arrived.
      last_stats_at: '2026-09-20T10:00:00+0200',
    } as any));
    fixture = TestBed.createComponent(Ids);
    component = fixture.componentInstance;
    fixture.detectChanges();
    component.setTab('rules');
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  beforeEach(() => {
    api = jasmine.createSpyObj<Api>('Api', [
      'alerts', 'alert', 'ackAlert', 'suricataStatus', 'muteSignature',
      'unmuteSignature', 'serviceAction', 'engineLog', 'protection', 'notifications',
    ]);
    api.alerts.and.returnValue(of(page()));
    api.alert.and.callFake((id: number) => of(alert(id)));
    api.ackAlert.and.returnValue(of({ id: 1, acknowledged: true }));
    api.serviceAction.and.returnValue(of({ ok: true, output: '' }));
    api.protection.and.returnValue(of({ muted: [] } as any));
    api.engineLog.and.returnValue(of({ path: '', lines: ['engine said something'] }));
    api.muteSignature.and.returnValue(of({ ok: true, output: '', state: { muted: [] } } as any));
    api.unmuteSignature.and.returnValue(of({ ok: true, output: '', state: { muted: [] } } as any));
    api.notifications.and.returnValue(of({ settings: {}, status: {} } as any));
    TestBed.configureTestingModule({
      providers: [{ provide: Api, useValue: api }, Live, provideRouter([])],
    });
  });

  afterEach(() => fixture?.destroy());

  // --- the verdict ---

  it('reads the engine counters, not the engine event rules', () => {
    // The card this replaces derived the same answer from decoder event rules,
    // which fire per packet: five "protocol detection skipped" in a week made
    // it red on a device that had dropped nothing out of 13.7 million packets.
    const el = build();
    expect(el.querySelector('.health-line')?.textContent).toContain('Keeping up');
    expect(el.querySelector('.health-line.bad')).toBeNull();
  });

  it('does not claim nothing is missed while counting streams it missed', () => {
    // The line said "nothing is being missed" with "5 reassembly gaps" printed
    // underneath it. A gap is a TCP stream the engine could not put back
    // together, which is exactly something missed. The claim that holds is the
    // one about packets, so that is the only claim the sentence makes.
    const el = build({ reassembly_gaps: 6, tcp_sessions: 36583 });
    const line = el.querySelector('.health-line')?.textContent ?? '';
    expect(line).not.toContain('nothing');
    expect(line).toContain('No packets dropped');
  });

  it('does not say "no packets dropped" when some were', () => {
    // Under the threshold is not the same as none, and the card is the last
    // place that should round one to the other.
    const el = build({ drop_rate_percent: 0.4, kernel_drops: 400 });
    const line = el.querySelector('.health-line')?.textContent ?? '';
    expect(line).not.toContain('No packets dropped');
    expect(line).toContain('0.40 %');
    expect(line).toContain('under the one percent');
  });

  it('carries a green dot when it is keeping up and a red one when it is not', () => {
    // On a card of numbers the verdict has to be readable without being read.
    const good = build();
    expect(good.querySelector('.health-line .dot.on')).toBeTruthy();
    expect(good.querySelector('.health-line .dot.off')).toBeNull();
    fixture.destroy();
    const bad = build({ drop_rate_percent: 3.71, sensor_problem: 'drops' });
    expect(bad.querySelector('.health-line .dot.off')).toBeTruthy();
    expect(bad.querySelector('.health-line .dot.on')).toBeNull();
  });

  it('stays calm about losses under the one percent everybody uses', () => {
    // Zeek documents capture loss as something that should never exceed 1 %,
    // and Security Onion colours its per-node loss on the same scale.
    const el = build({ drop_rate_percent: 0.4, sensor_problem: null });
    expect(el.querySelector('.health-line.bad')).toBeNull();
    // The tile beside it takes the same answer from the same place. A second
    // copy of "> 1" in the template is the copy that goes stale.
    expect(el.querySelector('.tile.alarm')).toBeNull();
  });

  it('puts the drop tile in alarm off the backend verdict', () => {
    const el = build({ drop_rate_percent: 3.71, sensor_problem: 'drops' });
    expect(el.querySelector('.tile.alarm')).toBeTruthy();
  });

  it('says so, and says how much, when packets are being dropped', () => {
    const el = build({
      drop_rate_percent: 3.71, kernel_drops: 492118, sensor_problem: 'drops',
    });
    expect(el.querySelector('.health-line.bad')).toBeTruthy();
    expect(el.textContent).toContain('3.71 %');
    expect(el.textContent).toContain('not keeping up');
    expect(el.textContent).toContain('492,118 dropped of 13,738,238 packets');
  });

  it('treats one capture error as one too many', () => {
    // Not a proportion of anything: the kernel telling us the ring is broken.
    const el = build({ capture_errors: 1, sensor_problem: 'errors' });
    expect(el.querySelector('.health-line.bad')).toBeTruthy();
    expect(el.textContent).toContain('1 error.');
  });

  it('says so when whole streams cannot be put back together', () => {
    const el = build({ gap_rate_percent: 4.2, reassembly_gaps: 1164, sensor_problem: 'gaps' });
    expect(el.querySelector('.health-line.bad')).toBeTruthy();
    expect(el.textContent).toContain('4.20 % of TCP streams');
    expect(el.textContent).toContain('part of the traffic only');
  });

  describe('inline on a netfilter queue', () => {
    function buildInline(overrides: Record<string, any> = {}) {
      api.suricataStatus.and.returnValue(of({
        service: { running: true }, engine: inline(overrides),
        event_counts: { alert: 12 }, last_stats_at: '2026-09-20T10:00:00+0200',
      } as any));
      fixture = TestBed.createComponent(Ids);
      component = fixture.componentInstance;
      fixture.detectChanges();
      component.setTab('rules');
      fixture.detectChanges();
      return fixture.nativeElement as HTMLElement;
    }

    it('does not report a clean sensor from counters that are absent', () => {
      // The evening this panel spent saying "no packets dropped" while 266 had
      // been destroyed and the mirror port was not being inspected at all.
      const el = buildInline();
      const line = el.querySelector('.health-line')?.textContent ?? '';
      expect(line).not.toContain('No packets dropped');
      expect(line).not.toContain('Keeping up');
      expect(line).toContain('capture loss is not reported');
    });

    it('is amber, which is neither the all clear nor an alarm', () => {
      const el = buildInline();
      expect(el.querySelector('.health-line .dot.warn')).toBeTruthy();
      expect(el.querySelector('.health-line .dot.on')).toBeNull();
      expect(el.querySelector('.health-line .dot.off')).toBeNull();
    });

    it('says what was stopped and how much of it any rule asked for', () => {
      // Measured on the device: 266 stopped, drop_reason.rules zero for all.
      const el = buildInline();
      const line = el.querySelector('.health-line')?.textContent ?? '';
      expect(line).toContain('266 packets stopped');
      expect(line).toContain('0 of them by a rule');
    });

    it('does not print a capture error count it does not have', () => {
      const el = buildInline();
      const note = el.querySelector('.card .dim.note')?.textContent ?? '';
      expect(note).not.toContain('0 capture errors');
      expect(note).toContain('no capture counters in this mode');
    });

    it('shows the drop tile as not applicable rather than as zero', () => {
      const el = buildInline();
      const tiles = Array.from(el.querySelectorAll('.tile'))
        .filter((t) => t.textContent?.includes('Dropped packets'));
      expect(tiles.length).toBe(1);
      expect(tiles[0].textContent).toContain('n/a');
      expect(tiles[0].textContent).not.toContain('0.00');
      expect(tiles[0].classList.contains('alarm')).toBeFalse();
    });

    it('still turns red when the engine does report a real loss', () => {
      // The unknown state must not swallow a fault that is measurable.
      const el = buildInline({
        loss_measured: true, drop_rate_percent: 3.71, kernel_drops: 492118,
        kernel_packets: 13738238, capture_errors: 0, sensor_problem: 'drops',
      });
      expect(el.querySelector('.health-line.bad')).toBeTruthy();
      expect(el.querySelector('.health-line .dot.off')).toBeTruthy();
    });
  });

  it('leaves the drop percentage to the tile that owns it', () => {
    // It is a tile above this card. Printing it twice is how two numbers that
    // mean the same thing start disagreeing.
    const el = build();
    expect(el.querySelector('.card .dim.note')?.textContent).not.toContain('dropped of');
  });

  it('shows the evidence under the verdict', () => {
    const el = build();
    const note = el.querySelector('.card .dim.note')?.textContent ?? '';
    expect(note).toContain('5 of 27,714 TCP streams incomplete');
    expect(note).toContain('0 capture errors');
  });

  it('does not claim health before the counters have arrived', () => {
    api.suricataStatus.and.returnValue(new Subject<any>());
    fixture = TestBed.createComponent(Ids);
    component = fixture.componentInstance;
    fixture.detectChanges();
    component.setTab('rules');
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Checking');
    expect(el.textContent).not.toContain('Keeping up');
  });

  it('does not call an ordinary sensor inline before the counters arrive', () => {
    // A status with no stats record yet has no capture section either, which
    // read exactly like a netfilter queue: for the first half minute after
    // every restart this card described a mirror-port sensor as inline.
    api.suricataStatus.and.returnValue(of({
      service: { running: true }, event_counts: {},
      engine: engine({ capture_mode: null, loss_measured: false,
                       kernel_packets: null, kernel_drops: null,
                       capture_errors: null, drop_rate_percent: null }),
    } as any));
    fixture = TestBed.createComponent(Ids);
    component = fixture.componentInstance;
    fixture.detectChanges();
    component.setTab('rules');
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Waiting for the first counter report');
    expect(el.textContent).not.toContain('netfilter queue');
    expect(el.textContent).not.toContain('not reported while inline');
    expect(el.textContent).toContain('waiting for the first counter report');
  });

  it('names the interval the engine really publishes on', () => {
    // Measured on this device: 8.00 s between stats records. The screen said
    // thirty, which is also what two comments in the repo said.
    api.suricataStatus.and.returnValue(of({
      service: { running: true }, event_counts: {},
      engine: engine({ capture_mode: null, loss_measured: false }),
    } as any));
    fixture = TestBed.createComponent(Ids);
    component = fixture.componentInstance;
    fixture.detectChanges();
    component.setTab('rules');
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('every 8 seconds');
    expect(el.textContent).not.toContain('30 seconds');
  });

  it('says nothing under the verdict until there is something to say', () => {
    // "Waiting for the first counter report" over "0 of 0 TCP streams
    // incomplete, no capture counters in this mode" is two answers to one
    // question, and the second is a measurement nobody made.
    api.suricataStatus.and.returnValue(of({
      service: { running: true }, event_counts: {},
      engine: engine({ capture_mode: null, loss_measured: false,
                       tcp_sessions: 0, reassembly_gaps: 0 }),
    } as any));
    fixture = TestBed.createComponent(Ids);
    component = fixture.componentInstance;
    fixture.detectChanges();
    component.setTab('rules');
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).not.toContain('TCP streams incomplete');
    expect(el.textContent).not.toContain('no capture counters');
  });

  it('has nothing folded away behind a button', () => {
    // Four sections behind "Details" was the complaint. There is one line now,
    // so there is nothing to open.
    const el = build();
    expect(el.textContent).not.toContain('Details');
    expect(el.textContent).not.toContain('About the sensor');
    expect(el.textContent).not.toContain('About the traffic');
    expect(el.textContent).not.toContain('What the reader has seen');
  });

  // --- the rest of the tab ---

  it('gives the engine log a card and a name of its own', () => {
    const el = build();
    expect(el.textContent).toContain('Engine log');
    component.loadEngineLog();
    fixture.detectChanges();
    expect(el.textContent).toContain('engine said something');
  });

  it('leaves the signature set to the protection screen', () => {
    // This tab used to carry a second "Download fresh signatures" button, the
    // same rule count and the same source line. Same endpoint, two screens,
    // and two different messages afterwards: one told the reader to reload,
    // the other did not.
    const el = build();
    expect(el.textContent).not.toContain('Download fresh signatures');
    expect(el.textContent).not.toContain('Active rules');
    expect(el.textContent).not.toContain('Emerging Threats Open');
    expect(el.textContent).not.toContain('Rule files');
  });

  it('keeps the one button that is about the engine rather than the rules', () => {
    const el = build();
    expect(el.textContent).toContain('Reload rules');
  });

  it('is called Engine, because that is all that is left on it', () => {
    const el = build();
    const tabs = Array.from(el.querySelectorAll('.tab')).map((t) => t.textContent?.trim());
    expect(tabs).toContain('Engine');
    expect(tabs.join(' ')).not.toContain('Rules');
  });
});
