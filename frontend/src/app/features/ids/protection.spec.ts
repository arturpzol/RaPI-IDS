import { provideRouter } from '@angular/router';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Subject, of, throwError } from 'rxjs';

import { Api } from '../../core/api';
import { formatDateTime } from '../../core/format';
import { Live } from '../../core/live';
import { Protection } from '../../core/models';
import { ProtectionView } from './protection';

function category(id: string, enabled = true, locked = false, informational = 0,
                  signatures = 100, alert_only = false) {
  return {
    id, name: id, description: '', enabled, locked,
    signatures, active_signatures: enabled ? signatures : 0, informational, alert_only,
  };
}

function protection(overrides: Partial<Protection> = {}): Protection {
  return {
    signatures: { total: 68411, active: 52464 },
    updated_at: 1788381900,
    built_at: 1788381900,
    fetched_at: 1788399072,
    source: 'Emerging Threats Open',
    applied: true,
    applied_at: '2026-08-22T08:05:00+00:00',
    mode: {
      id: 'ids', label: 'Detection', can_block: false, reason: 'listens to a copy',
      can_switch: true, drop_rules: 0, drop_pending: 0, inline: false,
      blocking_possible: true, blocking_unavailable: '',
      interfaces: ['eth0'], capture: 'af-packet',
    },
    categories: [category('malware'), category('info'), category('other', true, true)],
    informational: { enabled: true, signatures: 15023, active_signatures: 15023 },
    muted: [{ signature_id: 2013504, signature: 'ET INFO GNU/Linux APT User-Agent' }],
    allowed: [],
    ...overrides,
  } as Protection;
}

describe('ProtectionView', () => {
  let fixture: ComponentFixture<ProtectionView>;
  let component: any;
  let api: jasmine.SpyObj<Api>;

  function build(state = protection(), running = true) {
    api.protection.and.returnValue(of(state));
    fixture = TestBed.createComponent(ProtectionView);
    fixture.componentRef.setInput('running', running);
    component = fixture.componentInstance;
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  beforeEach(() => {
    api = jasmine.createSpyObj<Api>('Api', [
      'protection', 'setProtectionCategories', 'unmuteSignature', 'updateRules',
      'serviceAction', 'setProtectionMode', 'unallowSignature', 'rebuildProtection',
    ]);
    api.serviceAction.and.returnValue(of({ ok: true, output: '' }));
    TestBed.configureTestingModule({
      providers: [{ provide: Api, useValue: api }, Live, provideRouter([])],
    });
  });

  describe('the age of the signature set', () => {
    it('dates the set by the vendor, not by the last local rebuild', () => {
      // The two used to be one number, taken from the mtime of the merged rule
      // file. That file is rewritten by every category switch, so silencing one
      // signature made a month old set read as today's.
      const host = build(protection({ built_at: 1788381900, updated_at: 1788500000 }));
      const meta = host.querySelector('.sig-meta')?.textContent ?? '';
      expect(meta).toContain(formatDateTime(1788381900));
      expect(meta).not.toContain(formatDateTime(1788500000));
    });

    it('shows when this device last downloaded it', () => {
      // A set built yesterday and last fetched in June is a daily timer that
      // has quietly stopped, and nothing else on the screen would say so.
      const host = build();
      const meta = host.querySelector('.sig-meta')?.textContent ?? '';
      expect(meta).toContain(formatDateTime(1788399072));
    });

    it('falls back to the rebuild date when the vendor date is unknown', () => {
      // No archive in the cache yet, or the helper is not installed. Better a
      // date that is honest about being a rebuild than a blank line.
      const host = build(protection({ built_at: null, fetched_at: null }));
      const meta = host.querySelector('.sig-meta')?.textContent ?? '';
      expect(meta).toContain('Rebuilt');
      expect(meta).toContain(formatDateTime(1788381900));
    });
  });

  describe('the informational rating', () => {
    it('is a row of its own, counted apart from the categories', () => {
      // It comes from the rule set's rating of itself, not from the rule name,
      // so a signature can be in a category and informational at once. Adding
      // its count to the ones above would count those rules twice.
      const host = build();
      const row = host.querySelector('.cat-rating');
      expect(row?.textContent).toContain('15,023');
      expect(host.querySelectorAll('.cat-rating').length).toBe(1);
    });

    it('counts as a pending change like any switch on this screen', () => {
      build();
      expect(component.pendingCount()).toBe(0);
      component.toggleInformational();
      expect(component.pendingCount()).toBe(1);
    });

    it('is saved by the same button, in the same rebuild as the categories', () => {
      // Two calls would be two rebuilds of 68 556 rules for one visit here, and
      // a window in between where the rule file matches neither half.
      api.setProtectionCategories.and.returnValue(
        of({ ok: true, output: '', state: protection() }),
      );
      build();
      component.toggle({ id: 'malware', locked: false } as any);
      component.toggleInformational();
      component.save();
      expect(api.setProtectionCategories).toHaveBeenCalledTimes(1);
      const [selection, informational] = api.setProtectionCategories.calls.mostRecent().args;
      expect(selection['malware']).toBe(false);
      expect(informational).toBe(false);
    });

    it('follows the state the device sends back', () => {
      const off = protection({
        informational: { enabled: false, signatures: 15023, active_signatures: 0 },
      });
      build(off);
      expect(component.informational()).toBe(false);
      expect(component.pendingCount()).toBe(0);
    });

    it('says which categories it would empty', () => {
      // The cut is nowhere near uniform. Measured on the shipped set: 6 188 of
      // the 6 720 rules in the reputation category are rated informational
      // (almost all of them ET DYN_DNS), against 133 of 23 895 in malware. A
      // switch that quietly drops a category from 6 676 to 517, while the
      // operator is looking at a screen that says the category is on, is the
      // exact failure this panel exists to avoid.
      const host = build(protection({
        categories: [category('botnet', true, false, 92), category('malware'),
                     category('other', true, true)],
      }));
      const cost = host.querySelector('.cat-cost')?.textContent ?? '';
      expect(cost).toContain('botnet');
      expect(cost).not.toContain('malware');
    });

    it('names them without numbers', () => {
      // Three percentages for one fact, that these categories go mostly
      // quiet. The owner's verdict: the numbers say nothing.
      const host = build(protection({
        categories: [category('Peer to peer and dark web', true, false, 1284, 1336),
                     category('Botnets and threat intelligence', true, false, 6188, 6742)],
      }));
      const cost = host.querySelector('.cat-cost')?.textContent ?? '';
      expect(cost).not.toMatch(/\d/);
      expect(cost).not.toContain('%');
    });

    it('does not run two category names together', () => {
      // The names carry commas and an "and" of their own, so only a semicolon
      // shows where one ends: "advisory, hunting and current events".
      const host = build(protection({
        categories: [category('Peer to peer and dark web', true, false, 1284, 1336),
                     category('Botnets and threat intelligence', true, false, 6188, 6742)],
      }));
      const cost = (host.querySelector('.cat-cost')?.textContent ?? '').replace(/\s+/g, ' ');
      expect(cost).toContain('peer to peer and dark web; botnets and threat intelligence.');
    });

    it('does not list a category the rating leaves alone', () => {
      const host = build(protection({
        categories: [
          category('Botnets and threat intelligence', true, false, 6188, 6742),
          category('Viruses, malware and spyware', true, false, 133, 32756),
          category('Hacking and exploits', true, false, 120, 17052),
        ],
      }));
      const cost = (host.querySelector('.cat-cost')?.textContent ?? '').toLowerCase();
      expect(cost).toContain('botnets and threat intelligence');
      expect(cost).not.toContain('spyware');
      expect(cost).not.toContain('exploits');
    });

    it('says nothing when no category would lose much', () => {
      const host = build(protection({
        categories: [category('malware'), category('exploit')],
      }));
      expect(host.querySelector('.cat-cost')).toBeNull();
    });

    it('puts the worst hit category first', () => {
      const host = build(protection({
        categories: [category('protocol', true, false, 50),
                     category('p2p', true, false, 96),
                     category('botnet', true, false, 92)],
      }));
      const cost = host.querySelector('.cat-cost')?.textContent ?? '';
      expect(cost.indexOf('p2p')).toBeLessThan(cost.indexOf('botnet'));
      expect(cost.indexOf('botnet')).toBeLessThan(cost.indexOf('protocol'));
    });

    it('names the narrower tool next to the wide one', () => {
      // Measured shape of the problem: seven signatures made 95 % of every
      // alert on this network, and this switch drops fourteen thousand rules
      // to deal with them. Somebody about to reach for the wide one should be
      // told the narrow one exists, here, not on another screen.
      const host = build();
      const alt = host.querySelector('.cat-alt')?.textContent ?? '';
      expect(alt).toContain('alert list');
      expect(host.querySelector('.cat-alt a')?.getAttribute('href')).toContain('/ids');
    });

    it('does not move while a rebuild is running', () => {
      build();
      component.busy.set('save');
      component.toggleInformational();
      expect(component.informational()).toBe(true);
    });
  });

  // --- the switch between watching and blocking --------------------------

  it('offers the mode as a control where the panel can carry it out', () => {
    const dom = build();
    const buttons = Array.from(dom.querySelectorAll<HTMLButtonElement>('button.mode-opt'));
    expect(buttons.map((b) => b.textContent!.trim()))
      .toEqual(['Detection', 'Detection and blocking']);
  });

  it('calls the list of interfaces what it is', () => {
    // It lists capture interfaces; "Monitored networks" read as address ranges.
    const titles = Array.from(build().querySelectorAll('.card-title')).map((t) => t.textContent);
    expect(titles).toContain('Capture interfaces');
    expect(titles).not.toContain('Monitored networks');
  });

  it('states the mode without a control where it could not carry it out', () => {
    // A device without the helper installed. The two words stay on screen as a
    // statement of what the engine is doing, which is what they were before.
    const dom = build(protection({ mode: { ...protection().mode, can_switch: false } }));
    expect(dom.querySelectorAll('button.mode-opt').length).toBe(0);
    expect(dom.textContent).toContain('Detection and blocking');
  });

  describe('on a mirror port', () => {
    const why = 'A mirror port hands this Pi a copy of the traffic.';

    it('does not offer blocking, and says why on the button', () => {
      // The queue would stop the engine reading the mirror port: the network
      // goes uninspected while the screen says blocking.
      const dom = build(protection({ mode: { ...protection().mode,
        blocking_possible: false, blocking_unavailable: why } }));
      const [detection, blocking] =
        Array.from(dom.querySelectorAll<HTMLButtonElement>('button.mode-opt'));
      expect(blocking.disabled).toBeTrue();
      expect(blocking.title).toBe(why);
      expect(detection.disabled).toBeFalse();
    });

    it('still lets a device that is already blocking go back', () => {
      // Switched before the refusal existed: Detection must stay reachable,
      // and the active option is not greyed out as if it were not the state.
      const dom = build(protection({ mode: { ...protection().mode, id: 'ips',
        blocking_possible: false, blocking_unavailable: why } }));
      const [detection, blocking] =
        Array.from(dom.querySelectorAll<HTMLButtonElement>('button.mode-opt'));
      expect(detection.disabled).toBeFalse();
      expect(blocking.disabled).toBeFalse();
    });
  });

  it('asks the backend to switch, and only when it would change something', () => {
    api.setProtectionMode.and.returnValue(of({ ok: true, output: '' }));
    spyOn(window, 'confirm').and.returnValue(true);
    const dom = build();
    const [detection, blocking] =
      Array.from(dom.querySelectorAll<HTMLButtonElement>('button.mode-opt'));

    // Already in detection, so this is a click with nothing behind it.
    detection.click();
    expect(api.setProtectionMode).not.toHaveBeenCalled();

    blocking.click();
    expect(api.setProtectionMode).toHaveBeenCalledWith(true);
  });

  /** A panel upgraded from before the blocking policy: blocking on, every
   *  category enabled, and a rule set with the vendor's one drop rule. The
   *  drop count is not zero, so only the pending count can say it. */
  it('says so when blocking is on and the rule set still has the rules as alerts', () => {
    const dom = build(protection({
      mode: { ...protection().mode, id: 'ips', can_block: true,
              drop_rules: 1, drop_pending: 45262 },
    }));
    const warn = dom.querySelector('.mode-warn')!;
    expect(warn.textContent).toContain('45,262 signatures');
    expect(warn.textContent!.replace(/\s+/g, ' ')).toContain('do not follow the enabled categories');
  });

  it('rebuilds from the warning and reloads the engine', () => {
    const dom = build(protection({
      mode: { ...protection().mode, id: 'ips', can_block: true,
              drop_rules: 1, drop_pending: 10 },
    }));
    api.rebuildProtection.and.returnValue(of({ ok: true, output: '', state: protection() }));
    (dom.querySelector('.mode-warn button') as HTMLButtonElement).click();
    expect(api.rebuildProtection).toHaveBeenCalled();
    expect(api.serviceAction).toHaveBeenCalledWith('reload');
    expect(component.message().text).toContain('Rebuilt');
  });

  it('says nothing of the sort once the rule set follows the categories', () => {
    const dom = build(protection({
      mode: { ...protection().mode, id: 'ips', can_block: true,
              drop_rules: 45263, drop_pending: 0 },
    }));
    expect(dom.querySelector('.mode-warn')).toBeNull();
  });

  it('does not ask for a rebuild while only detecting', () => {
    // Alerts and drops behave the same on an engine reading a copy.
    const dom = build(protection({
      mode: { ...protection().mode, drop_rules: 1, drop_pending: 45262 },
    }));
    expect(dom.querySelector('.mode-warn')).toBeNull();
  });

  it('marks the categories that alert and never block', () => {
    const dom = build(protection({
      categories: [category('malware'), category('info', true, false, 0, 100, true)],
    }));
    const rows = Array.from(dom.querySelectorAll('.cat'));
    const pills = rows.map((r) => !!r.querySelector('.pill-alert-only'));
    expect(pills.slice(0, 2)).toEqual([false, true]);
  });

  it('explains allowing before anything has been allowed', () => {
    const dom = build();
    const cards = Array.from(dom.querySelectorAll('.card'))
      .filter((c) => c.textContent?.includes('Allowed signatures'));
    expect(cards.length).toBe(1);
    expect(cards[0].textContent).toContain('never blocked');
    expect(cards[0].textContent).toContain('Nothing is allowed');
  });

  it('lists the allowed signatures and can make one block again', () => {
    const entry = { signature_id: 2013031, signature: 'ET REMOTE_ACCESS AnyDesk' };
    const dom = build(protection({ allowed: [entry] }));
    expect(dom.textContent).toContain('ET REMOTE_ACCESS AnyDesk');
    api.unallowSignature.and.returnValue(of({ ok: true, output: '', state: protection() }));
    component.unallow(entry);
    expect(api.unallowSignature).toHaveBeenCalledWith(2013031);
    expect(api.serviceAction).toHaveBeenCalledWith('reload');
    expect(component.data()!.allowed.length).toBe(0);
    expect(component.message().text).toContain('blocks again');
  });

  it('reports a rebuild that failed instead of reloading', () => {
    build();
    api.rebuildProtection.and.returnValue(of({
      ok: false, output: 'error: no cache', state: protection(),
    }));
    component.rebuild();
    expect(api.serviceAction).not.toHaveBeenCalled();
    expect(component.message().ok).toBeFalse();
  });

  it('shows the mode and why it is that mode', () => {
    // Blocking is a topology decision, not a switch in the panel, so the screen
    // has to say why the switch is not there.
    const dom = build();
    expect(dom.textContent).toContain('Detection');
    expect(dom.textContent).toContain('listens to a copy');
  });

  it('counts nothing pending until a switch is moved', () => {
    build();
    expect(component.pendingCount()).toBe(0);
    component.toggle(component.data()!.categories[0]);
    expect(component.pendingCount()).toBe(1);
  });

  it('will not move the bucket that cannot be expressed as a rule', () => {
    build();
    const locked = component.data()!.categories.find((c: any) => c.locked);
    component.toggle(locked);
    expect(component.pendingCount()).toBe(0);
  });

  it('takes the switches back to the saved state', () => {
    build();
    component.toggle(component.data()!.categories[0]);
    component.revert();
    expect(component.pendingCount()).toBe(0);
  });

  it('sends every unlocked category, not only the one that changed', () => {
    // suricata-update rebuilds from the whole file, so a partial selection
    // would silently re-enable everything left out.
    build();
    api.setProtectionCategories.and.returnValue(
      of({ ok: true, output: 'Writing rules to /var/lib/suricata/rules/suricata.rules', state: protection() }),
    );
    component.toggle(component.data()!.categories[1]);
    component.save();
    expect(api.setProtectionCategories).toHaveBeenCalledWith({ malware: true, info: false }, true);
  });

  it('reloads the engine after saving, or the old rules keep matching', () => {
    build(protection(), true);
    api.setProtectionCategories.and.returnValue(
      of({ ok: true, output: '', state: protection() }),
    );
    component.save();
    expect(api.serviceAction).toHaveBeenCalledWith('reload');
    expect(component.message().text).toContain('reloaded');
  });

  it('does not try to reload an engine that is not running', () => {
    build(protection(), false);
    api.setProtectionCategories.and.returnValue(
      of({ ok: true, output: '', state: protection() }),
    );
    component.save();
    expect(api.serviceAction).not.toHaveBeenCalled();
    expect(component.message().text).toContain('once the engine is started');
  });

  it('says plainly when the rebuild failed', () => {
    build();
    api.setProtectionCategories.and.returnValue(
      of({ ok: false, output: 'error: source has not yet been downloaded', state: protection() }),
    );
    component.save();
    expect(component.message().ok).toBeFalse();
    expect(api.serviceAction).not.toHaveBeenCalled();
  });

  it('says plainly when the rules were saved but the engine would not reload', () => {
    build();
    api.setProtectionCategories.and.returnValue(of({ ok: true, output: '', state: protection() }));
    api.serviceAction.and.returnValue(throwError(() => ({ error: { detail: 'no' } })));
    component.save();
    expect(component.message().ok).toBeFalse();
    expect(component.message().text).toContain('saved');
  });

  it('explains silencing before anything has been silenced', () => {
    // The card used to appear only once something was muted, so the one
    // mechanism that deals with a noisy signature without touching anything
    // else was invisible to everybody who had not already found it.
    const dom = build(protection({ muted: [] }));
    const cards = Array.from(dom.querySelectorAll('.card'))
      .filter((c) => c.textContent?.includes('Silenced signatures'));
    expect(cards.length).toBe(1);
    expect(cards[0].textContent).toContain('alert list');
    expect(dom.querySelector('.empty-inline')?.textContent).toContain('Nothing is silenced');
  });

  it('lists the silenced signatures and can put one back', () => {
    const dom = build();
    expect(dom.textContent).toContain('ET INFO GNU/Linux APT User-Agent');
    api.unmuteSignature.and.returnValue(of({ ok: true, output: '', state: protection({ muted: [] }) }));
    component.unmute({ signature_id: 2013504, signature: 'ET INFO GNU/Linux APT User-Agent' });
    expect(api.unmuteSignature).toHaveBeenCalledWith(2013504);
    expect(component.data()!.muted.length).toBe(0);
  });

  describe('switching the engine to blocking', () => {
    function ready(mode: 'ids' | 'ips' = 'ids') {
      return protection({
        mode: { ...protection().mode, id: mode, can_switch: true,
                can_block: mode === 'ips' },
      });
    }

    it('asks first, because two clicks can blind the sensor', () => {
      // It happened: a phone put this device inline for two hours, blind to
      // the mirror port it was deployed to watch, and nothing asked.
      build(ready());
      const ask = spyOn(window, 'confirm').and.returnValue(false);
      component.setMode(true);
      expect(ask).toHaveBeenCalled();
      expect(api.setProtectionMode).not.toHaveBeenCalled();
    });

    it('does not say "Switching" beside "rebuilding first, then switching"', () => {
      // Both lines were printed together, and the first half of the second one
      // contradicted the first.
      const lagging = ready();
      lagging.mode = { ...lagging.mode, drop_pending: 45262 };
      const dom = build(lagging);
      spyOn(window, 'confirm').and.returnValue(true);
      api.setProtectionMode.and.returnValue(new Subject<any>());
      component.setMode(true);
      fixture.detectChanges();
      const working = dom.querySelector('.mode-working')!.textContent!
        .replace(/\s+/g, ' ');
      expect(working).toContain('Rebuilding the rule set first, then switching.');
      expect(working).not.toContain('switching. Switching.');
    });

    it('says the rule set is rebuilt first when it lags the categories', () => {
      const lagging = ready();
      lagging.mode = { ...lagging.mode, drop_pending: 45262 };
      const dom = build(lagging);
      const ask = spyOn(window, 'confirm').and.returnValue(true);
      api.setProtectionMode.and.returnValue(new Subject<any>());
      component.setMode(true);
      expect(ask.calls.mostRecent().args[0]).toContain('rebuilt first');
      fixture.detectChanges();
      expect(dom.querySelector('.mode-working')!.textContent).toContain('Rebuilding the rule set first');
    });

    it('says nothing of a rebuild when there is none to do, or on the way back', () => {
      build(ready());
      const ask = spyOn(window, 'confirm').and.returnValue(false);
      component.setMode(true);
      expect(ask.calls.mostRecent().args[0]).not.toContain('rebuilt');
      fixture.destroy();

      const lagging = ready('ips');
      lagging.mode = { ...lagging.mode, drop_pending: 45262 };
      build(lagging);
      component.setMode(false);
      expect(ask.calls.mostRecent().args[0]).not.toContain('rebuilt');
    });

    it('names the detection that stops, not only the dropping that starts', () => {
      // The half nobody expects is the capture that ends: inline on a queue the
      // engine no longer reads its interface at all.
      build(ready());
      const ask = spyOn(window, 'confirm').and.returnValue(false);
      component.setMode(true);
      const text = ask.calls.mostRecent().args[0] as string;
      expect(text).toContain('mirror');
      expect(text).toContain('no longer inspected');
      expect(text).toContain('restarts');
    });

    it('asks a different question where the engine would carry the link', () => {
      // Inline, this switch moves the forwarding from the kernel to the engine.
      // The cables do not change, so the old question - about a capture
      // interface the engine stops reading - describes nothing that happens,
      // and leaves out the one thing that matters: the link stops surviving a
      // stopped engine.
      build(protection({ mode: { ...protection().mode, inline: true } }));
      const ask = spyOn(window, 'confirm').and.returnValue(false);
      component.setMode(true);
      const text = ask.calls.mostRecent().args[0] as string;
      expect(text).toContain('cables stay where they are');
      expect(text).toContain('nothing crosses');
      expect(text).not.toContain('netfilter queue');
    });

    it('warns that the swap itself is an outage', () => {
      // Both directions cost an engine restart, and inline that is a link down
      // for as long as 68,000 rules take to load.
      build(protection({ mode: { ...protection().mode, id: 'ips', can_block: true,
                                 inline: true } }));
      const ask = spyOn(window, 'confirm').and.returnValue(false);
      component.setMode(false);
      const text = ask.calls.mostRecent().args[0] as string;
      expect(text).toContain('outage');
      expect(text).toContain('survives it stopping');
    });

    it('reports afterwards that the engine now carries the link', () => {
      build(protection({ mode: { ...protection().mode, inline: true } }));
      api.setProtectionMode.and.returnValue(of({ ok: true, output: '', mode: {} } as any));
      spyOn(window, 'confirm').and.returnValue(true);
      component.setMode(true);
      expect(component.modeMessage()?.text).toContain('carries this link');
    });

    it('confirms in a line instead of repeating the paragraph below it', () => {
      // The success message restated how the queue works right above the
      // paragraph that says the same, so the explanation showed twice.
      build();
      api.setProtectionMode.and.returnValue(of({ ok: true, output: '', mode: {} } as any));
      spyOn(window, 'confirm').and.returnValue(true);
      component.setMode(true);
      const text = component.modeMessage()!.text;
      expect(text).toBe('Blocking is on.');
      expect(text).not.toContain('netfilter');
    });

    it('goes ahead when the question is answered yes', () => {
      build(ready());
      api.setProtectionMode.and.returnValue(of({ ok: true, output: '', mode: {} } as any));
      spyOn(window, 'confirm').and.returnValue(true);
      component.setMode(true);
      expect(api.setProtectionMode).toHaveBeenCalledWith(true);
    });

    it('asks on the way back too, because that direction is the silent one', () => {
      // Turning blocking off changes nothing anybody can see: traffic keeps
      // flowing, no screen changes, and the badge simply stops being there -
      // and an absent badge is not a signal. On a device deployed inline that
      // is protection ending with nobody noticing.
      build(ready('ips'));
      const ask = spyOn(window, 'confirm').and.returnValue(false);
      component.setMode(false);
      expect(ask).toHaveBeenCalled();
      expect(api.setProtectionMode).not.toHaveBeenCalled();
    });

    it('says what stopping means, and what is kept', () => {
      build(ready('ips'));
      const ask = spyOn(window, 'confirm').and.returnValue(false);
      component.setMode(false);
      const text = ask.calls.mostRecent().args[0] as string;
      expect(text).toContain('Nothing will be blocked');
      expect(text).toContain('nothing on the network will show');
      // The selection survives; saying so is the difference between a pause and
      // an undo somebody is afraid to make.
      expect(text).toContain('kept');
    });

    it('asks a different question in each direction', () => {
      build(ready('ips'));
      const ask = spyOn(window, 'confirm').and.returnValue(false);
      component.setMode(false);
      const off = ask.calls.mostRecent().args[0] as string;
      fixture.destroy();

      build(ready('ids'));
      component.setMode(true);
      const on = ask.calls.mostRecent().args[0] as string;
      expect(on).not.toBe(off);
      expect(on).toContain('no longer inspected');   // only true going in
      expect(off).not.toContain('no longer inspected');
    });

    it('says it is working, because the switch takes a while', () => {
      // The engine restarts as part of it - about fifteen seconds. Two greyed
      // buttons and nothing else read as a click that did not register.
      const dom = build(ready());
      spyOn(window, 'confirm').and.returnValue(true);
      api.setProtectionMode.and.returnValue(new Subject<any>());
      component.setMode(true);
      fixture.detectChanges();
      const working = dom.querySelector('.mode-working')?.textContent ?? '';
      expect(working).toContain('engine restarts');
      expect(working).toContain('Leave this page open');
      expect(working).toContain('live stream drops and comes');
      expect(working).toContain('not a fault');
      // No timings: they are the board's business, not a promise to make here.
      expect(working).not.toMatch(/\bseconds?\b|\bminute\b/);
    });

    it('does not claim the change failed when the connection went', () => {
      // status 0 is the browser saying the connection died, not the device
      // saying no - and the engine restarts as part of the change, so the
      // request is the one call here that can die with the answer already true.
      build(ready());
      spyOn(window, 'confirm').and.returnValue(true);
      api.setProtectionMode.and.returnValue(throwError(() => ({ status: 0 })));
      component.setMode(true);
      const text = component.modeMessage().text as string;
      expect(text).toContain('may have gone through');
      expect(text).toContain('Reload');
      expect(text).not.toContain('could not be changed');
    });

    it('shows the answer beside the switch, not at the foot of the page', () => {
      // The working note vanished and the error landed far below, off screen:
      // "something happens and then it is gone".
      api.setProtectionMode.and.returnValue(throwError(() => ({
        status: 500, error: { detail: 'the ruleset was refused - nothing has been changed' },
      })));
      spyOn(window, 'confirm').and.returnValue(true);
      const dom = build();
      component.setMode(true);
      fixture.detectChanges();
      const card = dom.querySelector('.mode-switch')!.closest('section')!;
      expect(card.querySelector('.mode-result')!.textContent).toContain('the ruleset was refused');
      expect(component.message()).toBeNull();
    });

    it('still reports a refusal the device actually sent', () => {
      build(ready());
      spyOn(window, 'confirm').and.returnValue(true);
      api.setProtectionMode.and.returnValue(
        throwError(() => ({ status: 500, error: { detail: 'nft is missing' } })));
      component.setMode(true);
      expect(component.modeMessage().text).toBe('nft is missing');
    });

    it('goes ahead on the way back when the question is answered yes', () => {
      build(ready('ips'));
      api.setProtectionMode.and.returnValue(of({ ok: true, output: '', mode: {} } as any));
      spyOn(window, 'confirm').and.returnValue(true);
      component.setMode(false);
      expect(api.setProtectionMode).toHaveBeenCalledWith(false);
    });

    it('warns the rest of the app that the stream is about to drop', () => {
      // The request takes about fifteen seconds and the stream comes back half
      // a minute after that. In between the header showed "disconnected" in red
      // with no reason beside it, which reads as the panel dropping you - and
      // that is what it was reported as.
      build(ready());
      spyOn(window, 'confirm').and.returnValue(true);
      api.setProtectionMode.and.returnValue(new Subject<any>());
      const live = TestBed.inject(Live);
      component.setMode(true);
      expect(live.restarting()).toBeTrue();
    });

    it('says nothing of the sort when the question is declined', () => {
      build(ready());
      spyOn(window, 'confirm').and.returnValue(false);
      const live = TestBed.inject(Live);
      component.setMode(true);
      expect(live.restarting()).toBeFalse();
    });

    it('asks nothing when the mode is already the one requested', () => {
      build(ready('ips'));
      const ask = spyOn(window, 'confirm');
      component.setMode(true);
      expect(ask).not.toHaveBeenCalled();
      expect(api.setProtectionMode).not.toHaveBeenCalled();
    });
  });

  it('asks before downloading a fresh signature set', () => {
    build();
    spyOn(window, 'confirm').and.returnValue(false);
    component.updateSignatures();
    expect(api.updateRules).not.toHaveBeenCalled();
  });

  describe('downloading a fresh set', () => {
    const output = 'Writing rules to /var/lib/suricata/rules/suricata.rules: '
      + 'total: 68411; enabled: 52464';

    it('reloads the engine, like every other button on this screen', () => {
      // Downloading was the one action here that rewrote the rule file and did
      // not tell the engine. The message said "Signatures downloaded", the new
      // set sat on disk, and the engine went on matching the old one until
      // somebody found the reload button on another tab.
      build(protection(), true);
      api.updateRules.and.returnValue(of({ ok: true, output }));
      spyOn(window, 'confirm').and.returnValue(true);
      component.updateSignatures();
      expect(api.serviceAction).toHaveBeenCalledWith('reload');
      expect(component.message().text).toContain('reloaded');
    });

    it('says so when the download worked but the reload did not', () => {
      build(protection(), true);
      api.updateRules.and.returnValue(of({ ok: true, output }));
      api.serviceAction.and.returnValue(throwError(() => ({ error: { detail: 'no' } })));
      spyOn(window, 'confirm').and.returnValue(true);
      component.updateSignatures();
      expect(component.message().ok).toBeFalse();
      expect(component.message().text).toContain('downloaded');
      expect(component.message().text).toContain('Engine');
    });

    it('does not try to reload an engine that is not running', () => {
      build(protection(), false);
      api.updateRules.and.returnValue(of({ ok: true, output }));
      spyOn(window, 'confirm').and.returnValue(true);
      component.updateSignatures();
      expect(api.serviceAction).not.toHaveBeenCalled();
      expect(component.message().text).toContain('once the engine is started');
    });

    it('keeps the count from the rebuild output in the message', () => {
      // Without it the screen says a set was downloaded and never says how big
      // it turned out to be, which is the one number that says it worked.
      build(protection(), true);
      api.updateRules.and.returnValue(of({ ok: true, output }));
      spyOn(window, 'confirm').and.returnValue(true);
      component.updateSignatures();
      expect(component.message().text).toContain('enabled: 52464');
    });
  });

  it('keeps only the summary line out of the rebuild output', () => {
    build();
    const output = [
      '22/8/2026 -- 08:00:00 - <Info> -- Loading /etc/suricata/disable.conf',
      '22/8/2026 -- 08:00:07 - <Info> -- Writing rules to /var/lib/suricata/rules/suricata.rules: total: 68411; enabled: 52464',
    ].join('\n');
    expect(component.tail(output)).toBe(
      'Writing rules to /var/lib/suricata/rules/suricata.rules: total: 68411; enabled: 52464',
    );
  });

  it('offers a way to the wiring screen, because that is the other half', () => {
    const dom = build();
    expect(dom.querySelector('a[href="/setup"]')).not.toBeNull();
  });
});
