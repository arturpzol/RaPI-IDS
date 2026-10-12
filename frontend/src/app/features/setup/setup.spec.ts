import { provideRouter } from '@angular/router';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';

import { Api } from '../../core/api';
import { NetworkLink, TopologyState } from '../../core/models';
import { Setup } from './setup';

function link(name: string, overrides: Partial<NetworkLink> = {}): NetworkLink {
  return {
    name,
    kind: 'wired',
    driver: 'bcmgenet',
    usb: false,
    is_up: true,
    carrier: true,
    speed_mbps: 1000,
    mtu: 1500,
    mac: 'de:ad:be:ef:00:01',
    ipv4: ['192.168.1.10/24'],
    ipv6: [],
    subnets: ['192.168.1.0/24'],
    blocked: false,
    is_management: false,
    ...overrides,
  } as NetworkLink;
}

function profile(id: string, overrides: Record<string, unknown> = {}) {
  return {
    id,
    name: id,
    summary: '',
    sees: '',
    blind_to: '',
    hardware: '',
    steps: ['do a thing'],
    roles: [{ id: 'capture', label: 'Capture' }, { id: 'management', label: 'Panel access' }],
    passive: true,
    can_block: false,
    blocking_needs: '',
    blocking_cost: '',
    capture_has_address: false,
    can_apply: true,
    available: true,
    reason: '',
    ...overrides,
  };
}

function state(overrides: Partial<TopologyState> = {}): TopologyState {
  return {
    hardware: {
      links: [
        link('eth0', { is_management: true }),
        link('eth1', { usb: true, ipv4: [], subnets: [] }),
        link('wlan0', { kind: 'wireless', ipv4: ['10.10.0.5/16'], subnets: ['10.10.0.0/16'] }),
      ],
      management: 'eth0',
      counts: { usable: 3, wired: 2, wireless: 1 },
      wireless_blocked: false,
    },
    profiles: [
      profile('self', { capture_has_address: true, roles: [{ id: 'capture', label: 'Capture' }] }),
      profile('mirror'),
      profile('bridge', { available: false, reason: 'Needs 2 wired interfaces', can_apply: false }),
    ],
    current: { profile: '', roles: {}, chosen_at: '', applied: false, applied_at: '', home_net: '' },
    engine: { interfaces: ['eth0'] },
    ...overrides,
  } as TopologyState;
}

describe('Setup', () => {
  let fixture: ComponentFixture<Setup>;
  let component: any;
  let api: jasmine.SpyObj<Api>;

  /** What a successful save() leaves behind: the backend agreeing with the
   *  screen. Apply puts the stored layout into effect, not the one on screen,
   *  so the wizard refuses to move past the interfaces until the two match. */
  function stored() {
    component.state.update((current: any) => ({
      ...current,
      current: { ...current.current, profile: component.chosen(), roles: component.roles() },
    }));
  }

  function build(topology = state()) {
    api.topology.and.returnValue(of(topology));
    fixture = TestBed.createComponent(Setup);
    component = fixture.componentInstance;
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  beforeEach(() => {
    api = jasmine.createSpyObj<Api>('Api', [
      'topology', 'homeNetSuggestion', 'previewTopology', 'saveTopology',
      'applyCapture',
    ]);
    api.homeNetSuggestion.and.returnValue(of({ suggested: ['192.168.1.0/24'] } as any));
    api.previewTopology.and.returnValue(of({ profile: 'mirror', roles: {}, warnings: [], saved: false } as any));
    api.saveTopology.and.returnValue(of({ profile: 'mirror', roles: {}, warnings: [], saved: true } as any));
    TestBed.configureTestingModule({
      providers: [{ provide: Api, useValue: api }, provideRouter([])],
    });
  });

  it('shows the prompt in an empty field but never offers it as a choice', () => {
    // Listed beside eth0, "Choose an interface" read as an option, and
    // picking it was refused as "no interface chosen".
    const dom = build();
    component.pick(component.profiles().find((p: any) => p.id === 'mirror'));
    component.setRole('capture', '');
    component.toStep(2);
    fixture.detectChanges();
    const select = dom.querySelector('.assign-form select') as HTMLSelectElement;
    const prompt = select.options[0];
    expect(prompt.textContent).toContain('Choose an interface');
    expect(prompt.disabled).toBeTrue();
    expect(prompt.hidden).toBeTrue();
    // Still what the closed field shows while nothing is assigned.
    expect(select.selectedIndex).toBe(0);
  });

  it('shows that Apply is working, and for how long it may take', () => {
    // Up to a minute with a button that only changed its word read as a hang.
    const dom = build(state({ profiles: [profile('mirror')] }));
    component.pick(component.profiles()[0]);
    component.step.set(4);
    component.busy.set(true);
    fixture.detectChanges();
    const apply = Array.from(dom.querySelectorAll('button'))
      .find((b) => b.textContent!.includes('Applying'))!;
    expect(apply.getAttribute('aria-busy')).toBe('true');
    expect(dom.querySelector('.wait-note .spinner')).not.toBeNull();
    expect(dom.querySelector('.wait-note')!.textContent).toContain('Please wait');

    component.busy.set(false);
    fixture.detectChanges();
    expect(dom.querySelector('.wait-note')).toBeNull();
    expect(Array.from(dom.querySelectorAll('button[aria-busy]')).length).toBe(0);
  });

  it('ends on Done, with no listening, naming where the engine listens', () => {
    // The 12-second listen was its own listener, not the engine, and a quiet
    // network made a working mirror look broken. The last step now names the
    // interface the engine was put on (the bridge the panel built, not a
    // port picked earlier) and sends the reader to the engine's counters.
    api.applyCapture.and.returnValue(of({
      ok: true, interface: 'br-rapi', home_net: '[10.10.0.0/16]', steps: [],
    } as any));
    const dom = build(state({
      profiles: [profile('bridge', {
        roles: [{ id: 'bridge_a', label: 'A' }, { id: 'bridge_b', label: 'B' }],
      })],
    }));
    component.pick(component.profiles().find((p: any) => p.id === 'bridge'));
    component.setRole('bridge_a', 'eth0');
    component.setRole('bridge_b', 'eth1');
    stored();
    component.applyLayout();
    fixture.detectChanges();
    expect(component.step()).toBe(5);
    expect(component.stepLabels[4]).toBe('Done');
    const text = dom.textContent!.replace(/\s+/g, ' ');
    expect(text).toContain('the engine listens on br-rapi');
    expect(text).toContain('capture loss');
    expect(text).not.toContain('Listen');
    expect(dom.querySelector('probe-result')).toBeNull();
  });

  it('draws every layout, including the ones this device cannot do', () => {
    // Hiding the bridge on a one-port Pi saves a line of screen and costs the
    // reader the fact that a cheap adapter is the whole difference.
    const dom = build();
    expect(dom.querySelectorAll('.topo-card').length).toBe(3);
    expect(dom.textContent).toContain('Needs 2 wired interfaces');
  });

  it('refuses to move past the first step until a layout is chosen', () => {
    build();
    component.toStep(2);
    expect(component.step()).toBe(1);
  });

  it('will not pick a layout this hardware cannot do', () => {
    build();
    component.pick(component.profiles().find((p: any) => p.id === 'bridge'));
    expect(component.chosen()).toBe('');
  });

  it('suggests a capture interface that is not the one the browser arrived on', () => {
    // The choice that does not cut anybody off.
    build();
    component.pick(component.profiles().find((p: any) => p.id === 'mirror'));
    expect(component.roles()['capture']).toBe('eth1');
    expect(component.roles()['management']).toBe('eth0');
  });

  it('suggests the only wired interface there is, warnings and all', () => {
    const single = state();
    single.hardware.links = [
      link('eth0', { is_management: true }),
      link('wlan0', { kind: 'wireless', ipv4: [], subnets: [] }),
    ];
    single.hardware.counts = { usable: 2, wired: 1, wireless: 1 };
    build(single);
    component.pick(component.profiles().find((p: any) => p.id === 'mirror'));
    expect(component.roles()['capture']).toBe('eth0');
  });

  it('never gives one interface two roles', () => {
    build();
    component.pick(component.profiles().find((p: any) => p.id === 'mirror'));
    const names = Object.values(component.roles());
    expect(new Set(names).size).toBe(names.length);
  });

  it('asks the backend what an assignment would mean before saving it', () => {
    // Only the backend knows which interface this browser is talking through.
    build();
    component.pick(component.profiles().find((p: any) => p.id === 'mirror'));
    component.setRole('capture', 'eth0');
    expect(api.previewTopology).toHaveBeenCalledWith('mirror', jasmine.objectContaining({ capture: 'eth0' }));
    expect(api.saveTopology).not.toHaveBeenCalled();
  });

  it('says nothing at all while the form is still half filled', () => {
    // The backend refuses a partial assignment, correctly, and that refusal was
    // being painted across the top of the page the moment the step opened -
    // before anybody had touched a field. An empty select already says which
    // one is missing, and it does not read as a fault.
    build();
    component.pick(component.profiles().find((p: any) => p.id === 'mirror'));
    api.previewTopology.calls.reset();
    component.setRole('management', '');
    expect(api.previewTopology).not.toHaveBeenCalled();
    expect(component.error()).toBe('');
  });

  it('asks again as soon as the last field is filled', () => {
    // The negative test above passes on a component that never previews at all.
    build();
    component.pick(component.profiles().find((p: any) => p.id === 'mirror'));
    component.setRole('management', '');
    api.previewTopology.calls.reset();
    component.setRole('management', 'wlan0');
    expect(api.previewTopology).toHaveBeenCalled();
  });

  it('shows the warnings a preview came back with', () => {
    api.previewTopology.and.returnValue(
      of({ profile: 'mirror', roles: {}, warnings: ['eth0 is how this browser is talking'], saved: false } as any),
    );
    const dom = build();
    component.pick(component.profiles().find((p: any) => p.id === 'mirror'));
    component.toStep(2);
    fixture.detectChanges();
    expect(dom.textContent).toContain('is how this browser is talking');
  });

  it('reads home networks one per line and ignores the blanks', () => {
    build();
    component.homeNet = '192.168.1.0/24\n\n10.10.0.0/16 , 172.16.0.0/12\n';
    expect(component.homeNetList()).toEqual(['192.168.1.0/24', '10.10.0.0/16', '172.16.0.0/12']);
  });

  it('fills the home networks from what this machine is on', () => {
    build();
    expect(component.homeNet).toBe('192.168.1.0/24');
  });

  it('opens with the home networks that were applied, not a fresh guess', () => {
    // Applying the wizard again used to replace a hand-added VLAN with the
    // guess from this Pi's addresses, and HOME_NET decides which rules fire.
    build(state({ current: { profile: 'mirror', roles: { capture: 'eth1' }, chosen_at: '',
                             applied: true, applied_at: '',
                             home_net: '[10.10.0.0/16,192.168.50.0/24]' } }));
    expect(component.homeNet).toBe('10.10.0.0/16\n192.168.50.0/24');
    expect(component.homeNet).not.toContain('192.168.1.0/24');
  });

  it('still suggests the networks when nothing was applied yet', () => {
    build();
    expect(component.homeNet).toBe('192.168.1.0/24');
  });

  it('offers an empty choice for a role the wizard could not fill', () => {
    // A select with no empty entry shows its first option whatever the model
    // holds, so an unassigned role looked assigned and the save was refused
    // with "no interface chosen".
    const dom = build();
    component.pick(component.profiles().find((p: any) => p.id === 'mirror'));
    component.setRole('capture', '');
    component.toStep(2);
    fixture.detectChanges();
    const select = dom.querySelectorAll('.assign-form select')[0] as HTMLSelectElement;
    expect(select.value).toBe('');
    expect(select.options[0].textContent).toContain('Choose an interface');
  });

  it('reports a refused apply instead of pretending it worked', () => {
    api.applyCapture.and.returnValue(
      throwError(() => ({ error: { detail: 'eth0 cannot be the capture interface and the way into the panel' } })),
    );
    build();
    component.pick(component.profiles().find((p: any) => p.id === 'mirror'));
    stored();
    component.applyLayout();
    fixture.detectChanges();
    expect(component.error()).toContain('cannot be the capture interface');
    expect(component.step()).not.toBe(5);
  });

  it('moves to the check step once the engine has taken the change', () => {
    api.applyCapture.and.returnValue(of({ ok: true, interface: 'eth1', home_net: '[10.10.0.0/16]', steps: [] } as any));
    build();
    component.pick(component.profiles().find((p: any) => p.id === 'mirror'));
    stored();
    component.applyLayout();
    expect(component.step()).toBe(5);
  });

  it('notices when the engine is listening somewhere else entirely', () => {
    build();
    component.pick(component.profiles().find((p: any) => p.id === 'mirror'));
    component.setRole('capture', 'eth1');
    expect(component.engineMismatch()).toBe('eth0');
    component.setRole('capture', 'eth0');
    expect(component.engineMismatch()).toBe('');
  });

  it('comes back to the layout that was recorded last time', () => {
    const chosen = state();
    chosen.current = {
      profile: 'mirror', roles: { capture: 'eth1', management: 'wlan0' },
      chosen_at: '2026-08-22T10:00:00+02:00', applied: true,
      applied_at: '2026-08-22T10:00:05+02:00', home_net: '[10.10.0.0/16]',
    };
    build(chosen);
    expect(component.chosen()).toBe('mirror');
    expect(component.roles()['capture']).toBe('eth1');
  });


  it('does not call the own-traffic layout watch only', () => {
    // On "This device only" the blocking switch drops this Pi's own packets.
    // That is not the network, and not nothing either.
    const dom = build(state({ profiles: [profile('self', { can_block: false })] }));
    const pill = dom.querySelector('.topo-card .pill')!;
    expect(pill.textContent).toContain('blocks this Pi only');
    expect(pill.textContent).not.toContain('watch only');
  });

  it('says why an inline layout still does not block', () => {
    // "Traffic passes through the Pi" reads as "so it can block". It does not:
    // the panel builds a kernel bridge, which forwards the frame whatever the
    // rule says, and hands the engine a copy. The pill says watch only; this is
    // where that gets a reason instead of just a label.
    const dom = build(state({
      profiles: [profile('bridge', {
        passive: false,
        blocking_needs: 'af-packet with copy-mode: ips, or NFQUEUE',
      })],
    }));
    dom.querySelector<HTMLButtonElement>('.topo-card')!.click();
    fixture.detectChanges();

    const detail = dom.querySelector('.detail')!.textContent!;
    expect(detail).toContain('Does not block');
    expect(detail).toContain('copy-mode: ips');
    expect(dom.querySelector('.pill.block')).toBeNull();
  });

  describe('applying only what the backend has stored', () => {
    // Apply sends the home networks and nothing else: the layout and the roles
    // it puts into effect are the ones save() stored. A screen that lets you
    // pick a layout, skip to the last step and press Apply configures the
    // engine from an earlier visit, or fails with "No layout has been chosen
    // yet" while a layout is plainly selected in front of you.

    function saved(profile = 'self', roles: Record<string, string> = { capture: 'eth1' }) {
      return state({
        current: { profile, roles, chosen_at: '', applied: false,
                   applied_at: '', home_net: '' },
      } as any);
    }

    it('refuses to step past the interfaces while they are unsaved', () => {
      build();
      component.chosen.set('self');
      component.toStep(4);
      expect(component.step()).toBe(2);
      expect(component.error()).toContain('Save the interfaces first');
    });

    it('will not apply an unsaved layout', () => {
      build();
      component.chosen.set('self');
      component.applyLayout();
      expect(api.applyCapture).not.toHaveBeenCalled();
      expect(component.step()).toBe(2);
    });

    it('applies once the screen and the backend agree', () => {
      api.applyCapture.and.returnValue(of({ ok: true, interface: 'eth1', steps: [] } as any));
      build(saved());
      component.toStep(4);
      expect(component.step()).toBe(4);
      component.applyLayout();
      expect(api.applyCapture).toHaveBeenCalled();
    });

    it('counts a role changed after saving as unsaved again', () => {
      // The interesting case: the layout matches, one interface does not, and
      // the engine would be pointed at the one still on the backend.
      build(saved());
      expect(component.unsaved()).toBeFalse();
      component.setRole('capture', 'wlan0');
      expect(component.unsaved()).toBeTrue();
    });

    it('greys the later steps out rather than only refusing them', () => {
      const dom = build();
      component.chosen.set('self');
      fixture.detectChanges();
      const buttons = Array.from(dom.querySelectorAll<HTMLButtonElement>('.steps button'));
      expect(buttons[1].disabled).toBeFalse();
      expect(buttons[2].disabled).toBeTrue();
      expect(buttons[3].disabled).toBeTrue();
    });
  });

  describe('what the Apply step promises', () => {
    /** The last screen before the button, for one chosen layout. */
    function applyStep(id: string, overrides: Record<string, unknown> = {}) {
      const dom = build(state({
        profiles: [profile(id, { can_apply: true, ...overrides })],
      }));
      component.pick(component.profiles().find((p: any) => p.id === id));
      stored();
      component.toStep(4);
      fixture.detectChanges();
      return Array.from(dom.querySelectorAll('.banner'))
        .map((b) => b.textContent ?? '').join(' ');
    }

    it('says the inline layout changes the network, not a config file', () => {
      // The blanket banner described a config edit, and it was the last text
      // read before the one action that puts this device into a live link.
      const banner = applyStep('bridge');
      expect(banner).toContain('change to your network');
      expect(banner).toContain('survives a reboot');
    });

    it('does not promise the bridge is rolled back, because it is not', () => {
      // _apply_bridge says so in its own docstring: a bridge pulled out from
      // under a cable already plugged in is a dead link, so it stays.
      expect(applyStep('bridge')).toContain('the bridge stays');
      // And in the order rapi-inline really runs: the engine configuration is
      // checked before the network is touched, not written afterwards.
      expect(applyStep('bridge')).toContain('written and checked first');
      expect(applyStep('bridge')).not.toContain('written afterwards');
    });

    it('warns that a capture interface is taken over for good', () => {
      // The panel installs a unit that strips the address again after every
      // reboot and has no button to undo it.
      const banner = applyStep('mirror', { capture_has_address: false });
      expect(banner).toContain('after every reboot');
      expect(banner).toContain('rapi-capture-iface');
    });

    it('says what blocking costs on the layout that can do it', () => {
      // The pill says "can block". The cost of saying yes to that is a link
      // that stops surviving a stopped engine, and it belongs on the same card
      // rather than in a dialog somebody meets later.
      const dom = build(state({
        profiles: [profile('bridge', {
          can_block: true,
          blocking_cost: 'a stopped engine is a link that carries nothing',
        })],
      }));
      component.pick(component.profiles()[0]);
      fixture.detectChanges();
      const terms = Array.from(dom.querySelectorAll('.detail dt'))
        .map((t) => t.textContent ?? '');
      expect(terms).toContain('When it blocks');
      expect(dom.querySelector('.detail')!.textContent)
        .toContain('carries nothing');
    });

    it('says none of that for a layout that only edits the engine config', () => {
      const banner = applyStep('self', { capture_has_address: true });
      expect(banner).toContain('engine configuration');
      expect(banner).not.toContain('change to your network');
      expect(banner).not.toContain('after every reboot');
    });
  });
});
