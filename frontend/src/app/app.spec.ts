import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';

import { Api } from './core/api';
import { Auth } from './core/auth';
import { Live } from './core/live';
import { App } from './app';

/** The engine's stats as the status endpoint reports them. */
function status(captureMode: 'af-packet' | 'nfqueue' | null, blocking?: boolean) {
  return {
    reader_alive: true, last_stats_at: 1788400000, last_event_at: 1788400000,
    lines_read: 10, parse_errors: 0, event_counts: {},
    engine: {
      capture_mode: captureMode,
      loss_measured: captureMode === 'af-packet',
      blocking: blocking ?? captureMode === 'nfqueue',
    },
    service: { running: true },
  } as any;
}

describe('App shell', () => {
  let fixture: ComponentFixture<App>;
  let api: jasmine.SpyObj<Api>;
  let live: Live;

  function build() {
    fixture = TestBed.createComponent(App);
    live = TestBed.inject(Live);
    TestBed.inject(Auth).user.set({ username: 'a' } as any);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  beforeEach(() => {
    api = jasmine.createSpyObj<Api>('Api', ['modules', 'health']);
    api.modules.and.returnValue(of({
      modules: [{ id: 'ids', name: 'IDS / IPS', description: '', icon: 'shield',
                  route: '/ids', tags: [], api_prefix: '/api/suricata',
                  enabled: true }],
    }));
    api.health.and.returnValue(of({ status: 'ok', version: '0.5.0', ws_clients: 0 }));
    TestBed.configureTestingModule({
      providers: [{ provide: Api, useValue: api }, Live, Auth, provideRouter([]),
                  provideHttpClient(), provideHttpClientTesting()],
    });
  });

  afterEach(() => fixture?.destroy());

  it('draws the mark as a filled shield with the pulse cut out of it', () => {
    const dom = build();
    const mark = dom.querySelector('.brand-icon')!;
    const shield = mark.querySelector('path.brand-shield')!;
    const pulse = mark.querySelector('path.brand-pulse')!;
    expect(shield.getAttribute('d')).toContain('M12 2 4 5v6');
    expect(pulse.getAttribute('d')).toContain('M7 12.5h2.4');
    // Filled, not outlined: it has to stand apart from the menu icons.
    expect(getComputedStyle(shield).fill).not.toBe('none');
    expect(getComputedStyle(pulse).fill).toBe('none');
  });

  it('names the module by what it does, both halves of it', () => {
    // Called "IDS", the one screen that can block sat behind a word saying it
    // cannot, and somebody looking for blocking had no reason to click it.
    const dom = build();
    const nav = dom.querySelector('nav')?.textContent ?? '';
    expect(nav).toContain('IDS / IPS');
  });

  it('says the live connection dropped, not that the panel is unreachable', () => {
    // The pages still refresh by polling in this state, so "not reachable"
    // contradicted the sentence right after it.
    build();
    const hint = (fixture.componentInstance as any).sensorHint();
    expect(hint).toContain('live connection to the panel dropped');
    expect(hint).not.toContain('not reachable');
  });

  describe('a restart the operator asked for', () => {
    it('is amber and explained, not a red fault', () => {
      // Switching the detection mode restarts the engine: fifteen seconds for
      // the request, half a minute more for the stream. The header said
      // "disconnected" in red for the whole of it with no reason beside it.
      const dom = build();
      live.expectRestart();
      fixture.detectChanges();
      expect(dom.querySelector('.stream-state.down')).toBeNull();
      expect(dom.querySelector('.stream-state')?.textContent).toContain('restarting');
      expect((fixture.componentInstance as any).sensorHint()).toContain('restarted from the panel');
    });

    it('gives way as soon as the stream is back', () => {
      const dom = build();
      live.expectRestart();
      fixture.detectChanges();
      expect(dom.querySelector('.stream-state')?.textContent).toContain('restarting');

      // A live stream is the answer; the flag is not consulted once it is.
      live.setRestStatus(status('af-packet'));
      (live as any).connected.set(true);
      (live as any).packetsMoving.set(true);
      fixture.detectChanges();
      expect(dom.querySelector('.stream-state')?.textContent).not.toContain('restarting');
    });

    it('does not dress up a fault nobody asked for', () => {
      // Without the flag the red state has to stay red: an engine that died on
      // its own is exactly what this indicator exists to show.
      const dom = build();
      fixture.detectChanges();
      expect(live.restarting()).toBeFalse();
      expect(dom.querySelector('.stream-state')?.textContent).not.toContain('restarting');
    });
  });

  describe('the blocking badge', () => {
    it('says so from any screen while the engine is inline', () => {
      // This device spent two hours on a netfilter queue - destroying packets
      // and inspecting nothing off the mirror port - and the only screen that
      // said so was the one nobody had open.
      const dom = build();
      live.setRestStatus(status('nfqueue'));
      fixture.detectChanges();
      expect(live.blocking()).toBeTrue();
      expect(dom.querySelector('.stream-state.blocking')?.textContent)
        .toContain('blocking');
    });

    it('says so on an inline pair, where there is no queue to read', () => {
      // The engine forwarding a pair itself publishes both sections, so the
      // badge keyed on the queue's presence called a kernel bridge a netfilter
      // queue - and the one keyed on the capture method would have missed it.
      const dom = build();
      live.setRestStatus(status('af-packet', true));
      fixture.detectChanges();
      expect(live.blocking()).toBeTrue();
      const badge = dom.querySelector('.stream-state.blocking')!;
      expect(badge.textContent).toContain('blocking');
      expect(badge.getAttribute('title')).not.toContain('netfilter');
      expect(badge.getAttribute('title')).toContain('stop packets');
    });

    it('is absent while the engine only reads a copy', () => {
      // A badge that is always there is a badge nobody reads on the day it
      // means something.
      const dom = build();
      live.setRestStatus(status('af-packet'));
      fixture.detectChanges();
      expect(live.blocking()).toBeFalse();
      expect(dom.querySelector('.stream-state.blocking')).toBeNull();
    });

    it('claims nothing before the engine has reported', () => {
      const dom = build();
      live.setRestStatus(status(null));
      fixture.detectChanges();
      expect(live.blocking()).toBeFalse();
      expect(dom.querySelector('.stream-state.blocking')).toBeNull();
    });
  });
});
