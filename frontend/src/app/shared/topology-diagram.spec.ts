import { ComponentFixture, TestBed } from '@angular/core/testing';

import { TopologyDiagram } from './topology-diagram';

/** The drawing is what the layout gets recognised by, in the card, in the step
 *  where interfaces are assigned and on the summary. */
describe('TopologyDiagram', () => {
  let fixture: ComponentFixture<TopologyDiagram>;

  function draw(profile: string, assignments: Record<string, string> = {}) {
    fixture = TestBed.createComponent(TopologyDiagram);
    fixture.componentRef.setInput('profile', profile);
    fixture.componentRef.setInput('assignments', assignments);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  function labels(root: HTMLElement): string[] {
    return Array.from(root.querySelectorAll('.node text')).map((n) => n.textContent!.trim());
  }

  it('draws every layout the wizard offers', () => {
    for (const profile of ['self', 'mirror', 'bridge']) {
      const svg = draw(profile);
      expect(labels(svg)).withContext(profile).toContain('This Pi');
      expect(svg.querySelectorAll('.edge').length).withContext(profile).toBeGreaterThan(2);
    }
  });

  it('draws a copy as a copy, not as a cable carrying the conversation', () => {
    expect(draw('mirror').querySelectorAll('.edge.copy').length).toBe(1);
    expect(draw('self').querySelectorAll('.edge.copy').length).toBe(0);
  });

  it('keeps the panel path separate from the captured traffic', () => {
    const svg = draw('mirror');
    expect(svg.querySelectorAll('.edge.mgmt').length).toBe(1);
  });

  it('puts the Pi in the traffic path only for the layouts that can block', () => {
    // The picture has to be the difference between watching and standing in the
    // way, because that difference is the whole decision.
    for (const inline of ['bridge']) {
      expect(draw(inline).querySelectorAll('.edge.copy').length).withContext(inline).toBe(0);
    }
  });

  it('draws nothing at all for a layout that no longer exists', () => {
    // "Network tap" and "The Pi is the router" were both removed. The map is
    // rendered from the stored profile id, and a device that chose one of them
    // still has that id on disk until the wizard is run again.
    for (const gone of ['tap', 'gateway', 'nonsense']) {
      expect(draw(gone).querySelectorAll('.node').length).withContext(gone).toBe(0);
    }
  });

  it('writes the interface names onto the lines once they are assigned', () => {
    const svg = draw('mirror', { capture: 'eth0', management: 'wlan0' });
    const text = svg.textContent!;
    expect(text).toContain('eth0');
    expect(text).toContain('wlan0');
  });

  it('says what it is drawing to a screen reader', () => {
    expect(draw('mirror').querySelector('svg')!.getAttribute('aria-label')).toBeTruthy();
  });

  it('gives each drawing its own marker, so several fit on one page', () => {
    const first = draw('mirror').querySelector('marker')!.id;
    const second = draw('tap').querySelector('marker')!.id;
    expect(first).not.toBe(second);
  });
});
