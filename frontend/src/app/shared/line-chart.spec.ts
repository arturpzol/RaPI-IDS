import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ChartDatum, LineChart } from './line-chart';

/** Host with a card that behaves the way the dashboard cards do: a column, and
 *  a height only when the grid row hands it one. */
@Component({
  imports: [LineChart],
  template: `
    <!-- A grid row around the card, the way the dashboard has it: the row takes
         its height from the tallest card unless one is forced here. padding: 0
         so the numbers below are the width the chart is given, not the width
         minus whatever the card class pads by. -->
    <div style="display: grid; align-items: stretch; width: 600px">
      <div class="card" [style.height]="cardHeight"
           style="display: flex; flex-direction: column; padding: 0">
        <div class="card-title">Alerts per hour</div>
        <line-chart [data]="data" [fill]="fill" [legend]="legend" />
      </div>
    </div>
  `,
})
class Host {
  data: ChartDatum[] = [
    { label: '10', value: 4 }, { label: '11', value: 9 }, { label: '12', value: 2 },
  ];
  fill = false;
  legend = [{ label: 'Medium' }, { label: 'High' }];
  cardHeight: string | null = null;
}

/** The chart measures itself, so these have to run against real layout rather
 *  than against the template alone. */
describe('LineChart', () => {
  let fixture: ComponentFixture<Host>;

  function plot(): SVGSVGElement {
    return fixture.nativeElement.querySelector('svg.chart') as SVGSVGElement;
  }

  function card(): DOMRect {
    return (fixture.nativeElement.querySelector('.card') as HTMLElement).getBoundingClientRect();
  }

  /** One frame for the ResizeObserver, one for the re-render it triggers. */
  function settle(): Promise<void> {
    return new Promise((resolve) =>
      requestAnimationFrame(() =>
        setTimeout(() => {
          fixture.detectChanges();
          resolve();
        }, 30),
      ),
    );
  }

  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [Host] }).compileComponents();
    fixture = TestBed.createComponent(Host);
    document.body.appendChild(fixture.nativeElement);
  });

  afterEach(() => fixture.nativeElement.remove());

  it('sizes itself from its width when the card does not decide', async () => {
    fixture.detectChanges();
    await settle();
    // A third of the width, which at 600 px sits between the floor and the cap.
    const box = plot().getBoundingClientRect();
    expect(box.height / box.width).toBeCloseTo(0.34, 2);
  });

  /** The regression this exists for: with flex-basis 0 the plot contributed
   *  nothing to the height of the card, so a card alone in its grid row ended
   *  right below the title and the drawing hung out underneath it - where the
   *  next card painted over it and the chart looked simply absent. */
  it('stays inside its card in fill mode when nothing constrains the row', async () => {
    fixture.componentInstance.fill = true;
    fixture.detectChanges();
    await settle();
    const box = plot().getBoundingClientRect();
    expect(box.height).toBeGreaterThanOrEqual(170);
    expect(box.bottom).toBeLessThanOrEqual(card().bottom + 1);
  });

  it('takes the height the card gives it in fill mode', async () => {
    fixture.componentInstance.fill = true;
    fixture.componentInstance.cardHeight = '520px';
    fixture.detectChanges();
    await settle();
    // Well past the 230 px cap a self-sizing chart would stop at.
    expect(plot().getBoundingClientRect().height).toBeGreaterThan(400);
  });

  it('leaves the cap in place when it is not filling', async () => {
    fixture.componentInstance.cardHeight = '520px';
    fixture.detectChanges();
    await settle();
    expect(plot().getBoundingClientRect().height).toBeLessThanOrEqual(230);
  });
});
