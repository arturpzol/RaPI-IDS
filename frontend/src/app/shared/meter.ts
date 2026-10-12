import { Component, computed, input } from '@angular/core';

/** A labelled fill bar - for CPU, memory, disk.
 *
 *  The colour changes at thresholds (normal / warning / alarm), but the percentage
 *  is always spelled out, so reading it never depends on telling colours apart.
 */
@Component({
  selector: 'ui-meter',
  template: `
    <div class="meter-row">
      <span class="meter-label">{{ label() }}</span>
      <span class="meter-detail">{{ detail() }}</span>
      <span class="meter-pct" [class]="level()">{{ percent().toFixed(0) }}%</span>
    </div>
    <div class="track" role="progressbar" [attr.aria-valuenow]="percent().toFixed(0)"
         aria-valuemin="0" aria-valuemax="100" [attr.aria-label]="label()">
      <div class="fill" [class]="level()" [style.width.%]="clamped()"></div>
    </div>
  `,
  styles: [`
    .meter-row {
      display: flex;
      align-items: baseline;
      gap: 0.5rem;
      margin-bottom: 0.35rem;
    }
    .meter-label { font-size: var(--fs-sm); font-weight: 500; }
    .meter-detail {
      flex: 1;
      color: var(--text-dim);
      font-size: var(--fs-xs);
      font-variant-numeric: tabular-nums;
    }
    .meter-pct {
      font-size: var(--fs-sm);
      font-weight: 600;
      font-variant-numeric: tabular-nums;
    }
    .meter-pct.warn { color: var(--warn); }
    .meter-pct.crit { color: var(--danger); }

    /* The track is sunken, the fill is lit - the bar reads as liquid in a
       channel instead of two stacked rectangles. */
    .track {
      height: 7px;
      border-radius: var(--radius-full);
      background: var(--bg-input);
      box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.3);
      overflow: hidden;
    }
    .fill {
      height: 100%;
      border-radius: var(--radius-full);
      background: linear-gradient(90deg,
        color-mix(in srgb, var(--accent) 72%, transparent), var(--accent));
      box-shadow: 0 0 10px -2px var(--accent-glow), var(--edge-strong);
      transition: width 0.5s var(--ease), background 0.3s var(--ease);
    }
    .fill.warn {
      background: linear-gradient(90deg,
        color-mix(in srgb, var(--warn) 72%, transparent), var(--warn));
      box-shadow: 0 0 10px -2px color-mix(in srgb, var(--warn) 45%, transparent), var(--edge-strong);
    }
    .fill.crit {
      background: linear-gradient(90deg,
        color-mix(in srgb, var(--danger) 72%, transparent), var(--danger));
      box-shadow: 0 0 10px -2px color-mix(in srgb, var(--danger) 45%, transparent), var(--edge-strong);
    }
  `],
})
export class Meter {
  readonly label = input.required<string>();
  readonly percent = input.required<number>();
  readonly detail = input<string>('');
  readonly warnAt = input<number>(75);
  readonly critAt = input<number>(90);

  protected readonly clamped = computed(() => Math.min(Math.max(this.percent(), 0), 100));

  protected readonly level = computed(() => {
    const p = this.percent();
    if (p >= this.critAt()) return 'crit';
    if (p >= this.warnAt()) return 'warn';
    return '';
  });
}
