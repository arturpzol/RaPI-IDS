import { Component, computed, input, output } from '@angular/core';

export interface RankItem {
  label: string;
  value: number;
  /** Optional severity class (sev-1..sev-4) - gives the bar its status colour. */
  severityClass?: string;
  /** Arbitrary value returned on click (e.g. an IP or SID to filter by). */
  key?: string | number;
}

/** A list of items with a proportional bar behind each row.
 *
 *  Horizontal bars instead of a pie chart: labels stay readable without a legend
 *  and lengths can be compared by eye. Every row carries a text label, so colour
 *  is never the only carrier of information.
 */
@Component({
  selector: 'rank-list',
  template: `
    @if (items().length === 0) {
      <div class="empty">No data</div>
    } @else {
      <ul class="ranks">
        @for (row of rows(); track row.label) {
          <li class="rank" [class.clickable]="clickable()"
              (click)="clickable() && pick.emit(row.key ?? row.label)"
              [title]="row.label">
            <div class="rank-fill" [class]="row.severityClass || ''"
                 [style.width.%]="row.percent"></div>
            <span class="rank-label">{{ row.label }}</span>
            <span class="rank-value">{{ row.value }}</span>
          </li>
        }
      </ul>
    }
  `,
  styles: [`
    .ranks { display: flex; flex-direction: column; gap: 3px; margin: 0; padding: 0; list-style: none; }

    .rank {
      position: relative;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.32rem 0.5rem;
      border-radius: var(--radius-sm);
      overflow: hidden;
    }
    .rank.clickable { cursor: pointer; }
    .rank.clickable:hover { background: var(--bg-hover); }

    .rank-fill {
      position: absolute;
      top: 0;
      left: 0;
      bottom: 0;
      border-radius: 0 2px 2px 0;
      /* Fades towards the label end. A flat 22% wash of --sev-3 yellow over the
         dark surface came out olive, and it read as a selected row rather than
         a measurement; the gradient keeps the hue and gives the bar an edge. */
      background: linear-gradient(90deg,
        color-mix(in srgb, var(--accent) 34%, transparent),
        color-mix(in srgb, var(--accent) 11%, transparent));
      border-left: 2px solid color-mix(in srgb, var(--accent) 65%, transparent);
    }
    /* the bar inherits the status colour when the item has a severity */
    .rank-fill.sev-1 { background: linear-gradient(90deg, color-mix(in srgb, var(--sev-1) 34%, transparent), color-mix(in srgb, var(--sev-1) 10%, transparent)); border-left-color: color-mix(in srgb, var(--sev-1) 70%, transparent); }
    .rank-fill.sev-2 { background: linear-gradient(90deg, color-mix(in srgb, var(--sev-2) 32%, transparent), color-mix(in srgb, var(--sev-2) 9%, transparent));  border-left-color: color-mix(in srgb, var(--sev-2) 70%, transparent); }
    .rank-fill.sev-3 { background: linear-gradient(90deg, color-mix(in srgb, var(--sev-3) 28%, transparent), color-mix(in srgb, var(--sev-3) 8%, transparent));  border-left-color: color-mix(in srgb, var(--sev-3) 70%, transparent); }
    .rank-fill.sev-4 { background: linear-gradient(90deg, color-mix(in srgb, var(--sev-4) 34%, transparent), color-mix(in srgb, var(--sev-4) 10%, transparent)); border-left-color: color-mix(in srgb, var(--sev-4) 70%, transparent); }

    .rank-label {
      position: relative;
      flex: 1;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-size: var(--fs-sm);
    }
    .rank-value {
      position: relative;
      color: var(--text-muted);
      font-size: var(--fs-sm);
      font-variant-numeric: tabular-nums;
      font-weight: 600;
    }
  `],
})
export class RankList {
  readonly items = input.required<RankItem[]>();
  readonly clickable = input<boolean>(false);
  readonly pick = output<string | number>();

  protected readonly rows = computed(() => {
    const items = this.items();
    const max = Math.max(...items.map((i) => i.value), 1);
    return items.map((i) => ({ ...i, percent: (i.value / max) * 100 }));
  });
}
