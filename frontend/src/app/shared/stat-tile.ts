import { NgTemplateOutlet } from '@angular/common';
import { Component, input, output } from '@angular/core';
import { RouterLink } from '@angular/router';

/** A tile with a single number. Deliberately without a chart - when the number
 *  is the whole message, a chart only dilutes it.
 *
 *  Give it a `link` and the whole tile becomes one, which is what a counter
 *  invites anyway: reading "264 waiting to be reviewed" and then hunting for
 *  the list through the menu is a step nobody should have to take. A link tile
 *  carries a chevron, because a tile that behaves differently from its
 *  neighbours has to look different from them before it is clicked.
 */
@Component({
  selector: 'stat-tile',
  imports: [NgTemplateOutlet, RouterLink],
  template: `
    @if (acts()) {
      <button type="button" class="tile linked" [class.alarm]="alarm()" [class]="tone()"
              (click)="activate.emit()">
        <ng-container *ngTemplateOutlet="body" />
        <span class="tile-go" aria-hidden="true">&rarr;</span>
      </button>
    } @else if (link().length) {
      <a class="tile linked" [class.alarm]="alarm()" [class]="tone()"
         [routerLink]="link()" [queryParams]="linkParams()">
        <ng-container *ngTemplateOutlet="body" />
        <span class="tile-go" aria-hidden="true">&rarr;</span>
      </a>
    } @else {
      <div class="tile" [class.alarm]="alarm()" [class]="tone()">
        <ng-container *ngTemplateOutlet="body" />
      </div>
    }

    <ng-template #body>
      <div class="tile-label">{{ label() }}@if (badge()) {<span class="tile-badge">{{ badge() }}</span>}</div>
      <div class="tile-value">
        {{ value() }}@if (unit()) {<span class="tile-unit">{{ unit() }}</span>}
      </div>
      @if (hint()) {
        <div class="tile-hint">{{ hint() }}</div>
      }
    </ng-template>
  `,
  styles: [`
    .tile {
      position: relative;
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
      padding: 0.95rem 1.1rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      background: linear-gradient(180deg, var(--bg-raised), var(--bg-elevated) 55%);
      box-shadow: var(--shadow-md), var(--edge);
      color: inherit;
      text-decoration: none;
    }

    button.tile {
      width: 100%;
      margin: 0;
      font: inherit;
      text-align: inherit;
      appearance: none;
      -webkit-appearance: none;
    }

    .tile.linked {
      cursor: pointer;
      transition: border-color var(--t-fast) var(--ease),
                  box-shadow var(--t-fast) var(--ease),
                  transform var(--t-fast) var(--ease);
    }
    .tile.linked:hover {
      border-color: var(--border-strong);
      box-shadow: var(--shadow-lg), var(--edge);
      transform: translateY(-1px);
    }
    .tile.linked.alarm:hover {
      border-color: color-mix(in srgb, var(--danger) 70%, transparent);
    }

    .tile-go {
      position: absolute;
      top: 0.85rem;
      right: 1rem;
      color: var(--text-dim);
      font-size: var(--fs-sm);
      line-height: 1;
      transition: color var(--t-fast) var(--ease), transform var(--t-fast) var(--ease);
    }
    .tile.linked:hover .tile-go { color: var(--text); transform: translateX(2px); }
    .tile.alarm .tile-go { color: var(--danger); }

    @media (prefers-reduced-motion: reduce) {
      .tile.linked, .tile-go { transition: none; }
      .tile.linked:hover { transform: none; }
      .tile.linked:hover .tile-go { transform: none; }
    }
    /* An alarming tile tints its whole surface rather than only its outline -
       a 1px red border is easy to miss at a glance across the room. */
    .tile.alarm {
      border-color: color-mix(in srgb, var(--danger) 45%, transparent);
      background:
        linear-gradient(180deg,
          color-mix(in srgb, var(--danger) 11%, var(--bg-raised)),
          var(--bg-elevated) 60%);
    }
    /* The rating tiles. Colour is the message here, not decoration: a tile
       that has to be read to be understood is a tile nobody reads across a
       room. The tint only appears when the count is not zero, so a row of
       quiet ratings stays quiet and one Critical is the only coloured thing
       on the screen.

       The edge is drawn whatever the count, because the row is a scale and a
       scale with missing rungs is not one. */
    .tile.rating { border-left: 3px solid var(--sev-4); }
    .tile.sev-1 { border-left-color: var(--sev-1); }
    .tile.sev-2 { border-left-color: var(--sev-2); }
    .tile.sev-3 { border-left-color: var(--sev-3); }
    .tile.sev-4 { border-left-color: var(--sev-4); }
    .tile.sev-none { border-left-color: var(--text-dim); }

    .tile.rating.lit.sev-1 { background: linear-gradient(180deg,
      color-mix(in srgb, var(--sev-1) 14%, var(--bg-raised)), var(--bg-elevated) 65%); }
    .tile.rating.lit.sev-2 { background: linear-gradient(180deg,
      color-mix(in srgb, var(--sev-2) 13%, var(--bg-raised)), var(--bg-elevated) 65%); }
    .tile.rating.lit.sev-3 { background: linear-gradient(180deg,
      color-mix(in srgb, var(--sev-3) 13%, var(--bg-raised)), var(--bg-elevated) 65%); }
    .tile.rating.lit.sev-1 .tile-value { color: var(--sev-1); }
    .tile.rating.lit.sev-2 .tile-value { color: var(--sev-2); }

    /* Nothing in this rating today. A dash is not a measurement, which is the
       point: "0" reads as a reading somebody took, and on the tile that would
       be shouting if it were wrong. */
    .tile.rating .tile-value { color: var(--text-dim); }
    .tile.rating.lit .tile-value { color: var(--text); }

    /* Blocking is not a rating, and a tile that looks like one is read as the
       sixth tier of a five tier scale. Its own colour, and the badge says which
       mode the number belongs to. Lit only when something was stopped: zero
       under "blocking is on" is a statement, not an achievement. */
    .tile.blocking { border-left: 3px solid var(--accent); }
    .tile.blocking .tile-value { color: var(--text-dim); }
    .tile.blocking.lit { background: linear-gradient(180deg,
      color-mix(in srgb, var(--accent) 13%, var(--bg-raised)), var(--bg-elevated) 65%); }
    .tile.blocking.lit .tile-value { color: var(--accent); }

    .tile-label {
      color: var(--text-muted);
      font-size: var(--fs-xs);
      font-weight: 600;
      letter-spacing: 0.075em;
      text-transform: uppercase;
    }
    .tile-value {
      font-size: var(--fs-xl);
      font-weight: 620;
      font-variant-numeric: tabular-nums;
      letter-spacing: -0.03em;   /* big figures need tighter tracking than body text */
      line-height: 1.1;
    }
    .tile.alarm .tile-value { color: var(--danger); }
    .tile-unit {
      margin-left: 0.18rem;
      color: var(--text-muted);
      font-size: var(--fs-md);
      font-weight: 500;
      letter-spacing: 0;
    }
    .tile-badge {
      margin-left: 0.4rem;
      padding: 0.05rem 0.3rem;
      border: 1px solid color-mix(in srgb, var(--accent) 55%, transparent);
      border-radius: var(--radius-sm);
      color: var(--accent);
      font-size: 0.62rem;
      letter-spacing: 0.08em;
    }
    .tile-hint {
      color: var(--text-dim);
      font-size: var(--fs-xs);
      font-variant-numeric: tabular-nums;
    }
  `],
})
export class StatTile {
  readonly label = input.required<string>();
  readonly value = input.required<string | number>();
  readonly unit = input<string>('');
  readonly hint = input<string>('');
  /** A word beside the label, for a tile whose number only means something in
   *  one mode of the engine. */
  readonly badge = input<string>('');
  /** Turns the tile red - e.g. dropped packets or under-voltage. */
  readonly alarm = input<boolean>(false);
  /** Extra classes for a tile that carries a rating: 'rating' plus the sev-N
   *  of the tier, plus 'lit' when the count is not zero. Passed as one string
   *  rather than four flags, because the caller builds the row from a list and
   *  the tier is already a string there. */
  readonly tone = input<string>('');
  /** Router path the tile leads to. Empty means the tile is not a link. */
  /** For a tile whose target is the screen it is already on. Navigating there
   *  changes the address and nothing else, because Angular keeps the component
   *  it already has and ngOnInit, where the parameters are read, does not run
   *  a second time. */
  readonly acts = input<boolean>(false);
  readonly activate = output<void>();

  readonly link = input<unknown[]>([]);
  readonly linkParams = input<Record<string, unknown>>({});
}
