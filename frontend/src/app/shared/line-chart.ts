import {
  Component, ElementRef, OnDestroy, afterNextRender, computed, inject, input, signal,
  viewChild,
} from '@angular/core';

/** One band of a stacked area - e.g. alerts of a single severity in that hour. */
export interface ChartSegment {
  value: number;
  label: string;
  /** Status class (sev-1..sev-4) giving the band its colour. */
  className?: string;
}

export interface ChartDatum {
  /** X axis label (short). */
  label: string;
  /** Full description for the tooltip. */
  title?: string;
  value: number;
  /** Second line in the tooltip. For a value that qualifies the first one -
   *  a peak behind an average, say - rather than one that stacks with it. */
  note?: string;
  /** Optional breakdown. When present the chart is drawn as a stacked area. */
  segments?: ChartSegment[];
}

interface Point {
  x: number;
  y: number;
}

interface Band {
  label: string;
  className: string;
  /** Filled shape between this band's top edge and the one below it. */
  area: string;
  /** Top edge alone - stroked in the surface colour to separate the bands. */
  edge: string;
  tops: Point[];
}

const PAD_LEFT = 42;
const PAD_RIGHT = 12;
const PAD_TOP = 12;
const PAD_BOTTOM = 26;

/** Height as a share of width, then clamped - a time chart stretched to 7:1
 *  flattens every slope into a straight line. */
const ASPECT = 0.34;
const MIN_HEIGHT = 170;
/* Was 280. On a wide screen the chart hit the cap and made its card roughly
   twice the height of the one beside it, leaving a large gap in the grid - and
   most of the extra height was empty plot, since a quiet network spends most
   hours at zero. The cap applies to a chart that sizes itself; in fill mode the
   card decides, because there the height is not the chart's to choose. */
const MAX_HEIGHT = 230;

/** Above this many samples a dot per point turns into noise. */
const MAX_DOTS = 26;

/** Width assumed before the first measurement - replaced on the first frame. */
const FALLBACK_WIDTH = 720;

/** Line/area chart for one series over time, optionally stacked by category.
 *
 *  The SVG is measured, never stretched: a viewBox scaled to fit would give the
 *  drawing a horizontal scale factor of its own, which flattens slopes, turns
 *  round markers into ellipses and pulls the axis labels wide. So the component
 *  observes its own width and works in real pixels.
 *
 *  Straight segments, never a spline: the points are hourly buckets and a curve
 *  would invent values between them. One series => no legend (the card title
 *  names the data), a wash of the accent hue under the line. With segments the
 *  bands are stacked and a legend becomes mandatory, because colour then carries
 *  meaning - and every value is repeated as text in the tooltip, so colour is
 *  never the only cue.
 */
@Component({
  selector: 'line-chart',
  host: { '[class.fill]': 'fill()' },
  template: `
    @if (legend().length) {
      <div class="legend">
        @for (item of legend(); track item.label) {
          <span class="legend-item">
            <span class="swatch" [class]="'swatch ' + (item.className ?? '')"></span>{{ item.label }}
          </span>
        }
      </div>
    }

    <div class="chart-host" #plot>
      <svg [attr.viewBox]="'0 0 ' + width() + ' ' + height()" class="chart"
           [style.height.px]="height()" role="img" [attr.aria-label]="ariaLabel()">
        <!-- grid + Y axis labels -->
        @for (tick of yTicks(); track tick.label) {
          <line class="grid" [attr.x1]="PAD_LEFT" [attr.x2]="width() - PAD_RIGHT"
                [attr.y1]="tick.y" [attr.y2]="tick.y" />
          <text class="axis-label" [attr.x]="PAD_LEFT - 8" [attr.y]="tick.y + 3.5"
                text-anchor="end">{{ tick.label }}</text>
        }
        <!-- the two axes themselves, a step stronger than the grid -->
        <line class="axis" [attr.x1]="PAD_LEFT" [attr.x2]="PAD_LEFT"
              [attr.y1]="PAD_TOP" [attr.y2]="baselineY()" />
        <line class="axis" [attr.x1]="PAD_LEFT" [attr.x2]="width() - PAD_RIGHT"
              [attr.y1]="baselineY()" [attr.y2]="baselineY()" />

        <!-- crosshair: keeps the eye on the hovered slot across the whole plot -->
        @if (hoverIndex() !== null) {
          <line class="crosshair" [attr.x1]="crosshairX()" [attr.x2]="crosshairX()"
                [attr.y1]="PAD_TOP" [attr.y2]="baselineY()" />
        }

        @if (bands().length) {
          @for (band of bands(); track band.label) {
            <path [attr.class]="'area ' + band.className" [attr.d]="band.area" />
          }
          @for (band of bands(); track band.label) {
            <!-- Only a surface-coloured stroke, never one in the band's own hue:
                 an empty band collapses onto the one below it, so a coloured top
                 edge would paint the whole silhouette in the topmost colour even
                 at samples where that severity never occurred. -->
            <path class="edge-gap" [attr.d]="band.edge" />
          }
        } @else if (linePath()) {
          <path class="area" [attr.d]="areaPath()" />
          <path class="line" [attr.d]="linePath()" />
          @if (showDots()) {
            @for (point of points(); track $index) {
              <circle class="dot" [attr.cx]="point.x" [attr.cy]="point.y" r="3.5" />
            }
          }
        }

        <!-- X axis labels (every n-th, so they do not collide) -->
        @for (point of points(); track $index) {
          @if ($index % xLabelEvery() === 0) {
            <text class="axis-label" [attr.x]="point.x"
                  [attr.y]="baselineY() + 16" text-anchor="middle">
              {{ data()[$index].label }}
            </text>
          }
        }

        <!-- markers on the hovered sample, drawn last so they sit on top -->
        @for (marker of hoverDots(); track $index) {
          <circle [attr.class]="'marker ' + marker.className"
                  [attr.cx]="marker.x" [attr.cy]="marker.y" r="4.5" />
        }

        <!-- hit layer: a full-height slot per point, so hovering is easy -->
        @for (slot of hitSlots(); track $index) {
          <rect class="hit" [attr.x]="slot.x" [attr.y]="PAD_TOP"
                [attr.width]="slot.w" [attr.height]="baselineY() - PAD_TOP"
                (mouseenter)="hoverIndex.set($index)"
                (mouseleave)="hoverIndex.set(null)" />
        }
      </svg>

      @if (hovered(); as h) {
        <div class="tooltip" [style.left.%]="tooltipLeft()"
             [class.flip]="tooltipLeft() > 60">
          <div class="tt-title">{{ h.title || h.label }}</div>
          <div class="tt-value">{{ h.value }} {{ valueUnit() }}</div>
          @if (h.note) {
            <div class="tt-note">{{ h.note }}</div>
          }
          @for (seg of h.segments ?? []; track seg.label) {
            @if (seg.value > 0) {
              <div class="tt-seg">
                <span [attr.class]="'swatch ' + (seg.className ?? '')"></span>
                {{ seg.label }}<span class="tt-seg-value">{{ seg.value }}</span>
              </div>
            }
          }
        </div>
      }

      @if (points().length === 0) {
        <div class="empty">No data for this period</div>
      }
    </div>
  `,
  styles: [`
    /* A custom element is inline by default, so the component would measure an
       inline box instead of the card it sits in - and render narrower than it. */
    :host { display: block; width: 100%; }

    .chart-host { position: relative; width: 100%; }

    /* fill mode: the plot takes whatever height the card has left.
       flex-basis stays auto - with 0 the box contributes nothing to the card's
       own height, so a chart card alone in its grid row collapsed to the title
       and the plot disappeared. min-height: 0 is still needed, otherwise the
       drawing could push the box out and the measurement would chase itself. */
    :host(.fill) { display: flex; flex-direction: column; flex: 1 1 auto; min-height: 0; }
    :host(.fill) .chart-host { flex: 1 1 auto; min-height: 0; }
    .chart { display: block; width: 100%; overflow: visible; }

    .grid { stroke: var(--border); stroke-width: 1; }
    .axis { stroke: var(--border-strong); stroke-width: 1; }
    .axis-label { fill: var(--text-dim); font-size: 10px; font-family: var(--sans); }

    .crosshair {
      stroke: var(--border-strong);
      stroke-width: 1;
      stroke-dasharray: 2 3;
      pointer-events: none;
    }

    /* single series: a wash under the line, never a saturated block */
    .area { fill: var(--accent); opacity: 0.12; }
    .line {
      fill: none;
      stroke: var(--accent);
      stroke-width: 2;
      stroke-linejoin: round;
      stroke-linecap: round;
    }
    .dot {
      fill: var(--accent);
      /* the ring keeps a dot legible where it sits on its own line */
      stroke: var(--bg-elevated);
      stroke-width: 2;
    }

    /* stacked bands carry their hue in the fill - solid enough to read as a band */
    .area.sev-1 { fill: var(--sev-1); opacity: 0.72; }
    .area.sev-2 { fill: var(--sev-2); opacity: 0.72; }
    .area.sev-3 { fill: var(--sev-3); opacity: 0.72; }
    .area.sev-4 { fill: var(--sev-4); opacity: 0.72; }

    /* white doing the separating - not a border drawn around the band */
    .edge-gap {
      fill: none;
      stroke: var(--bg-elevated);
      stroke-width: 2;
      stroke-linejoin: round;
      stroke-linecap: round;
    }

    .marker {
      fill: var(--accent);
      stroke: var(--bg-elevated);
      stroke-width: 2;
      pointer-events: none;
    }
    .marker.sev-1 { fill: var(--sev-1); }
    .marker.sev-2 { fill: var(--sev-2); }
    .marker.sev-3 { fill: var(--sev-3); }
    .marker.sev-4 { fill: var(--sev-4); }

    .hit { fill: transparent; cursor: crosshair; }

    .legend {
      display: flex;
      flex-wrap: wrap;
      gap: 0.15rem 0.9rem;
      margin-bottom: 0.5rem;
      color: var(--text-muted);
      font-size: 0.75rem;
    }
    .legend-item { display: inline-flex; align-items: center; gap: 0.35rem; }

    .swatch {
      display: inline-block;
      width: 9px;
      height: 9px;
      border-radius: 2px;
      background: var(--accent);
      flex: none;
    }
    .swatch.sev-1 { background: var(--sev-1); }
    .swatch.sev-2 { background: var(--sev-2); }
    .swatch.sev-3 { background: var(--sev-3); }
    .swatch.sev-4 { background: var(--sev-4); }

    .tooltip {
      position: absolute;
      top: 0;
      transform: translateX(-50%);
      padding: 0.4rem 0.6rem;
      border: 1px solid var(--border-strong);
      border-radius: var(--radius);
      background: var(--bg-raised);
      box-shadow: var(--shadow-lg), var(--edge);
      pointer-events: none;
      white-space: nowrap;
      z-index: 5;
    }
    .tooltip.flip { transform: translateX(-100%); }
    .tt-title { color: var(--text-muted); font-size: var(--fs-xs); }
    .tt-value { font-size: var(--fs-sm); font-weight: 600; font-variant-numeric: tabular-nums; }
    .tt-note {
      color: var(--text-muted);
      font-size: var(--fs-xs);
      font-variant-numeric: tabular-nums;
    }
    .tt-seg {
      display: flex;
      align-items: center;
      gap: 0.35rem;
      margin-top: 0.15rem;
      color: var(--text-muted);
      font-size: 0.75rem;
    }
    .tt-seg-value {
      margin-left: auto;
      padding-left: 0.6rem;
      color: var(--text);
      font-variant-numeric: tabular-nums;
    }

    .empty {
      position: absolute;
      inset: 0;
      display: grid;
      place-items: center;
      color: var(--text-dim);
      font-size: 0.8rem;
    }
  `],
})
export class LineChart implements OnDestroy {
  readonly data = input.required<ChartDatum[]>();
  readonly valueUnit = input<string>('');
  readonly ariaLabel = input<string>('Line chart');
  /** Shown only when the chart is stacked - then colour carries meaning. */
  readonly legend = input<Array<{ label: string; className?: string }>>([]);
  /** Whether the Y axis has to start at zero.
   *
   *  It has to for counts: half a bar is half as many alerts, and a floating
   *  baseline would lie about that. It must not for a reading that lives in a
   *  narrow band well above zero - a CPU that sits between 48 and 62 degrees
   *  drawn from 0 to 80 is a flat line, which is the same as no chart at all.
   *  The axis labels are what keeps a floating baseline honest, so they are
   *  never omitted. */
  readonly startAtZero = input<boolean>(true);
  /** Take the height the card gives instead of deriving one from the width.
   *
   *  For a chart that is the whole card and sits in a row with a taller one:
   *  the cards are stretched to a common height anyway, so the choice is
   *  between a bigger plot and an empty strip under a small one. */
  readonly fill = input<boolean>(false);

  protected readonly PAD_LEFT = PAD_LEFT;
  protected readonly PAD_RIGHT = PAD_RIGHT;
  protected readonly PAD_TOP = PAD_TOP;

  private readonly host = inject(ElementRef<HTMLElement>);
  private readonly plot = viewChild<ElementRef<HTMLElement>>('plot');
  private observer: ResizeObserver | null = null;

  protected readonly width = signal(FALLBACK_WIDTH);
  /** Height handed over by the card in fill mode; 0 until first measured. */
  private readonly available = signal(0);
  protected readonly hoverIndex = signal<number | null>(null);

  /** Keeping the plot near 3:1 - the card is far wider than a chart should be. */
  protected readonly height = computed(() => {
    const free = this.available();
    if (this.fill() && free >= MIN_HEIGHT) return free;
    return Math.round(Math.min(Math.max(this.width() * ASPECT, MIN_HEIGHT), MAX_HEIGHT));
  });

  constructor() {
    afterNextRender(() => {
      const element = this.host.nativeElement as HTMLElement;
      const plot = this.plot()?.nativeElement;
      this.observer = new ResizeObserver((entries) => {
        for (const entry of entries) {
          if (entry.target === element) {
            // Width off the host: outside fill mode the height follows from it,
            // so reacting to height as well would feed the observer its output.
            const measured = Math.round(entry.contentRect.width);
            if (measured > 0 && measured !== this.width()) this.width.set(measured);
            continue;
          }
          // Fill mode: the plot box is sized by the card, and the drawing is
          // never made taller than the box that was measured, so this settles
          // after one extra frame instead of growing on every pass.
          const free = Math.floor(entry.contentRect.height);
          if (free > 0 && free !== this.available()) this.available.set(free);
        }
      });
      this.observer.observe(element);
      if (this.fill() && plot) this.observer.observe(plot);
    });
  }

  ngOnDestroy(): void {
    this.observer?.disconnect();
  }

  protected readonly maxValue = computed(() => {
    const values = this.data().map((d) => d.value);
    return values.length ? Math.max(...values, 1) : 1;
  });

  private readonly minValue = computed(() => {
    const values = this.data().map((d) => d.value);
    return values.length ? Math.min(...values) : 0;
  });

  /** Bottom of the scale. Zero unless the caller asked for a fitted axis, in
   *  which case it is the first round number at or below the smallest sample. */
  protected readonly scaleMin = computed(() => {
    if (this.startAtZero()) return 0;
    const step = niceStep((this.maxValue() - this.minValue()) / 2);
    return Math.min(Math.floor(this.minValue() / step) * step, this.maxValue() - step);
  });

  /** Round the top of the scale up, so axis labels read 5/10/25 - not 7 or 13. */
  protected readonly scaleMax = computed(() => {
    const max = this.maxValue();
    if (!this.startAtZero()) {
      const step = niceStep((max - this.minValue()) / 2);
      return Math.max(Math.ceil(max / step) * step, this.scaleMin() + step);
    }
    const step = Math.pow(10, Math.floor(Math.log10(max)));
    // A coarse ladder wastes half the plot: a peak of 27 would scale to 50.
    for (const factor of [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) {
      const candidate = step * factor;
      if (candidate >= max) return candidate;
    }
    return max;
  });

  protected readonly baselineY = computed(() => this.height() - PAD_BOTTOM);

  /** X of every sample. Edge to edge, so the series fills the plot. */
  protected readonly xs = computed(() => {
    const n = this.data().length;
    const plotW = this.width() - PAD_LEFT - PAD_RIGHT;
    if (n === 0) return [];
    if (n === 1) return [PAD_LEFT + plotW / 2];
    return this.data().map((_, i) => PAD_LEFT + (i / (n - 1)) * plotW);
  });

  /** Points of the total value - the single-series line, and the X label anchors. */
  protected readonly points = computed<Point[]>(() =>
    this.xs().map((x, i) => ({ x, y: this.toY(this.data()[i].value) })),
  );

  protected readonly showDots = computed(() => this.data().length <= MAX_DOTS);

  /** Transposed into stacked bands, bottom-up in the order the segments arrive. */
  protected readonly bands = computed<Band[]>(() => {
    const data = this.data();
    const xs = this.xs();
    const count = data[0]?.segments?.length ?? 0;
    if (!count) return [];

    const baseline = this.baselineY();
    // Running height of the stack under the band currently being built.
    const below = data.map(() => 0);
    const bands: Band[] = [];

    for (let s = 0; s < count; s += 1) {
      const tops: Point[] = [];
      const bottoms: Point[] = [];
      for (let i = 0; i < data.length; i += 1) {
        const seg = data[i].segments?.[s];
        bottoms.push({ x: xs[i], y: this.toY(below[i]) });
        below[i] += seg?.value ?? 0;
        tops.push({ x: xs[i], y: this.toY(below[i]) });
      }
      const first = data[0].segments?.[s];
      bands.push({
        label: first?.label ?? String(s),
        className: first?.className ?? '',
        area: this.polygon(tops, bottoms, baseline),
        edge: this.polyline(tops),
        tops,
      });
    }
    return bands;
  });

  protected readonly linePath = computed(() =>
    this.bands().length ? '' : this.polyline(this.points()),
  );

  protected readonly areaPath = computed(() => {
    const pts = this.points();
    if (!pts.length) return '';
    const baseline = this.baselineY();
    const floor = pts.map((p) => ({ x: p.x, y: baseline }));
    return this.polygon(pts, floor, baseline);
  });

  /** Full-height hover slots, each centred on its point. */
  protected readonly hitSlots = computed(() => {
    const xs = this.xs();
    if (!xs.length) return [];
    const plotW = this.width() - PAD_LEFT - PAD_RIGHT;
    const w = xs.length > 1 ? plotW / (xs.length - 1) : plotW;
    return xs.map((x) => ({ x: Math.max(x - w / 2, PAD_LEFT), w }));
  });

  /** Three grid levels - enough to read a value off, few enough to stay quiet. */
  protected readonly yTicks = computed(() => {
    const min = this.scaleMin();
    const span = this.scaleMax() - min;
    const plotH = this.baselineY() - PAD_TOP;
    return [0, 0.5, 1].map((f) => ({
      label: formatTick(min + span * f, span),
      y: PAD_TOP + plotH - f * plotH,
    }));
  });

  protected readonly xLabelEvery = computed(() => {
    const n = this.data().length;
    return n <= 8 ? 1 : Math.ceil(n / 8);
  });

  protected readonly hovered = computed(() => {
    const i = this.hoverIndex();
    return i === null ? null : (this.data()[i] ?? null);
  });

  protected readonly crosshairX = computed(() => {
    const i = this.hoverIndex();
    return i === null ? 0 : (this.xs()[i] ?? 0);
  });

  /** One marker per series at the hovered X - skipping bands that are empty there. */
  protected readonly hoverDots = computed(() => {
    const i = this.hoverIndex();
    if (i === null) return [];
    const x = this.xs()[i] ?? 0;
    const bands = this.bands();
    if (!bands.length) {
      const point = this.points()[i];
      return point ? [{ x, y: point.y, className: '' }] : [];
    }
    const segments = this.data()[i].segments ?? [];
    return bands
      .map((b, s) => ({ x, y: b.tops[i].y, className: b.className, value: segments[s]?.value ?? 0 }))
      .filter((dot) => dot.value > 0);
  });

  protected readonly tooltipLeft = computed(() => {
    const i = this.hoverIndex();
    return i === null ? 0 : ((this.xs()[i] ?? 0) / this.width()) * 100;
  });

  private toY(value: number): number {
    const plotH = this.baselineY() - PAD_TOP;
    const min = this.scaleMin();
    const span = this.scaleMax() - min || 1;
    return PAD_TOP + plotH - ((value - min) / span) * plotH;
  }

  private polyline(points: Point[]): string {
    if (!points.length) return '';
    return points
      .map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(2)} ${p.y.toFixed(2)}`)
      .join(' ');
  }

  /** Top edge left to right, bottom edge back again, closed. */
  private polygon(top: Point[], bottom: Point[], baseline: number): string {
    if (!top.length) return '';
    if (top.length === 1) {
      // A single sample has no width - give it one, so it is visible at all.
      const { x, y } = top[0];
      return `M${x - 2} ${baseline} L${x - 2} ${y} L${x + 2} ${y} L${x + 2} ${baseline} Z`;
    }
    const back = [...bottom].reverse();
    return `${this.polyline(top)} ${back
      .map((p) => `L${p.x.toFixed(2)} ${p.y.toFixed(2)}`)
      .join(' ')} Z`;
  }
}

/** Round a rough interval to the nearest 1, 2 or 5 of its magnitude, so the
 *  axis reads 45 / 55 / 65 rather than 47.3 / 56.8 / 66.3. */
function niceStep(rough: number): number {
  if (!(rough > 0)) return 1;
  const magnitude = Math.pow(10, Math.floor(Math.log10(rough)));
  for (const factor of [1, 2, 5]) {
    if (magnitude * factor >= rough) return magnitude * factor;
  }
  return magnitude * 10;
}

/** Tick label with just enough precision for the range it sits in.
 *
 *  Rounding every tick to an integer broke fitted axes over a narrow band: a
 *  scale from 31 to 34 put its middle tick at 32.5 and printed it as 33, right
 *  under a top tick reading 34. Trailing zeros are dropped, so a wide scale
 *  still reads 40 / 55 / 70 rather than 40.0 / 55.0 / 70.0.
 */
function formatTick(value: number, span: number): string {
  const decimals = span >= 10 ? 0 : span >= 1 ? 1 : 2;
  return String(Number(value.toFixed(decimals)));
}
