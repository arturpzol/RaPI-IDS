import { Component, computed, input, output, signal } from '@angular/core';

import { GeoCountry } from '../core/models';
import { WORLD_PATHS, WORLD_VIEW } from './world-outline';

interface Marker {
  country: GeoCountry;
  x: number;
  y: number;
  r: number;
  className: string;
}

/** Radius of a country with a single alert, and of the busiest one. Both in
 *  viewBox units, so they scale with the card. */
const R_MIN = 3.5;
const R_MAX = 17;

/** Bubbles are sized by area, not by radius: doubling the radius quadruples the
 *  ink, and the eye reads the ink. */
function radius(count: number, max: number): number {
  if (max <= 1) return R_MIN;
  const share = Math.sqrt(count / max);
  return R_MIN + (R_MAX - R_MIN) * share;
}

/** Where alerts came from, on a world map drawn offline.
 *
 *  Accuracy is the country, and only the country: the database Debian ships
 *  resolves nothing finer, so a marker sits on the country's principal city and
 *  the caption says as much. Drawing a marker at the exact coordinates of an
 *  address we cannot locate to better than a national border would be a lie
 *  told in pixels.
 *
 *  Bubbles rather than shaded countries: the outline has no borders in it (see
 *  scripts/generate-world-map.py), and a choropleth of a hundred alerts spread
 *  over six countries is mostly empty land anyway.
 */
@Component({
  selector: 'world-map',
  template: `
    <div class="map-host">
      <svg [attr.viewBox]="viewBox" class="map" role="img" [attr.aria-label]="ariaLabel()">
        <g class="land">
          @for (path of paths; track $index) {
            <path [attr.d]="path" />
          }
        </g>

        <g class="markers">
          @for (marker of markers(); track marker.country.code) {
            <g [attr.class]="'marker ' + marker.className"
               [class.dimmed]="hovered() !== null && hovered() !== marker.country.code"
               (mouseenter)="hovered.set(marker.country.code)"
               (mouseleave)="hovered.set(null)"
               (click)="selected.emit(marker.country.code)">
              <!-- halo first: it gives a one-alert dot enough presence to find -->
              <circle class="halo" [attr.cx]="marker.x" [attr.cy]="marker.y"
                      [attr.r]="marker.r * 2.1" />
              <circle class="bubble" [attr.cx]="marker.x" [attr.cy]="marker.y"
                      [attr.r]="marker.r" />
              <!-- hit area, so a 3px dot is still clickable on a touchscreen -->
              <circle class="hit" [attr.cx]="marker.x" [attr.cy]="marker.y"
                      [attr.r]="marker.r + 6" />
            </g>
          }
        </g>
      </svg>

      @if (hoveredCountry(); as country) {
        <div class="tooltip" [style.left.%]="tooltipLeft()" [style.top.%]="tooltipTop()"
             [class.flip-x]="tooltipLeft() > 62" [class.flip-y]="tooltipTop() > 58">
          <div class="tt-name">{{ country.name }}</div>
          <div class="tt-count">{{ country.count }} {{ country.count === 1 ? 'alert' : 'alerts' }}</div>
          <div class="tt-meta">
            {{ country.sources }} {{ country.sources === 1 ? 'address' : 'addresses' }}
          </div>
        </div>
      }

      @if (markers().length === 0) {
        <div class="empty">{{ emptyText() }}</div>
      }
    </div>
  `,
  styles: [`
    :host { display: block; width: 100%; }

    .map-host { position: relative; width: 100%; }
    .map { display: block; width: 100%; height: auto; }

    .land path {
      fill: var(--bg-sunken);
      stroke: var(--border);
      stroke-width: 0.4;
    }

    .marker { cursor: pointer; }
    .marker.dimmed { opacity: 0.4; }

    .halo { fill: var(--accent); opacity: 0.13; }
    .bubble {
      fill: var(--accent);
      fill-opacity: 0.75;
      stroke: var(--bg-elevated);
      stroke-width: 0.8;
    }
    .hit { fill: transparent; }

    .marker.sev-1 .halo, .marker.sev-1 .bubble { fill: var(--sev-1); }
    .marker.sev-2 .halo, .marker.sev-2 .bubble { fill: var(--sev-2); }
    .marker.sev-3 .halo, .marker.sev-3 .bubble { fill: var(--sev-3); }
    .marker.sev-4 .halo, .marker.sev-4 .bubble { fill: var(--sev-4); }

    .marker:hover .bubble { fill-opacity: 1; }
    .marker:hover .halo { opacity: 0.3; }
    .marker, .halo, .bubble { transition: opacity var(--t-fast) var(--ease); }

    .tooltip {
      position: absolute;
      transform: translate(-50%, -115%);
      padding: 0.35rem 0.6rem;
      border: 1px solid var(--border-strong);
      border-radius: var(--radius);
      background: var(--bg-raised);
      box-shadow: var(--shadow-lg), var(--edge);
      pointer-events: none;
      white-space: nowrap;
      z-index: 5;
    }
    /* Near an edge the box would hang off the card, so it flips to the inside. */
    .tooltip.flip-x { transform: translate(-100%, -115%); }
    .tooltip.flip-y { transform: translate(-50%, 25%); }
    .tooltip.flip-x.flip-y { transform: translate(-100%, 25%); }

    .tt-name { font-size: var(--fs-sm); font-weight: 600; }
    .tt-count {
      color: var(--text);
      font-size: var(--fs-xs);
      font-variant-numeric: tabular-nums;
    }
    .tt-meta { color: var(--text-muted); font-size: var(--fs-xs); }

    .empty {
      position: absolute;
      inset: 0;
      display: grid;
      place-items: center;
      color: var(--text-dim);
      font-size: 0.8rem;
      text-align: center;
    }
  `],
})
export class WorldMap {
  readonly countries = input.required<GeoCountry[]>();
  readonly emptyText = input('No located alerts in this period');

  /** Alpha-2 of the country clicked, for filtering the alert list. */
  readonly selected = output<string>();

  protected readonly paths = WORLD_PATHS;
  protected readonly viewBox = `0 0 ${WORLD_VIEW.width} ${WORLD_VIEW.height}`;
  protected readonly hovered = signal<string | null>(null);

  protected readonly markers = computed<Marker[]>(() => {
    const placed = this.countries().filter((c) => c.lat !== null && c.lon !== null);
    const max = Math.max(...placed.map((c) => c.count), 1);
    return placed
      // Busiest first, so the small bubbles end up drawn on top of the big ones
      // and stay reachable where several countries sit close together.
      .sort((a, b) => b.count - a.count)
      .map((country) => {
        const { x, y } = project(country.lat as number, country.lon as number);
        return {
          country,
          x,
          y,
          r: radius(country.count, max),
          className: country.severity ? `sev-${country.severity}` : '',
        };
      });
  });

  protected readonly hoveredCountry = computed(() => {
    const code = this.hovered();
    return code === null ? null : (this.markers().find((m) => m.country.code === code)?.country ?? null);
  });

  private readonly hoveredMarker = computed(() => {
    const code = this.hovered();
    return code === null ? null : (this.markers().find((m) => m.country.code === code) ?? null);
  });

  protected readonly tooltipLeft = computed(
    () => ((this.hoveredMarker()?.x ?? 0) / WORLD_VIEW.width) * 100,
  );
  protected readonly tooltipTop = computed(
    () => ((this.hoveredMarker()?.y ?? 0) / WORLD_VIEW.height) * 100,
  );

  protected readonly ariaLabel = computed(() => {
    const list = this.markers();
    if (!list.length) return 'World map, no located alerts';
    const top = list.slice(0, 3).map((m) => `${m.country.name}: ${m.country.count}`);
    return `World map of alert sources. Busiest: ${top.join(', ')}.`;
  });
}

/** Plate carree, the same two lines the outline was generated with. */
function project(lat: number, lon: number): { x: number; y: number } {
  return {
    x: ((lon + 180) * WORLD_VIEW.width) / 360,
    y: ((WORLD_VIEW.latMax - lat) * WORLD_VIEW.height) / (WORLD_VIEW.latMax - WORLD_VIEW.latMin),
  };
}
