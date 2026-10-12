import { Component, computed, input } from '@angular/core';

/** A box in the drawing. Coordinates are the centre, in viewBox units. */
interface Node {
  id: string;
  x: number;
  y: number;
  label: string;
  kind: 'net' | 'device' | 'pi';
}

interface Edge {
  from: string;
  to: string;
  kind: 'traffic' | 'copy' | 'mgmt';
  /** Role whose interface name is written next to the line, when one is known. */
  role?: string;
  note?: string;
}

interface Layout {
  nodes: Node[];
  edges: Edge[];
}

const W = 380;
const H = 168;

/** Box sizes. The tap is deliberately smaller: it is a lump in a cable, not a
 *  device anyone administers. */
const BOX_W = 56;
const BOX_H = 32;

const ROW = 46;      // the main traffic chain
const BELOW = 126;   // where a passive sensor hangs

function chain(routerLabel = 'Router'): Node[] {
  return [
    { id: 'net', x: 40, y: ROW, label: 'Internet', kind: 'net' },
    { id: 'router', x: 130, y: ROW, label: routerLabel, kind: 'device' },
    { id: 'switch', x: 232, y: ROW, label: 'Switch', kind: 'device' },
    { id: 'clients', x: 334, y: ROW, label: 'Machines', kind: 'device' },
  ];
}

/** One drawing per layout. Written out rather than generated: five pictures is
 *  fewer than the rules that would be needed to derive them, and each one has a
 *  point to make that a generic renderer would flatten. */
const LAYOUTS: Record<string, Layout> = {
  self: {
    nodes: [...chain(), { id: 'pi', x: 232, y: BELOW, label: 'This Pi', kind: 'pi' }],
    edges: [
      { from: 'net', to: 'router', kind: 'traffic' },
      { from: 'router', to: 'switch', kind: 'traffic' },
      { from: 'switch', to: 'clients', kind: 'traffic' },
      { from: 'switch', to: 'pi', kind: 'traffic', role: 'capture' },
    ],
  },

  mirror: {
    nodes: [...chain(), { id: 'pi', x: 232, y: BELOW, label: 'This Pi', kind: 'pi' }],
    edges: [
      { from: 'net', to: 'router', kind: 'traffic' },
      { from: 'router', to: 'switch', kind: 'traffic' },
      { from: 'switch', to: 'clients', kind: 'traffic' },
      { from: 'switch', to: 'pi', kind: 'copy', role: 'capture', note: 'copy' },
      { from: 'router', to: 'pi', kind: 'mgmt', role: 'management', note: 'panel' },
    ],
  },


  bridge: {
    nodes: [
      { id: 'net', x: 34, y: ROW, label: 'Internet', kind: 'net' },
      { id: 'router', x: 116, y: ROW, label: 'Router', kind: 'device' },
      { id: 'pi', x: 198, y: ROW, label: 'This Pi', kind: 'pi' },
      { id: 'switch', x: 280, y: ROW, label: 'Switch', kind: 'device' },
      { id: 'clients', x: 350, y: BELOW, label: 'Machines', kind: 'device' },
    ],
    edges: [
      { from: 'net', to: 'router', kind: 'traffic' },
      { from: 'router', to: 'pi', kind: 'traffic', role: 'bridge_a' },
      { from: 'pi', to: 'switch', kind: 'traffic', role: 'bridge_b' },
      { from: 'switch', to: 'clients', kind: 'traffic' },
    ],
  },

};

/** Marker ids have to be unique per document, and five of these end up on one
 *  page. */
let instances = 0;

/** How the Pi is wired into the network, drawn rather than described.
 *
 *  A paragraph explaining that a mirror port sends a copy of the traffic to a
 *  passive sensor is read by people who already know what that is. The picture
 *  is for everyone else, and it is the same picture in the card, in the step
 *  where interfaces are assigned, and on the summary, so it becomes the thing
 *  the layout is recognised by.
 */
@Component({
  selector: 'topology-diagram',
  template: `
    <svg [attr.viewBox]="viewBox" class="diagram" role="img" [attr.aria-label]="ariaLabel()">
      <defs>
        <marker [attr.id]="'copy-' + uid" markerWidth="7" markerHeight="7"
                refX="6" refY="3.5" orient="auto">
          <path class="head-copy" d="M0 0 L7 3.5 L0 7 Z" />
        </marker>
      </defs>

      <g class="edges">
        @for (edge of edges(); track $index) {
          <path [attr.d]="edge.d" [attr.class]="'edge ' + edge.kind"
                [attr.marker-end]="edge.kind === 'copy' ? 'url(#copy-' + uid + ')' : null" />
          @if (edge.text) {
            <text class="edge-label" [attr.x]="edge.tx" [attr.y]="edge.ty"
                  [attr.text-anchor]="edge.anchor">{{ edge.text }}</text>
          }
        }
      </g>

      <g class="nodes">
        @for (node of nodes(); track node.id) {
          <g [attr.class]="'node ' + node.kind">
            <rect [attr.x]="node.x - node.w / 2" [attr.y]="node.y - node.h / 2"
                  [attr.width]="node.w" [attr.height]="node.h" rx="6" />
            <text [attr.x]="node.x" [attr.y]="node.y + 4" text-anchor="middle">
              {{ node.label }}
            </text>
          </g>
        }
      </g>
    </svg>
  `,
  styles: [`
    :host { display: block; width: 100%; }
    .diagram { display: block; width: 100%; height: auto; }

    .node rect {
      fill: var(--bg-sunken);
      stroke: var(--border-strong);
      stroke-width: 1.2;
    }
    .node text {
      fill: var(--text-muted);
      font-size: 11px;
      font-family: var(--sans);
    }
    .node.pi rect {
      fill: var(--accent-dim);
      stroke: var(--accent);
      stroke-width: 1.6;
    }
    .node.pi text { fill: var(--text); font-weight: 600; }
    .node.net rect { fill: transparent; stroke-dasharray: 3 3; }

    .edge { fill: none; stroke-linecap: round; }
    .edge.traffic { stroke: var(--border-strong); stroke-width: 2; }
    /* A copy is not the traffic itself, and the eye should not read it as a
       cable carrying the conversation. */
    .edge.copy { stroke: var(--accent); stroke-width: 1.8; stroke-dasharray: 5 4; }
    .edge.mgmt { stroke: var(--text-dim); stroke-width: 1.4; stroke-dasharray: 2 4; }
    .head-copy { fill: var(--accent); }

    .edge-label {
      fill: var(--text-dim);
      font-size: 9.5px;
      font-family: var(--mono);
    }
  `],
})
export class TopologyDiagram {
  readonly profile = input.required<string>();
  /** role -> interface name, written onto the lines once they are assigned. */
  readonly assignments = input<Record<string, string>>({});

  protected readonly uid = ++instances;
  protected readonly viewBox = `0 0 ${W} ${H}`;

  private static readonly NOTHING: Layout = { nodes: [], edges: [] };

  private readonly layout = computed(
    () => LAYOUTS[this.profile()] ?? TopologyDiagram.NOTHING,
  );

  protected readonly nodes = computed(() =>
    this.layout().nodes.map((node) => ({
      ...node,
      w: BOX_W,
      h: BOX_H,
    })),
  );

  protected readonly edges = computed(() => {
    const nodes = new Map(this.nodes().map((n) => [n.id, n]));
    const names = this.assignments();

    return this.layout().edges.flatMap((edge) => {
      const from = nodes.get(edge.from);
      const to = nodes.get(edge.to);
      if (!from || !to) return [];

      const label = [edge.role ? names[edge.role] : '', edge.note]
        .filter(Boolean)
        .join(' ');
      return [{ ...edge, ...route(from, to), text: label }];
    });
  });

  protected readonly ariaLabel = computed(() => {
    const names = this.nodes().map((n) => n.label).join(', ');
    return `Network layout: ${names}`;
  });
}

type Box = Node & { w: number; h: number };

/** Where the line runs, and where its label goes.
 *
 *  Two cases, because those are the two that occur: a straight run along the
 *  chain, and an elbow down to a box on the lower row. Anything cleverer would
 *  be a routing engine serving five fixed pictures.
 */
function route(from: Box, to: Box): { d: string; tx: number; ty: number; anchor: string } {
  if (from.y === to.y) {
    const left = from.x < to.x ? from : to;
    const right = from.x < to.x ? to : from;
    const x1 = left.x + left.w / 2;
    const x2 = right.x - right.w / 2;
    return {
      d: `M${x1} ${from.y} H${x2}`,
      tx: (x1 + x2) / 2,
      ty: from.y - 8,
      anchor: 'middle',
    };
  }

  const upper = from.y < to.y ? from : to;
  const lower = from.y < to.y ? to : from;
  const startY = upper.y + upper.h / 2;
  const endY = lower.y - lower.h / 2;

  if (Math.abs(from.x - to.x) < 1) {
    return {
      d: `M${from.x} ${startY} V${endY}`,
      tx: from.x + 6,
      ty: (startY + endY) / 2 + 3,
      anchor: 'start',
    };
  }

  // Down from the upper box, then in through the side of the lower one. Coming
  // in from the side rather than from the top matters when two lines reach the
  // same box: a copy of the traffic and a way into the panel are different
  // things and must not appear to arrive down the same cable.
  const turnY = lower.y;
  const corner = upper.x < lower.x ? 10 : -10;
  const side = lower.x - Math.sign(corner) * (lower.w / 2);
  return {
    d: `M${upper.x} ${startY} V${turnY - 10} `
      + `Q${upper.x} ${turnY} ${upper.x + corner} ${turnY} `
      + `H${side}`,
    tx: (upper.x + side) / 2,
    ty: turnY - 6,
    anchor: 'middle',
  };
}
