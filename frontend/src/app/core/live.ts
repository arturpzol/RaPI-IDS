import { Injectable, computed, signal } from '@angular/core';

import { Alert, LiveEvent, SuricataStatus, WsMessage } from './models';

const MAX_BUFFER = 500;
const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 15000;

/** Close code the panel sends when a live socket's session has ended. Matches
 *  config.WS_SESSION_ENDED on the backend. 1008 means the cookie was never
 *  good; this one means it was, and is not any more. */
const WS_SESSION_ENDED = 4001;

/** One WebSocket connection for the whole application.
 *
 *  State lives in signals, so components only read it - no subscriptions to
 *  manage and nothing to tear down. After a drop it reconnects with an
 *  increasing backoff.
 */
@Injectable({ providedIn: 'root' })
export class Live {
  /** Whether the stream is up. */
  readonly connected = signal(false);
  /** Whether the live view is running (pausing does not drop the socket). */
  readonly streaming = signal(true);

  readonly alerts = signal<Alert[]>([]);
  readonly events = signal<LiveEvent[]>([]);
  /** Alerts counted since page load - feeds the "new" badge. */
  readonly newAlertCount = signal(0);

  /** Fast-moving part, arriving every few seconds over the socket. */
  private readonly streamStatus = signal<SuricataStatus | null>(null);
  /** The whole picture, from GET /status - the only source of `service`. */
  private readonly restStatus = signal<SuricataStatus | null>(null);

  /** Engine state assembled from both sources.
   *
   *  They have to be merged field by field rather than one replacing the other:
   *  the stream carries neither `service` nor `capture`, because reporting them
   *  would mean running systemctl and reading sysfs every few seconds, and REST
   *  alone would go stale between polls. Whole-object precedence loses both -
   *  the view then shows "checking..." for as long as the stream is up, and the
   *  warning about a dead capture interface disappears the moment the stream
   *  connects, which is the worst possible time for it to.
   */
  readonly status = computed<SuricataStatus | null>(() => {
    const stream = this.streamStatus();
    const rest = this.restStatus();
    if (!stream) return rest;
    return {
      ...stream,
      service: stream.service ?? rest?.service,
      capture: stream.capture ?? rest?.capture,
    };
  });

  /** Whether the engine's packet counter moved between the last two readings.
   *
   *  `null` until there are two to compare. The engine reports every 8 s, so
   *  this settles within one interval of the page opening.
   *
   *  This is the one thing a dot in a panel like this has to say and the one
   *  thing "the socket is open" never says. A sensor whose capture is dead
   *  keeps its service active, keeps answering, keeps its counters green and
   *  stops seeing traffic - twelve hours of exactly that is what a VLAN tag in
   *  the flow key cost here, with every indicator on every screen showing
   *  normal the whole time.
   */
  /** Whether the engine can stop a packet, from its own stats.
   *
   *  The chrome said whether the sensor was alive and never whether it was
   *  blocking. This device spent two hours inline - taking packets off a queue,
   *  destroying 266 of them and inspecting nothing off the mirror port - and
   *  the only screen that said so was the one nobody had open.
   *
   *  Not the capture method: an inline pair reports both sections, so reading
   *  the queue's presence answered a different question than this one asks. */
  readonly blocking = computed(() => this.status()?.engine?.blocking === true);

  /** Set while a restart the panel asked for is expected to be under way.
   *
   *  Switching the detection mode restarts the engine, and the live stream is
   *  down for as long as that takes - which depends on the board and on how
   *  many rules it has to load, so no figure belongs on the screen. In between,
   *  the chrome showed "disconnected" in red with no reason beside it, which
   *  reads as the panel having dropped the operator. The state is known to
   *  whoever pressed the button; this is how the rest of the screen learns it. */
  readonly restarting = signal(false);
  private restartTimer: ReturnType<typeof setTimeout> | null = null;

  readonly packetsMoving = signal<boolean | null>(null);
  private lastPacketCount: number | null = null;

  /** What the header dot means, worst state first.
   *
   *  Deliberately not one boolean: "your browser is connected", "you pressed
   *  pause", "the engine is stopped" and "the engine is running and seeing
   *  nothing" are four different situations and only the last two are about
   *  the sensor.
   */
  readonly sensor = computed<'disconnected' | 'paused' | 'stopped' | 'idle' | 'live'>(() => {
    if (!this.connected()) return 'disconnected';
    if (!this.streaming()) return 'paused';
    const status = this.status();
    // `service` comes from REST only, so it is absent for a moment on a fresh
    // page. Absent is not "stopped": claiming the engine is down because we
    // have not asked yet is the same class of lie as the one above.
    if (status?.service && !status.service.running) return 'stopped';
    return this.packetsMoving() === false ? 'idle' : 'live';
  });

  private socket: WebSocket | null = null;
  private attempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  /** The socket was closed because the session behind it ended, not because
   *  the network dropped. Reconnecting is pointless until someone signs in. */
  readonly sessionEnded = signal(false);
  private closedByUs = false;

  connect(): void {
    if (this.socket && (this.socket.readyState === WebSocket.OPEN ||
                        this.socket.readyState === WebSocket.CONNECTING)) {
      return;
    }
    this.closedByUs = false;
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${proto}://${location.host}/ws`;

    try {
      this.socket = new WebSocket(url);
    } catch {
      this.scheduleReconnect();
      return;
    }

    this.socket.onopen = () => {
      this.connected.set(true);
      this.attempts = 0;
    };

    this.socket.onmessage = (event: MessageEvent<string>) => {
      if (!this.streaming()) return;
      let msg: WsMessage;
      try {
        msg = JSON.parse(event.data) as WsMessage;
      } catch {
        return;
      }
      this.dispatch(msg);
    };

    this.socket.onclose = (event: CloseEvent) => {
      this.connected.set(false);
      this.socket = null;
      // A gap in the readings is not a measurement. Keeping the old comparison
      // across a reconnect would compare a count from before the break with
      // one from after it and call a stalled sensor healthy.
      this.lastPacketCount = null;
      this.packetsMoving.set(null);
      // The session behind this socket ended - it expired, or a password change
      // ended every session there was. Retrying cannot succeed: the handshake
      // reads the same cookie. Without this the panel backed off to a minute
      // between attempts and sat there saying "disconnected", which describes
      // the socket and not the reason. Stopping here hands the question to the
      // 401 interceptor, which is the one place that knows how to ask someone
      // to sign in again.
      if (event.code === WS_SESSION_ENDED) {
        this.sessionEnded.set(true);
        return;
      }
      if (!this.closedByUs) this.scheduleReconnect();
    };

    this.socket.onerror = () => {
      // onclose fires right after anyway - the retry logic lives there
      this.connected.set(false);
    };
  }

  disconnect(): void {
    this.closedByUs = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.socket?.close();
    this.socket = null;
    this.connected.set(false);
  }

  toggleStreaming(): void {
    this.streaming.update((v) => !v);
  }

  resetNewAlertCount(): void {
    this.newAlertCount.set(0);
  }

  /** Hand over a GET /status response - whichever view happened to fetch it. */
  /** Say that a restart was asked for, so a break in the stream is expected.
   *
   *  Cleared by the clock rather than by the stream coming back, because a
   *  restart that fails is exactly the case where the operator has to see the
   *  red state and not a soothing explanation of it.
   */
  expectRestart(ms = 90_000): void {
    if (this.restartTimer) clearTimeout(this.restartTimer);
    this.restarting.set(true);
    this.restartTimer = setTimeout(() => {
      this.restarting.set(false);
      this.restartTimer = null;
    }, ms);
  }

  setRestStatus(status: SuricataStatus): void {
    this.restStatus.set(status);
  }

  private dispatch(msg: WsMessage): void {
    switch (msg.topic) {
      case 'suricata.alert': {
        const alert = msg.data as Alert;
        this.alerts.update((list) => [alert, ...list].slice(0, MAX_BUFFER));
        this.newAlertCount.update((n) => n + 1);
        break;
      }
      case 'suricata.event': {
        const evt = msg.data as LiveEvent;
        this.events.update((list) => [evt, ...list].slice(0, MAX_BUFFER));
        break;
      }
      case 'suricata.stats': {
        const status = msg.data as SuricataStatus;
        this.streamStatus.set(status);
        this.trackPackets(status.engine?.kernel_packets ?? null);
        break;
      }
    }
  }

  /** Follow the engine's packet counter across readings.
   *
   *  A counter that goes backwards is a restarted engine, not a stalled one -
   *  the count starts from zero again. Reporting that as "seeing nothing"
   *  would put the panel in a warning state every time the rules are reloaded
   *  with a restart, which is the fastest way to teach somebody to ignore it.
   */
  private trackPackets(count: number | null): void {
    if (count === null) return;
    const previous = this.lastPacketCount;
    this.lastPacketCount = count;
    if (previous === null || count < previous) {
      this.packetsMoving.set(null);
      return;
    }
    this.packetsMoving.set(count > previous);
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    this.attempts += 1;
    const delay = Math.min(RECONNECT_BASE_MS * 2 ** (this.attempts - 1), RECONNECT_MAX_MS);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }
}
