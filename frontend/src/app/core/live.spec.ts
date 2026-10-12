import { TestBed } from '@angular/core/testing';

import { Live } from './live';
import { Alert, SuricataStatus } from './models';

/** The live stream. Tested through a fake socket: the reconnect and the merge
 *  of the two status sources are the parts that go quietly wrong. */
class FakeSocket {
  static last: FakeSocket | null = null;
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;

  readyState = 0;
  onopen: (() => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((event: MessageEvent<string>) => void) | null = null;
  closed = false;

  constructor(readonly url: string) {
    FakeSocket.last = this;
  }

  open() {
    this.readyState = 1;
    this.onopen?.();
  }

  send(topic: string, data: unknown) {
    this.onmessage?.(new MessageEvent('message', { data: JSON.stringify({ topic, data }) }));
  }

  raw(text: string) {
    this.onmessage?.(new MessageEvent('message', { data: text }));
  }

  drop(code = 1006) {
    this.readyState = 3;
    this.onclose?.({ code } as CloseEvent);
  }

  close() {
    this.closed = true;
    this.drop();
  }
}

function alert(id: number): Alert {
  return { id, ts: 0, signature: `alert ${id}` } as Alert;
}

describe('Live', () => {
  let live: Live;
  let original: typeof WebSocket;

  beforeEach(() => {
    original = window.WebSocket;
    (window as any).WebSocket = FakeSocket;
    FakeSocket.last = null;
    TestBed.configureTestingModule({});
    live = TestBed.inject(Live);
  });

  afterEach(() => {
    live.disconnect();
    (window as any).WebSocket = original;
  });

  it('connects to the same origin it was served from', () => {
    live.connect();
    expect(FakeSocket.last!.url).toBe(
      `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`,
    );
  });

  it('does not open a second socket while one is already up', () => {
    live.connect();
    const first = FakeSocket.last;
    first!.open();
    live.connect();
    expect(FakeSocket.last).toBe(first);
  });

  it('collects alerts newest first and counts them for the badge', () => {
    live.connect();
    FakeSocket.last!.open();
    FakeSocket.last!.send('suricata.alert', alert(1));
    FakeSocket.last!.send('suricata.alert', alert(2));
    expect(live.alerts().map((a) => a.id)).toEqual([2, 1]);
    expect(live.newAlertCount()).toBe(2);
    live.resetNewAlertCount();
    expect(live.newAlertCount()).toBe(0);
  });

  it('keeps the buffer bounded', () => {
    live.connect();
    FakeSocket.last!.open();
    for (let i = 0; i < 600; i += 1) FakeSocket.last!.send('suricata.event', { id: i });
    expect(live.events().length).toBe(500);
  });

  it('pausing stops the view without dropping the socket', () => {
    live.connect();
    FakeSocket.last!.open();
    live.toggleStreaming();
    FakeSocket.last!.send('suricata.alert', alert(1));
    expect(live.alerts().length).toBe(0);
    expect(live.connected()).toBeTrue();
  });

  it('ignores a message that is not the JSON it expects', () => {
    live.connect();
    FakeSocket.last!.open();
    expect(() => FakeSocket.last!.raw('<html>login page</html>')).not.toThrow();
    expect(live.alerts().length).toBe(0);
  });

  it('keeps the service state when only the stream is talking', () => {
    // The stream carries no `service` - reporting it would mean running
    // systemctl every few seconds. Letting the stream replace the whole object
    // leaves the view saying "checking..." for as long as the socket is up.
    live.setRestStatus({ service: { name: 'suricata', running: true } } as SuricataStatus);
    live.connect();
    FakeSocket.last!.open();
    FakeSocket.last!.send('suricata.stats', { lines_read: 10 });
    expect(live.status()!.service!.running).toBeTrue();
    expect((live.status() as any).lines_read).toBe(10);
  });

  it('keeps the capture warning up once the stream connects', () => {
    // Same trap as the line above, with worse consequences: the stream carries
    // no `capture` either, so whole-object precedence made the warning about a
    // dead capture interface vanish the moment the socket came up. The sensor
    // is deaf either way; only the sentence saying so disappears.
    live.setRestStatus({
      capture: { interfaces: [], state: 'bad', problem: 'eth0 is down' },
    } as unknown as SuricataStatus);
    live.connect();
    FakeSocket.last!.open();
    FakeSocket.last!.send('suricata.stats', { lines_read: 10 });
    expect(live.status()!.capture!.problem).toBe('eth0 is down');
  });

  describe('what the header dot means', () => {
    function stats(kernel_packets: number, running = true) {
      return {
        engine: { kernel_packets },
        service: { running },
      } as unknown as SuricataStatus;
    }

    function open() {
      live.connect();
      FakeSocket.last!.open();
      return FakeSocket.last!;
    }

    it('says nothing about the sensor until two readings can be compared', () => {
      const socket = open();
      socket.send('suricata.stats', stats(1000));
      // One reading is a number, not a trend. Calling it "live" here would be
      // a guess and calling it "no traffic" would be a false alarm.
      expect(live.packetsMoving()).toBeNull();
      expect(live.sensor()).toBe('live');
    });

    it('is live while the packet counter moves', () => {
      const socket = open();
      socket.send('suricata.stats', stats(1000));
      socket.send('suricata.stats', stats(1400));
      expect(live.sensor()).toBe('live');
    });

    it('warns when the engine runs and the counter stands still', () => {
      // The failure this exists for: service active, counters green, nothing
      // being inspected. Twelve hours of it here, with every screen normal.
      const socket = open();
      socket.send('suricata.stats', stats(1000));
      socket.send('suricata.stats', stats(1000));
      expect(live.sensor()).toBe('idle');
    });

    it('treats a counter that went backwards as a restart, not a stall', () => {
      // Counters start from zero again. Reporting that as "seeing nothing"
      // would put the panel in a warning state after every engine restart,
      // which is how somebody learns to ignore the warning.
      const socket = open();
      socket.send('suricata.stats', stats(90000));
      socket.send('suricata.stats', stats(120));
      expect(live.sensor()).toBe('live');
    });

    it('a stopped engine outranks a standing counter', () => {
      const socket = open();
      socket.send('suricata.stats', stats(1000, false));
      socket.send('suricata.stats', stats(1000, false));
      expect(live.sensor()).toBe('stopped');
    });

    it('a paused view is not a sensor problem', () => {
      const socket = open();
      socket.send('suricata.stats', stats(1000));
      socket.send('suricata.stats', stats(1000));
      live.toggleStreaming();
      expect(live.sensor()).toBe('paused');
    });

    it('a dropped socket outranks everything and forgets the comparison', () => {
      // A count from before the break against one from after it is not a
      // measurement, and would call a stalled sensor healthy.
      const socket = open();
      socket.send('suricata.stats', stats(1000));
      socket.drop();
      expect(live.sensor()).toBe('disconnected');
      expect(live.packetsMoving()).toBeNull();
    });

    it('does not call the engine stopped before it has been asked', () => {
      // `service` comes from REST, so it is absent for a moment on a fresh
      // page. Absent is not stopped.
      const socket = open();
      socket.send('suricata.stats', { engine: { kernel_packets: 10 } } as any);
      socket.send('suricata.stats', { engine: { kernel_packets: 20 } } as any);
      expect(live.sensor()).toBe('live');
    });
  });

  it('reconnects after a drop, with a growing wait', () => {
    jasmine.clock().install();
    live.connect();
    const first = FakeSocket.last;
    first!.open();
    first!.drop();
    expect(live.connected()).toBeFalse();

    jasmine.clock().tick(1000);
    expect(FakeSocket.last).not.toBe(first);

    FakeSocket.last!.drop();
    jasmine.clock().tick(1000);
    expect(FakeSocket.last!.readyState).toBe(3);   // still waiting, the delay grew
    jasmine.clock().tick(1000);
    expect(FakeSocket.last!.readyState).toBe(0);
    jasmine.clock().uninstall();
  });

  it('does not reconnect after a deliberate disconnect', () => {
    jasmine.clock().install();
    live.connect();
    FakeSocket.last!.open();
    const socket = FakeSocket.last;
    live.disconnect();
    jasmine.clock().tick(60000);
    expect(FakeSocket.last).toBe(socket);
    expect(socket!.closed).toBeTrue();
    jasmine.clock().uninstall();
  });

  it('stops retrying when the socket is closed because the session ended', () => {
    // Retrying cannot succeed - the handshake reads the same cookie that was
    // just invalidated. The panel used to back off to fifteen seconds and sit
    // there saying "disconnected", which describes the socket and not the
    // reason. The 401 interceptor is what asks the person to sign in again.
    jasmine.clock().install();
    live.connect();
    FakeSocket.last!.open();
    const socket = FakeSocket.last;

    FakeSocket.last!.drop(4001);

    jasmine.clock().tick(60000);
    expect(FakeSocket.last).toBe(socket);
    expect(live.sessionEnded()).toBeTrue();
    jasmine.clock().uninstall();
  });

  it('keeps retrying after an ordinary drop', () => {
    // The distinction is the whole point of using a code of our own: a network
    // blip must not log anybody out.
    jasmine.clock().install();
    live.connect();
    FakeSocket.last!.open();
    const socket = FakeSocket.last;

    FakeSocket.last!.drop();

    jasmine.clock().tick(1000);
    expect(FakeSocket.last).not.toBe(socket);
    expect(live.sessionEnded()).toBeFalse();
    jasmine.clock().uninstall();
  });


  describe('a restart the panel asked for', () => {
    // Switching the detection mode restarts the engine, and for about half a
    // minute the stream is down. Without this the chrome showed a red fault for
    // the whole of it, which an operator reported as the panel dropping them.

    it('is remembered while it is expected', () => {
      expect(live.restarting()).toBeFalse();
      live.expectRestart();
      expect(live.restarting()).toBeTrue();
    });

    it('gives up on the clock, not on the stream coming back', () => {
      // A restart that fails is exactly the case where the red state has to
      // return, and it is the case where the stream never comes back to clear
      // the flag. So the clock clears it and nothing else does.
      jasmine.clock().install();
      try {
        live.expectRestart(90_000);
        jasmine.clock().tick(89_000);
        expect(live.restarting()).toBeTrue();
        jasmine.clock().tick(2_000);
        expect(live.restarting()).toBeFalse();
      } finally {
        jasmine.clock().uninstall();
      }
    });

    it('a second restart extends the window rather than shortening it', () => {
      jasmine.clock().install();
      try {
        live.expectRestart(10_000);
        jasmine.clock().tick(9_000);
        live.expectRestart(10_000);
        jasmine.clock().tick(9_000);
        expect(live.restarting()).toBeTrue();   // the first timer did not fire
        jasmine.clock().tick(2_000);
        expect(live.restarting()).toBeFalse();
      } finally {
        jasmine.clock().uninstall();
      }
    });
  });
});
