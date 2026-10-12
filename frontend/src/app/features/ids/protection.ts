import { Component, OnInit, computed, inject, input, output, signal } from '@angular/core';
import { RouterLink } from '@angular/router';

import { Api } from '../../core/api';
import { Live } from '../../core/live';
import { DateTimePipe, NumberPipe } from '../../core/format';
import { Observable } from 'rxjs';

import { MutedSignature, Protection, ProtectionCategory, ProtectionResult } from '../../core/models';

/** Intrusion prevention screen: a handful of switches instead of 68k rules.
 *  All the configuration an ordinary user actually wants to touch. */
@Component({
  selector: 'app-protection',
  imports: [RouterLink, NumberPipe, DateTimePipe],
  templateUrl: './protection.html',
  styleUrl: './protection.css',
})
export class ProtectionView implements OnInit {
  private api = inject(Api);
  private live = inject(Live);

  /** Engine state - after a rebuild we reload it only when it is running. */
  readonly running = input<boolean>(false);
  /** The rule set changed - the parent view may refresh its counters. */
  readonly changed = output<void>();

  protected readonly data = signal<Protection | null>(null);
  protected readonly draft = signal<Record<string, boolean>>({});
  /** The informational switch, drafted like the categories and saved by the
   *  same button - both end in the same disable.conf and one rebuild. */
  protected readonly informational = signal(true);
  protected readonly loading = signal(true);
  /** 'save' | 'update' | 'unmute<sid>' - one flag guards every long action. */
  protected readonly busy = signal<string | null>(null);
  protected readonly message = signal<{ ok: boolean; text: string } | null>(null);
  /** What the mode switch said, shown in its own card. It shared the message
   *  at the foot of the page, far below the switch: the working note vanished
   *  and the error appeared off screen, which read as nothing happening. */
  protected readonly modeMessage = signal<{ ok: boolean; text: string } | null>(null);
  /** The switch in flight starts with a rebuild of the rule set. */
  protected readonly rebuildingFirst = signal(false);

  /** How many switches differ from the saved state - drives the button label. */
  protected readonly pendingCount = computed(() => {
    const current = this.data();
    const draft = this.draft();
    if (!current) return 0;
    const cats = current.categories.filter((c) => !c.locked && draft[c.id] !== c.enabled).length;
    return cats + (this.informational() === current.informational.enabled ? 0 : 1);
  });

  /** Categories the informational switch would gut, worst first.
   *
   *  Shown next to that switch rather than on every category row: this is the
   *  one place where somebody decides, and eight rows carrying a number that
   *  matters for three of them is eight rows nobody reads. The cut is not
   *  uniform - it takes 92 % of the reputation category and 0.5 % of malware -
   *  and a control that silently empties a category the operator deliberately
   *  left switched on is the kind of thing this panel exists to avoid. */
  protected readonly informationalImpact = computed(() => {
    const cats = this.data()?.categories ?? [];
    return cats
      .filter((c) => c.signatures > 0 && c.informational * 5 >= c.signatures * 2)
      .map((c) => ({
        name: c.name.toLowerCase(),
        percent: Math.round((c.informational / c.signatures) * 100),
      }))
      .sort((a, b) => b.percent - a.percent)
      .slice(0, 3);
  });

  protected readonly activeCategories = computed(() => {
    const draft = this.draft();
    const cats = this.data()?.categories ?? [];
    return cats.filter((c) => c.locked || draft[c.id]).length;
  });

  ngOnInit(): void {
    this.load();
  }

  protected load(): void {
    this.loading.set(true);
    this.api.protection().subscribe({
      next: (p) => {
        this.apply(p);
        this.loading.set(false);
      },
      error: (err) => {
        this.loading.set(false);
        this.message.set({
          ok: false,
          text: err?.error?.detail ?? 'Could not fetch the protection state',
        });
      },
    });
  }

  private apply(p: Protection): void {
    this.data.set(p);
    this.draft.set(Object.fromEntries(p.categories.map((c) => [c.id, c.enabled])));
    this.informational.set(p.informational.enabled);
  }

  protected toggleInformational(): void {
    if (this.busy()) return;
    this.informational.update((on) => !on);
  }

  protected toggle(cat: ProtectionCategory): void {
    if (cat.locked || this.busy()) return;
    this.draft.update((d) => ({ ...d, [cat.id]: !d[cat.id] }));
  }

  /** Turn blocking on or off.
   *
   *  Reloads the whole screen afterwards rather than patching the mode in
   *  place: the reason line, the drop count and the capture method all change
   *  together, and half of them updating is how a screen starts lying.
   */
  protected setMode(block: boolean): void {
    const current = this.data();
    if (!current || this.busy() || current.mode.id === (block ? 'ips' : 'ids')) return;
    // Both directions ask, and they ask different things.
    //
    // This started as a question on the way in only, on the grounds that going
    // back destroys nothing. That was wrong about which way is quiet. Switching
    // to blocking is loud: packets start disappearing and the sensor goes blind
    // to a mirror port. Switching back is silent - traffic keeps flowing, no
    // screen changes except a badge that vanishes, and an absent badge is not a
    // signal. On a device deployed inline that is protection ending with nobody
    // noticing, which is the same accident the other question exists for: two
    // clicks from a phone, and this one leaves no trace at all.
    //
    // The control is used a handful of times in a device's life, so the usual
    // objection - that people learn to dismiss dialogs - does not apply here.
    // Two questions, because the layout decides what this switch does.
    //
    // Inline, the forwarding moves from the kernel to the engine and back. The
    // cables do not change and the wiring diagram does not change, but the link
    // stops surviving a stopped engine, and that is the fact somebody has to
    // agree to before the traffic of other machines depends on it.
    const inline = current.mode.inline;
    const question = inline
      ? (block
        ? 'Hand the forwarding to the engine?\n\n'
          + 'The two cables stay where they are. What changes is who passes the '
          + 'frames: the kernel bridge stops and the engine does it, which is '
          + 'what makes a drop rule able to stop a packet.\n\n'
          + 'From then on this link depends on the engine. While it restarts, '
          + 'reloads or fails, nothing crosses. The swap itself is an outage of '
          + 'about as long as the engine takes to load its rules.'
        : 'Give the forwarding back to the kernel?\n\n'
          + 'Nothing will be blocked after this: the engine goes back to reading '
          + 'a copy while a kernel bridge passes the frames, so the link survives '
          + 'it stopping.\n\n'
          + 'Your categories and allowed signatures are kept, and block again the '
          + 'moment blocking is turned back on. The swap itself is an outage of '
          + 'about as long as the engine takes to load its rules.')
      : (block
        ? 'Switch the engine to blocking?\n\n'
          + 'It stops reading its capture interface and takes packets from a '
          + 'netfilter queue instead, so traffic that only passes a mirror port or '
          + 'a tap is no longer inspected at all.\n\n'
          + 'It also starts dropping: every signature in the enabled categories '
          + 'except the ones that only alert, and flows the engine '
          + 'cannot process, such as a stream picked up midway or one the '
          + 'exception policy cannot handle. The engine restarts.'
        : 'Switch the engine back to detection only?\n\n'
          + 'Nothing will be blocked after this. Traffic keeps flowing either way, '
          + 'so nothing on the network will show that protection has stopped.\n\n'
          + 'Your categories and allowed signatures are kept, and block again the '
          + 'moment blocking is turned back on. The engine restarts.');
    // A rule set behind the policy is rebuilt by the backend before it
    // switches. Said here because it is half a minute the operator would
    // otherwise spend looking at a switch that did not seem to move.
    const catchUp = block && current.mode.drop_pending > 0
      ? '\n\nThe rule set is rebuilt first, so that the enabled categories block. '
        + 'That adds about half a minute before the switch, and the link is not '
        + 'interrupted while it runs.'
      : '';
    this.rebuildingFirst.set(!!catchUp);
    if (!confirm(question + catchUp)) return;
    // Said before the request, not after: the stream drops while the engine is
    // coming back and the answer has not arrived yet, so the chrome would
    // otherwise show a red fault for the whole of that window.
    this.live.expectRestart();
    this.busy.set('mode');
    this.modeMessage.set(null);
    this.api.setProtectionMode(block).subscribe({
      next: () => {
        this.busy.set(null);
        this.modeMessage.set({
          ok: true,
          // Short on purpose: the paragraph under the switch already says how
          // this mode works, and saying it again right above it put the same
          // explanation on screen twice.
          text: block
            ? (inline ? 'Blocking is on. The engine carries this link now.' : 'Blocking is on.')
            : 'Blocking is off. Nothing is dropped.',
        });
        this.load();
      },
      error: (err) => {
        this.busy.set(null);
        // A mode change restarts the engine, so the request is the one call on
        // this screen that can die with the answer already true. status 0 is
        // the browser saying the connection went, not the device saying no -
        // and "The mode could not be changed" is then the opposite of what
        // happened. Ask, rather than assert.
        if (!err?.status) {
          this.modeMessage.set({
            ok: false,
            text: 'The panel lost contact while switching. The change may have '
              + 'gone through anyway, because the engine restarts as part of it. '
              + 'Reload this page in a few seconds to see which mode it is in.',
          });
          return;
        }
        this.modeMessage.set({
          ok: false,
          text: err?.error?.detail ?? 'The mode could not be changed.',
        });
      },
    });
  }

  protected revert(): void {
    const current = this.data();
    if (current) this.apply(current);
    this.message.set(null);
  }

  protected save(): void {
    const current = this.data();
    if (!current || this.busy()) return;
    const selection: Record<string, boolean> = {};
    for (const cat of current.categories) {
      if (!cat.locked) selection[cat.id] = this.draft()[cat.id];
    }

    this.busy.set('save');
    this.message.set(null);
    this.api.setProtectionCategories(selection, this.informational()).subscribe({
      next: (res) => {
        this.apply(res.state);
        this.changed.emit();
        if (!res.ok) {
          this.busy.set(null);
          this.message.set({ ok: false, text: this.tail(res.output) });
          return;
        }
        this.thenReload(
          'Saved, and the engine was reloaded.',
          'Rules saved, but the engine could not be reloaded. '
            + 'Do it by hand on the "Engine" tab.',
          'Saved. The new rule set takes effect once the engine is started.',
        );
      },
      error: (err) => {
        this.busy.set(null);
        this.message.set({
          ok: false,
          text: err?.error?.detail ?? 'Could not save the settings',
        });
      },
    });
  }

  /** Put a silenced signature back into the rule set. */
  protected unmute(entry: MutedSignature): void {
    this.rebuildWith('unmute' + entry.signature_id,
      this.api.unmuteSignature(entry.signature_id), {
        done: 'Restored, and the engine was reloaded.',
        stalled: 'Signature restored, but the engine could not be reloaded.',
        notRunning: 'Restored. It starts alerting once the engine is started.',
        failed: 'Could not restore the signature',
      });
  }

  /** Let the blocking policy drop an allowed signature again. */
  protected unallow(entry: MutedSignature): void {
    this.rebuildWith('unallow' + entry.signature_id,
      this.api.unallowSignature(entry.signature_id), {
        done: 'It blocks again, and the engine was reloaded.',
        stalled: 'Saved, but the engine could not be reloaded.',
        notRunning: 'Saved. It blocks once the engine is started.',
        failed: 'Could not change the signature',
      });
  }

  /** Bring a rule set that fell behind the blocking policy up to date. */
  protected rebuild(): void {
    this.rebuildWith('rebuild', this.api.rebuildProtection(), {
      done: 'Rebuilt, and the engine was reloaded.',
      stalled: 'Rebuilt, but the engine could not be reloaded.',
      notRunning: 'Rebuilt. The rules take effect once the engine is started.',
      failed: 'Could not rebuild the rule set',
    });
  }

  /** A request that rewrites the rule set, then the reload that makes it run. */
  private rebuildWith(
    key: string,
    request: Observable<ProtectionResult>,
    text: { done: string; stalled: string; notRunning: string; failed: string },
  ): void {
    if (this.busy()) return;
    this.busy.set(key);
    this.message.set(null);
    request.subscribe({
      next: (res) => {
        this.apply(res.state);
        this.changed.emit();
        if (!res.ok) {
          this.busy.set(null);
          this.message.set({ ok: false, text: this.tail(res.output) });
          return;
        }
        this.thenReload(text.done,
          text.stalled + ' Do it by hand on the "Engine" tab.', text.notRunning);
      },
      error: (err) => {
        this.busy.set(null);
        this.message.set({ ok: false, text: err?.error?.detail ?? text.failed });
      },
    });
  }

  protected updateSignatures(): void {
    if (this.busy()) return;
    if (!confirm('Download a fresh signature set? This can take a few minutes.')) return;
    this.busy.set('update');
    this.message.set(null);
    this.api.updateRules().subscribe({
      next: (res) => {
        this.load();
        this.changed.emit();
        const summary = this.tail(res.output);
        this.thenReload(
          'Signatures downloaded, and the engine was reloaded. ' + summary,
          'Signatures downloaded, but the engine could not be reloaded. '
            + 'Do it by hand on the "Engine" tab. ' + summary,
          'Signatures downloaded. They take effect once the engine is started. ' + summary,
        );
      },
      error: (err) => {
        this.busy.set(null);
        this.message.set({
          ok: false,
          text: err?.error?.detail ?? 'The signature update failed',
        });
      },
    });
  }

  /** Tell the engine to read the rule file again, and say what came of it.
   *
   *  Every button on this screen rewrites suricata.rules, and rewriting it is
   *  not the same as running it. Download was the one that skipped this and
   *  said nothing about it: a fresh set sat on disk, the message read
   *  "Signatures downloaded", and the engine went on inspecting traffic with
   *  the old one until somebody found the reload button on another tab.
   */
  private thenReload(done: string, stalled: string, notRunning: string): void {
    if (!this.running()) {
      this.busy.set(null);
      this.message.set({ ok: true, text: notRunning });
      return;
    }
    this.api.serviceAction('reload').subscribe({
      next: () => {
        this.busy.set(null);
        this.message.set({ ok: true, text: done });
      },
      error: () => {
        this.busy.set(null);
        this.message.set({ ok: false, text: stalled });
      },
    });
  }

  /** Out of the suricata-update output we only want the final summary line. */
  private tail(output: string): string {
    const lines = (output ?? '').trim().split('\n').filter((l) => l.trim());
    const summary = lines.reverse().find((l) => l.includes('Writing rules to'));
    return (summary ?? lines[0] ?? '').replace(/^\S+ -- \S+ - <\w+> -- /, '');
  }
}
