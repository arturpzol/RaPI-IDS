import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';

import { Api } from '../../core/api';
import {
  ApplyResult, NetworkLink, TopologyProfile, TopologyState,
} from '../../core/models';
import { TopologyDiagram } from '../../shared/topology-diagram';

/** How the Pi is wired into the network, chosen once and revisited when the
 *  cabling changes.
 *
 *  This exists because the honest answer to "why does the panel show nothing" is
 *  almost always "because nothing is reaching it", and that has never been
 *  written down anywhere the owner of the device would look. A device sold as an
 *  IDS that quietly watches only itself is worse than one that says so on the
 *  first screen.
 *
 *  Nothing here reconfigures the engine yet. The choice is recorded and the
 *  panel says what still has to happen, which is a smaller promise than the
 *  screen could make and one it can actually keep.
 */
@Component({
  selector: 'app-setup',
  imports: [FormsModule, TopologyDiagram],
  templateUrl: './setup.html',
  styleUrl: './setup.css',
})
export class Setup implements OnInit {
  private api = inject(Api);
  private router = inject(Router);

  protected readonly stepLabels = ['Layout', 'Interfaces', 'Home networks', 'Apply', 'Done'];

  protected readonly state = signal<TopologyState | null>(null);
  protected readonly step = signal(1);
  protected readonly chosen = signal('');
  protected readonly roles = signal<Record<string, string>>({});
  protected readonly warnings = signal<string[]>([]);
  protected readonly error = signal('');
  protected readonly busy = signal(false);

  /** Home networks, one per line. A text box rather than a list of detected
   *  subnets with checkboxes: a mirror port carries VLANs this machine has no
   *  address on, so the detected set is a starting point and never the answer. */
  protected homeNet = '';
  /** The field holds what was applied, so the suggestion must not replace it. */
  private homeNetFromStore = false;
  protected readonly applyResult = signal<ApplyResult | null>(null);

  protected readonly profiles = computed(() => this.state()?.profiles ?? []);

  protected readonly profile = computed<TopologyProfile | null>(
    () => this.profiles().find((p) => p.id === this.chosen()) ?? null,
  );

  /** Interfaces worth offering: what is left once the loopback, the bridges and
   *  the kernel's own inventions are gone. */
  protected readonly candidates = computed<NetworkLink[]>(
    () => (this.state()?.hardware.links ?? [])
      .filter((link) => link.kind === 'wired' || link.kind === 'wireless'),
  );

  /** True while what is on screen is not what the backend has stored.
   *
   *  This matters because Apply sends only the home networks: the layout and
   *  the interface roles it puts into effect are the ones the backend has
   *  stored, from save(). A screen that lets somebody pick a layout, jump to
   *  the last step and press Apply configures the engine with whatever was
   *  saved on some earlier visit, or fails with "No layout has been chosen
   *  yet" while a layout is plainly selected in front of them.
   *
   *  Comparing the two sides rather than tracking a dirty flag, because the
   *  flag would have to be cleared in five places and one of them would be
   *  missed. */
  protected readonly unsaved = computed(() => {
    const stored = this.state()?.current;
    if (!stored?.profile || stored.profile !== this.chosen()) return true;
    const here = this.roles();
    const there = stored.roles ?? {};
    const keys = new Set([...Object.keys(here), ...Object.keys(there)]);
    return [...keys].some((key) => (here[key] ?? '') !== (there[key] ?? ''));
  });

  /** The interface the engine listens on, as the summary names it.
   *
   *  What was applied wins over what was chosen: the inline layout has the
   *  engine listening on the bridge the panel built, which is not one of the
   *  two interfaces anybody picked on the previous screen. */
  protected readonly captureIface = computed(
    () => this.applyResult()?.interface
      || this.roles()['capture'] || this.roles()['bridge_a'] || '',
  );

  /** The engine is listening somewhere right now, and it is not necessarily
   *  where this screen has been told to look. */
  protected readonly engineMismatch = computed(() => {
    const engine = this.state()?.engine.interfaces ?? [];
    const capture = this.roles()['capture'] ?? this.roles()['bridge_a'] ?? '';
    if (!engine.length || !capture) return '';
    return engine.includes(capture) ? '' : engine.join(', ');
  });

  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    this.api.topology().subscribe({
      next: (state) => {
        this.state.set(state);
        const current = state.current;
        if (current.profile) {
          this.chosen.set(current.profile);
          this.roles.set({ ...current.roles });
        }
        // What was applied last, not a fresh guess from this Pi's addresses.
        // The field used to be filled with the guess every time, so applying
        // the wizard again quietly dropped any network or VLAN added by hand,
        // and HOME_NET decides whether most rules can fire at all. Wins over
        // the suggestion whichever of the two requests answers first.
        const applied = (current.home_net ?? '').replace(/^\[|\]$/g, '').trim();
        if (applied) {
          this.homeNet = applied.split(',').map((n) => n.trim()).filter(Boolean).join('\n');
          this.homeNetFromStore = true;
        }
      },
      error: (err: HttpErrorResponse) =>
        this.error.set(this.message(err, 'read what this Pi is connected to')),
    });

    this.api.homeNetSuggestion().subscribe({
      next: (result) => {
        if (!this.homeNet && !this.homeNetFromStore) this.homeNet = result.suggested.join('\n');
      },
      error: () => undefined,
    });
  }

  protected pick(profile: TopologyProfile): void {
    if (!profile.available) return;
    this.chosen.set(profile.id);
    this.warnings.set([]);
    this.roles.set(this.suggest(profile));
  }

  /** A first guess at which interface plays which part.
   *
   *  Capture goes to a wired interface that is not the one this browser arrived
   *  on, because that is the choice that does not cut anybody off. When there is
   *  only one wired interface it gets suggested anyway, with the warning that
   *  comes back from the backend attached to it.
   */
  private suggest(profile: TopologyProfile): Record<string, string> {
    const links = this.candidates();
    const wired = links.filter((l) => l.kind === 'wired');
    const management = this.state()?.hardware.management ?? '';
    const taken = new Set<string>();

    const take = (pool: NetworkLink[], prefer?: (l: NetworkLink) => boolean): string => {
      const free = pool.filter((l) => !taken.has(l.name));
      const pick = (prefer ? free.find(prefer) : undefined) ?? free[0];
      if (pick) taken.add(pick.name);
      return pick?.name ?? '';
    };

    const chosen: Record<string, string> = {};
    for (const { id } of profile.roles) {
      chosen[id] = id === 'management'
        ? take(links, (l) => l.name === management) || take(links)
        : take(wired, (l) => l.name !== management);
    }
    return chosen;
  }

  protected setRole(role: string, name: string): void {
    this.roles.update((current) => ({ ...current, [role]: name }));
    this.preview();
  }

  protected toStep(step: number): void {
    this.error.set('');
    if (step > 1 && !this.chosen()) return;
    // Past the interfaces step the backend is the source of truth, so getting
    // there means having agreed with it first.
    if (step > 2 && this.unsaved()) {
      this.error.set('Save the interfaces first: the engine is set up from what '
                     + 'the panel has stored, not from what is on this screen.');
      this.step.set(2);
      return;
    }
    this.step.set(step);
    if (step === 2) this.preview();
  }

  protected homeNetList(): string[] {
    return this.homeNet
      .split(/[\n,]+/)
      .map((line) => line.trim())
      .filter(Boolean);
  }

  /** Write the capture interface and the home networks into the engine, then
   *  restart it. The backend refuses before touching anything if this would
   *  take the panel off the network. */
  protected applyLayout(): void {
    if (this.busy()) return;
    // The last line of defence, because this is the call that reconfigures the
    // engine: what it applies comes from the stored layout, so applying an
    // unsaved one puts the capture on an interface nobody picked.
    if (this.unsaved()) {
      this.error.set('Save the interfaces first: this applies the layout the '
                     + 'panel has stored, not the one on this screen.');
      this.step.set(2);
      return;
    }
    this.busy.set(true);
    this.error.set('');
    this.applyResult.set(null);

    this.api.applyCapture(this.homeNetList()).subscribe({
      next: (result) => {
        this.busy.set(false);
        this.applyResult.set(result);
        this.load();
        if (result.ok) this.step.set(5);
      },
      error: (err: HttpErrorResponse) => {
        this.busy.set(false);
        this.error.set(this.message(err));
      },
    });
  }

  /** Ask the backend what this assignment would mean, without saving it.
   *
   *  Server side rather than worked out here: the warning that matters most is
   *  the one about handing away the interface this browser is talking through,
   *  and only the backend knows which one that is. */
  private preview(): void {
    const profile = this.profile();
    if (!profile) return;
    // A half-filled form is the normal state of this step - it is what the step
    // is for - and the backend refuses one, correctly. Asking anyway put "no
    // interface chosen for: Panel access" across the top of the page the moment
    // it opened, before anybody had touched a field. The empty select says the
    // same thing without reading as a fault.
    const roles = this.roles();
    if (profile.roles.some((role) => !roles[role.id])) {
      this.warnings.set([]);
      this.error.set('');
      return;
    }
    this.api.previewTopology(profile.id, roles).subscribe({
      next: (result) => {
        this.warnings.set(result.warnings);
        this.error.set('');
      },
      // A half-filled form is the normal state of this step, so a rejection is
      // shown where the field is, not as a page-level failure.
      error: (err: HttpErrorResponse) =>
        this.error.set(this.message(err, 'work out what this assignment would mean')),
    });
  }

  protected save(): void {
    const profile = this.profile();
    if (!profile || this.busy()) return;
    this.busy.set(true);
    this.error.set('');

    this.api.saveTopology(profile.id, this.roles()).subscribe({
      next: (result) => {
        this.busy.set(false);
        this.warnings.set(result.warnings);
        this.step.set(3);
        this.load();
      },
      error: (err: HttpErrorResponse) => {
        this.busy.set(false);
        this.error.set(this.message(err));
      },
    });
  }

  protected done(): void {
    this.router.navigate(['/dashboard']);
  }

  protected label(link: NetworkLink): string {
    const parts = [link.name, link.kind === 'wireless' ? 'Wi-Fi' : 'wired'];
    if (link.usb) parts.push('USB');
    if (link.speed_mbps) parts.push(`${link.speed_mbps} Mbps`);
    if (link.ipv4.length) parts.push(link.ipv4[0]);
    else if (link.carrier) parts.push('no address');
    if (!link.carrier) parts.push(link.blocked ? 'radio off' : 'no link');
    return parts.join(' · ');
  }

  protected roleLabel(role: string): string {
    return this.profile()?.roles.find((r) => r.id === role)?.label ?? role;
  }

  /** What to show when a request failed and said nothing useful.
   *
   *  `what` names the request, because this screen makes four of them and one
   *  sentence covered all four: a listen that failed reported that the layout
   *  could not be saved.
   */
  private message(err: HttpErrorResponse, what = 'save this layout'): string {
    if (err.status === 0) return 'No contact with the panel backend.';
    return err.error?.detail ?? `The panel could not ${what}.`;
  }
}
