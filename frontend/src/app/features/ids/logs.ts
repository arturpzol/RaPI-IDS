import { Component, OnInit, computed, inject, output, signal } from '@angular/core';

import { Api } from '../../core/api';
import { BytesPipe } from '../../core/format';
import { LogSettings } from '../../core/models';

/** Logs screen: where the engine writes events and how much room that takes.
 *  The practical point - move constant writes off the boot card onto a disk.
 *
 *  This used to be a path field and nothing else, on the reasoning that what is
 *  mounted now says nothing about what will be mounted after a reboot, and that
 *  a suggestion is read as a recommendation. The objection was right; the answer
 *  was wrong. Asking somebody to type `/mnt/ssd/suricata` is asking them to know
 *  what the panel can see for itself. The volumes are listed, and the one thing
 *  the old comment was afraid of is answered on screen instead of avoided: a
 *  mount missing from /etc/fstab is offered with that said out loud. The field
 *  is still there, behind a disclosure, for the case nobody predicted. */
@Component({
  selector: 'app-logs',
  imports: [BytesPipe],
  templateUrl: './logs.html',
  styleUrl: './logs.css',
})
export class LogsView implements OnInit {
  private api = inject(Api);

  /** The log directory changed - the parent view refreshes the engine status. */
  readonly changed = output<void>();

  protected readonly data = signal<LogSettings | null>(null);
  protected readonly loading = signal(true);
  protected readonly busy = signal(false);
  protected readonly path = signal('');
  protected readonly message = signal<{ ok: boolean; text: string } | null>(null);

  protected readonly totalSize = computed(() =>
    (this.data()?.files ?? []).reduce((sum, f) => sum + f.size_bytes, 0),
  );

  /** Nothing to save while the field still holds the directory in use. */
  protected readonly unchanged = computed(() => {
    const typed = this.path().trim();
    return !typed || typed === this.data()?.log_dir;
  });

  ngOnInit(): void {
    this.load();
  }

  protected load(): void {
    this.loading.set(true);
    this.api.logSettings().subscribe({
      next: (s) => {
        this.fill(s);
        this.loading.set(false);
      },
      error: (err) => {
        this.loading.set(false);
        this.message.set({
          ok: false,
          text: err?.error?.detail ?? 'Could not fetch the log settings',
        });
      },
    });
  }

  /** Fill the field, but never overwrite a path somebody typed and lost to a
   *  failed save - retyping it is the last thing they want to do. */
  private fill(s: LogSettings): void {
    if (this.unchanged()) this.path.set(s.log_dir);
    this.data.set(s);
  }

  /** One click, no typing. Same path through the backend as the field below -
   *  validation, the engine restart and the logrotate entry all still apply. */
  protected moveTo(path: string): void {
    this.path.set(path);
    this.save();
  }

  protected save(): void {
    const current = this.data();
    const path = this.path().trim();
    if (this.busy() || !current || !path || path === current.log_dir) return;
    if (!confirm(
      `Write the logs to ${path} from now on?\n\n`
      + 'The engine will be restarted (a few seconds without traffic inspection).\n'
      + `The existing files stay in ${current.log_dir}. The panel does not delete them.`,
    )) return;

    this.busy.set(true);
    this.message.set(null);
    this.api.setLogDir(path).subscribe({
      next: (res) => {
        this.busy.set(false);
        this.path.set(res.log_dir);
        this.data.set(res.state);
        this.changed.emit();
        // The move and the engine restart are two outcomes, not one. The
        // directory can be in place while the restart timed out, and reporting
        // that as a plain success leaves somebody waiting for alerts from an
        // engine that is still coming up, or not coming up at all.
        this.message.set(res.restarted ? {
          ok: true,
          text: `Logs now go to ${res.log_dir}. Previous directory: ${res.previous_dir}.`,
        } : {
          ok: false,
          text: `Logs now go to ${res.log_dir}, but the engine did not restart cleanly: `
            + `${res.output || 'no output'}. Until it does, it is still writing to `
            + `${res.previous_dir}.`,
        });
      },
      error: (err) => {
        this.busy.set(false);
        this.message.set({
          ok: false,
          text: err?.error?.detail ?? 'Could not change the directory',
        });
        this.load();
      },
    });
  }
}
