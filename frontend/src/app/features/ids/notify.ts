import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { Api } from '../../core/api';
import { formatDateTime } from '../../core/format';
import { EmailSettings, EmailStatus } from '../../core/models';

/** Alert notifications by e-mail.
 *
 *  A panel nobody opens reports nothing, so this is the part that reaches out.
 *  The screen is built around the one decision that matters after "which
 *  server": how loud this is allowed to be. A sensor on a mirror port can raise
 *  hundreds of alerts an hour, and a mailbox with one message per alert gets a
 *  filter rule within a day and is never read again.
 */
@Component({
  selector: 'app-notify',
  imports: [FormsModule],
  templateUrl: './notify.html',
  styleUrl: './notify.css',
})
export class NotifyView implements OnInit {
  private api = inject(Api);

  protected readonly loading = signal(true);
  protected readonly busy = signal<string | null>(null);
  protected readonly status = signal<EmailStatus | null>(null);
  protected readonly message = signal<{ ok: boolean; text: string } | null>(null);
  protected readonly passwordSet = signal(false);

  /** Plain fields rather than a signal per input: this is a form, it is saved
   *  in one go, and ngModel wants something it can write to. */
  protected form: EmailSettings = blank();
  protected password = '';
  protected recipients = '';

  protected readonly securityOptions = [
    { value: 'starttls', label: 'STARTTLS (usually port 587)' },
    { value: 'ssl', label: 'TLS from the start (usually port 465)' },
    { value: 'none', label: 'None (only on a server you run yourself)' },
  ];

  /** Suricata counts severity the other way round: 1 is the most serious. */
  protected readonly severityOptions = [
    { value: 1, label: 'Critical only' },
    { value: 2, label: 'Critical and major' },
    { value: 3, label: 'Down to minor' },
    { value: 4, label: 'Everything, informational included' },
  ];

  protected readonly digestOptions = [
    { value: 0, label: 'Send immediately' },
    { value: 60, label: 'Every minute' },
    { value: 300, label: 'Every 5 minutes' },
    { value: 900, label: 'Every 15 minutes' },
    { value: 3600, label: 'Hourly' },
  ];

  /** The worst case this configuration allows, in messages a day. Worth saying
   *  out loud on the screen where the limits are set.
   *
   *  A method, not a computed: the form is a plain object because ngModel
   *  writes to it, so a computed would read it once and never notice a change.
   */
  protected ceiling(): number {
    return this.form.max_per_hour * 24;
  }

  ngOnInit(): void {
    this.load();
  }

  protected load(): void {
    this.loading.set(true);
    this.api.notifications().subscribe({
      next: (state) => {
        this.form = { ...state.settings };
        this.recipients = state.settings.recipients.join('\n');
        this.passwordSet.set(state.settings.password_set);
        this.password = '';
        this.status.set(state.status);
        this.loading.set(false);
      },
      error: (err) => {
        this.loading.set(false);
        this.message.set({
          ok: false,
          text: err?.error?.detail ?? 'Could not fetch the notification settings',
        });
      },
    });
  }

  protected save(): void {
    if (this.busy()) return;
    this.busy.set('save');
    this.message.set(null);
    this.api.saveNotifications({
      ...this.form,
      recipients: this.recipientList(),
      // Left out when blank, so the stored password stays where it is.
      ...(this.password ? { password: this.password } : {}),
    }).subscribe({
      next: (state) => {
        this.busy.set(null);
        this.password = '';
        this.passwordSet.set(state.settings.password_set);
        this.status.set(state.status);
        this.message.set({ ok: true, text: 'Saved.' });
      },
      error: (err) => {
        this.busy.set(null);
        this.message.set({ ok: false, text: err?.error?.detail ?? 'Could not save' });
      },
    });
  }

  /** Save first, then send: a test that passes on values the panel is not
   *  going to keep proves nothing. */
  protected sendTest(): void {
    if (this.busy()) return;
    this.busy.set('test');
    this.message.set(null);
    this.api.saveNotifications({
      ...this.form,
      recipients: this.recipientList(),
      ...(this.password ? { password: this.password } : {}),
    }).subscribe({
      next: (state) => {
        this.password = '';
        this.passwordSet.set(state.settings.password_set);
        this.api.testNotification().subscribe({
          next: (result) => {
            this.busy.set(null);
            this.status.set(result.status);
            this.message.set({
              ok: true,
              text: `Test message sent to ${this.recipientList().join(', ')}.`,
            });
          },
          error: (err) => {
            this.busy.set(null);
            this.load();
            this.message.set({
              ok: false,
              // Whatever the mail server said. "Authentication failed" is
              // something a person can act on; "could not send" is not.
              text: err?.error?.detail ?? 'The mail server did not take the message',
            });
          },
        });
      },
      error: (err) => {
        this.busy.set(null);
        this.message.set({ ok: false, text: err?.error?.detail ?? 'Could not save' });
      },
    });
  }

  protected readonly lastSent = computed(() => {
    const ts = this.status()?.last_sent_at;
    return ts ? formatDateTime(ts) : 'never';
  });

  protected recipientList(): string[] {
    return this.recipients.split(/[\n,]+/).map((line) => line.trim()).filter(Boolean);
  }

  protected clearPassword(): void {
    this.password = '';
    this.passwordSet.set(false);
    this.api.saveNotifications({ clear_password: true } as never).subscribe({
      next: () => this.message.set({ ok: true, text: 'Password removed.' }),
      error: () => this.load(),
    });
  }
}

function blank(): EmailSettings {
  return {
    enabled: false,
    host: '',
    port: 587,
    security: 'starttls',
    username: '',
    sender: '',
    recipients: [],
    min_severity: 2,
    digest_seconds: 300,
    max_per_hour: 6,
    password_set: false,
  };
}
