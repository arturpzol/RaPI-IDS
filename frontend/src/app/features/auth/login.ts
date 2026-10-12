import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';

import { Auth } from '../../core/auth';

/** Sign-in, and on a fresh device the screen that claims it.
 *
 *  Both live in one component because they are the same form with a different
 *  verb: an unclaimed panel has nobody to sign in as, so offering a login box
 *  would only be a dead end.
 */
@Component({
  selector: 'panel-login',
  imports: [FormsModule],
  template: `
    <div class="auth-page">
      <form class="auth-card" (ngSubmit)="submit()">
        <div class="auth-brand">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path class="brand-shield" d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" />
            <path class="brand-pulse" d="M7 12.5h2.4l1.4-3.2 2.4 6 1.4-2.8H17" />
          </svg>
          <div>
            <h1>RaPi IDS Panel</h1>
            <p class="muted">{{ setupMode() ? 'Set up this device' : 'Sign in' }}</p>
          </div>
        </div>

        @if (setupMode()) {
          <p class="auth-note">
            This panel has no account yet. The first account you create owns it.
            After that, this screen becomes a normal sign-in.
          </p>
        }

        <label>
          <span>Username</span>
          <input name="username" [(ngModel)]="username" autocomplete="username"
                 autocapitalize="none" spellcheck="false" maxlength="64"
                 required autofocus />
        </label>

        <label>
          <span>Password</span>
          <input name="password" type="password" [(ngModel)]="password"
                 [attr.autocomplete]="setupMode() ? 'new-password' : 'current-password'"
                 maxlength="256" required />
        </label>

        @if (setupMode()) {
          <label>
            <span>Repeat password</span>
            <input name="confirm" type="password" [(ngModel)]="confirm"
                   autocomplete="new-password" maxlength="256" required />
          </label>
          <p class="auth-hint">
            At least 12 characters. On a freshly flashed device this password
            also opens SSH, as the user <strong>rapi</strong> (not the username
            above), unless a password was set when the card was prepared. The
            System page says which.
          </p>
        }

        @if (error(); as message) {
          <p class="auth-error" role="alert">{{ message }}</p>
        }

        <button class="btn btn-primary auth-submit" type="submit" [disabled]="busy()">
          {{ busy() ? 'Working...' : (setupMode() ? 'Create account' : 'Sign in') }}
        </button>
      </form>
    </div>
  `,
  styles: [`
    .auth-page {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1.5rem;
    }
    .auth-card {
      display: flex;
      flex-direction: column;
      gap: 0.85rem;
      width: 100%;
      max-width: 380px;
      padding: 1.6rem 1.5rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      background: linear-gradient(180deg, var(--bg-raised), var(--bg-elevated) 60%);
      box-shadow: var(--shadow-lg), var(--edge);
    }
    .auth-brand { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.3rem; }
    .auth-brand svg {
      width: 38px; height: 38px; flex-shrink: 0; padding: 6px;
      border-radius: var(--radius);
      background: linear-gradient(160deg, var(--accent-dim), transparent 70%);
      box-shadow: var(--edge);
      fill: none; stroke: var(--accent); stroke-width: 1.8;
      stroke-linecap: round; stroke-linejoin: round;
    }
    /* The same mark as the sidebar, the pulse cut in the card's own colour. */
    .auth-brand svg .brand-shield { fill: var(--accent); stroke: none; }
    .auth-brand svg .brand-pulse { stroke: var(--bg-raised); stroke-width: 1.9; }
    .auth-brand h1 { font-size: var(--fs-md); }
    .auth-brand p { margin: 0.1rem 0 0; font-size: var(--fs-sm); }

    .auth-note, .auth-hint {
      margin: 0;
      color: var(--text-muted);
      font-size: var(--fs-sm);
    }
    .auth-hint { color: var(--text-dim); font-size: var(--fs-xs); margin-top: -0.45rem; }

    label { display: flex; flex-direction: column; gap: 0.3rem; }
    label span { color: var(--text-muted); font-size: var(--fs-sm); font-weight: 500; }
    input { width: 100%; }

    .auth-error {
      margin: 0;
      padding: 0.5rem 0.7rem;
      border: 1px solid color-mix(in srgb, var(--danger) 45%, transparent);
      border-radius: var(--radius);
      background: color-mix(in srgb, var(--danger) 12%, transparent);
      color: var(--danger);
      font-size: var(--fs-sm);
    }
    .auth-submit { justify-content: center; margin-top: 0.3rem; padding: 0.55rem; }
  `],
})
export class Login {
  private auth = inject(Auth);
  private router = inject(Router);

  protected username = '';
  protected password = '';
  protected confirm = '';

  protected readonly busy = signal(false);
  protected readonly error = signal('');
  protected readonly setupMode = this.auth.configured() ? signal(false) : signal(true);

  protected submit(): void {
    if (this.busy()) return;
    this.error.set('');

    if (this.setupMode() && this.password !== this.confirm) {
      this.error.set('The passwords do not match.');
      return;
    }
    if (this.setupMode() && this.password.length < 12) {
      this.error.set('The password needs at least 12 characters.');
      return;
    }
    if (!this.username || !this.password) {
      this.error.set('Fill in both fields.');
      return;
    }

    this.busy.set(true);
    const request = this.setupMode()
      ? this.auth.setup(this.username, this.password)
      : this.auth.login(this.username, this.password);

    request.subscribe({
      next: () => {
        this.busy.set(false);
        // A device that has just been claimed has never been told what it is
        // plugged into, and that decides whether it sees anything at all. So the
        // first screen after the password is the one that asks.
        this.router.navigate([this.setupMode() ? '/setup' : '/dashboard']);
      },
      error: (err: HttpErrorResponse) => {
        this.busy.set(false);
        this.password = '';
        this.confirm = '';
        this.error.set(this.message(err));
      },
    });
  }

  private message(err: HttpErrorResponse): string {
    if (err.status === 0) return 'No contact with the panel backend.';
    if (err.status === 429) return err.error?.detail ?? 'Too many attempts. Wait a moment.';
    if (err.status === 409) return 'This panel already has an account. Reload the page.';
    // Both screens, because both send the same model: auth_router's
    // Credentials carries min_length=12 for the password, so signing in with
    // a shorter one is refused before any hash is checked. Written here as a
    // fact about this panel rather than about the account: every password it
    // ever accepted is at least that long, so a shorter one cannot be right.
    if (err.status === 422) {
      // Two rules can refuse a password here, and saying the wrong one leaves
      // somebody retyping a password that was never too short. The body is
      // FastAPI's list of validation errors, so it is read as text.
      const detail = JSON.stringify(err.error?.detail ?? '');
      if (detail.includes('control characters')) {
        return 'The password cannot contain tabs, line breaks or other control characters.';
      }
      if (detail.includes('"username"')) {
        return 'The username can be at most 64 characters.';
      }
      if (detail.includes('too_long')) {
        return 'The password can be at most 256 characters.';
      }
      return 'The password needs at least 12 characters.';
    }
    return err.error?.detail ?? 'Sign-in failed.';
  }
}
