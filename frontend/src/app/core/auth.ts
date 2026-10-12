import { HttpClient } from '@angular/common/http';
import { Injectable, computed, inject, signal } from '@angular/core';
import { Observable, tap } from 'rxjs';

export interface PanelUser {
  username: string;
}

interface AuthState {
  configured: boolean;
  user: PanelUser | null;
}

/** Who is signed in, and whether the panel has been claimed at all.
 *
 *  The credential itself never passes through here: it is an HttpOnly cookie,
 *  so the browser attaches it and this code cannot read it. That is the point -
 *  script injected into the panel has nothing to steal.
 */
@Injectable({ providedIn: 'root' })
export class Auth {
  private http = inject(HttpClient);

  readonly user = signal<PanelUser | null>(null);
  /** False until the first account exists - the panel then asks for one. */
  readonly configured = signal(true);
  /** Guards must not decide anything before the first answer arrives. */
  readonly ready = signal(false);

  readonly signedIn = computed(() => this.user() !== null);

  /** Resolves once, then leaves `ready` true for the rest of the session. */
  refresh(): Observable<AuthState> {
    return this.http.get<AuthState>('/api/auth/state').pipe(
      tap({
        next: (state) => {
          this.configured.set(state.configured);
          this.user.set(state.user);
          this.ready.set(true);
        },
        // A backend that cannot be reached is not the same as being signed out,
        // but there is nothing useful to show either way - let the sign-in
        // screen carry the error.
        error: () => {
          this.user.set(null);
          this.ready.set(true);
        },
      }),
    );
  }

  login(username: string, password: string): Observable<{ user: PanelUser }> {
    return this.http.post<{ user: PanelUser }>('/api/auth/login', { username, password })
      .pipe(tap((res) => this.user.set(res.user)));
  }

  setup(username: string, password: string): Observable<{ user: PanelUser }> {
    return this.http.post<{ user: PanelUser }>('/api/auth/setup', { username, password })
      .pipe(tap((res) => {
        this.configured.set(true);
        this.user.set(res.user);
      }));
  }

  logout(): Observable<unknown> {
    return this.http.post('/api/auth/logout', {}).pipe(tap(() => this.user.set(null)));
  }

  /** Called by the 401 interceptor: the cookie expired or was revoked. */
  forgetUser(): void {
    this.user.set(null);
  }
}
