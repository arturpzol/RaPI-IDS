import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { HttpClient } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { Router, UrlTree } from '@angular/router';
import { provideRouter } from '@angular/router';
import { firstValueFrom, isObservable } from 'rxjs';

import { Auth } from './auth';
import { authGuard, authInterceptor, guestGuard } from './auth-guard';

/** Sessions. The credential itself never appears here: it is an HttpOnly
 *  cookie, so the browser attaches it and this code cannot read it. */
describe('Auth', () => {
  let auth: Auth;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    });
    auth = TestBed.inject(Auth);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('starts out knowing nothing, which is not the same as signed out', () => {
    expect(auth.ready()).toBeFalse();
    expect(auth.signedIn()).toBeFalse();
  });

  it('picks the user up from the session cookie', () => {
    auth.refresh().subscribe();
    http.expectOne('/api/auth/state').flush({ configured: true, user: { username: 'admin' } });
    expect(auth.signedIn()).toBeTrue();
    expect(auth.user()!.username).toBe('admin');
  });

  it('reports a panel that has never been claimed', () => {
    auth.refresh().subscribe();
    http.expectOne('/api/auth/state').flush({ configured: false, user: null });
    expect(auth.configured()).toBeFalse();
    expect(auth.ready()).toBeTrue();
  });

  it('a backend it cannot reach still leaves the guard able to decide', () => {
    auth.refresh().subscribe({ error: () => undefined });
    http.expectOne('/api/auth/state').error(new ProgressEvent('offline'));
    expect(auth.ready()).toBeTrue();
    expect(auth.signedIn()).toBeFalse();
  });

  it('signing in never sends the password anywhere but the login route', () => {
    auth.login('admin', 'secret').subscribe();
    const request = http.expectOne('/api/auth/login');
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({ username: 'admin', password: 'secret' });
    request.flush({ user: { username: 'admin' } });
    expect(auth.signedIn()).toBeTrue();
  });

  it('sends the person back to the sign-in page when a session dies mid-session', async () => {
    // The cookie expires, or the password changes elsewhere. Without this the
    // views fill up with silent errors instead of asking for a sign-in.
    auth.refresh().subscribe();
    http.expectOne('/api/auth/state').flush({ configured: true, user: { username: 'admin' } });
    const router = TestBed.inject(Router);
    const navigate = spyOn(router, 'navigate');

    const client = TestBed.inject(HttpClient);
    client.get('/api/suricata/status').subscribe({ error: () => undefined });
    http.expectOne('/api/suricata/status').flush('', { status: 401, statusText: 'Unauthorized' });

    expect(auth.signedIn()).toBeFalse();
    expect(navigate).toHaveBeenCalledWith(['/login']);
  });

  it('a rejected sign-in does not bounce the login page to itself', () => {
    const router = TestBed.inject(Router);
    const navigate = spyOn(router, 'navigate');
    auth.login('admin', 'wrong').subscribe({ error: () => undefined });
    http.expectOne('/api/auth/login').flush('', { status: 401, statusText: 'Unauthorized' });
    expect(navigate).not.toHaveBeenCalled();
  });
});

describe('route guards', () => {
  let auth: Auth;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    auth = TestBed.inject(Auth);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  function run(guard: typeof authGuard) {
    return TestBed.runInInjectionContext(() => guard(null as any, null as any));
  }

  it('waits for the first answer instead of bouncing a valid cookie', async () => {
    const result = run(authGuard);
    expect(isObservable(result)).toBeTrue();
    // The guard is a cold observable: nothing is requested until it is
    // subscribed, so the answer is flushed after that and not before.
    const decision = firstValueFrom(result as any);
    http.expectOne('/api/auth/state').flush({ configured: true, user: { username: 'admin' } });
    expect(await decision).toBeTrue();
  });

  it('sends a visitor with no session to the sign-in page', async () => {
    const decision = firstValueFrom(run(authGuard) as any);
    http.expectOne('/api/auth/state').flush({ configured: true, user: null });
    expect(await decision).toBeInstanceOf(UrlTree);
  });

  it('decides on the spot once the session is known', () => {
    auth.refresh().subscribe();
    http.expectOne('/api/auth/state').flush({ configured: true, user: { username: 'admin' } });
    expect(run(authGuard)).toBeTrue();
    expect(run(guestGuard)).toBeInstanceOf(UrlTree);
  });

  it('leaves the sign-in page reachable when nobody is signed in', () => {
    auth.refresh().subscribe();
    http.expectOne('/api/auth/state').flush({ configured: true, user: null });
    expect(run(guestGuard)).toBeTrue();
  });
});
