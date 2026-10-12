import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { catchError, map, throwError } from 'rxjs';

import { Auth } from './auth';

/** Keeps unauthenticated visitors off every view but the sign-in screen. */
export const authGuard: CanActivateFn = () => {
  const auth = inject(Auth);
  const router = inject(Router);

  // First navigation of the session: the guard has to wait for /auth/state,
  // otherwise it would bounce a perfectly valid cookie to the login page.
  if (!auth.ready()) {
    return auth.refresh().pipe(
      map(() => (auth.signedIn() ? true : router.createUrlTree(['/login']))),
      catchError(() => [router.createUrlTree(['/login'])]),
    );
  }
  return auth.signedIn() ? true : router.createUrlTree(['/login']);
};

/** The mirror image: someone already signed in has no use for the login page. */
export const guestGuard: CanActivateFn = () => {
  const auth = inject(Auth);
  const router = inject(Router);

  if (!auth.ready()) {
    return auth.refresh().pipe(
      map(() => (auth.signedIn() ? router.createUrlTree(['/dashboard']) : true)),
      catchError(() => [true as const]),
    );
  }
  return auth.signedIn() ? router.createUrlTree(['/dashboard']) : true;
};

/** A session can die while the panel is open - the cookie expires, or someone
 *  changes the password elsewhere. Without this the views would just fill up
 *  with silent errors instead of asking the person to sign in again. */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(Auth);
  const router = inject(Router);

  return next(req).pipe(
    catchError((err: unknown) => {
      const isAuthCall = req.url.startsWith('/api/auth/');
      if (err instanceof HttpErrorResponse && err.status === 401 && !isAuthCall) {
        auth.forgetUser();
        router.navigate(['/login']);
      }
      return throwError(() => err);
    }),
  );
};
