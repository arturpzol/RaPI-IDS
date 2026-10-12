import { Routes } from '@angular/router';

import { authGuard, guestGuard } from './core/auth-guard';

/** Every view is lazy-loaded, so the startup bundle does not grow as the panel
 *  gains modules - which matters on a Raspberry Pi. */
export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  {
    path: 'login',
    title: 'Sign in | RaPi IDS Panel',
    canActivate: [guestGuard],
    loadComponent: () => import('./features/auth/login').then((m) => m.Login),
  },
  {
    path: 'dashboard',
    canActivate: [authGuard],
    title: 'Dashboard | RaPi IDS Panel',
    loadComponent: () => import('./features/dashboard/dashboard').then((m) => m.Dashboard),
  },
  {
    path: 'ids',
    canActivate: [authGuard],
    title: 'Intrusion detection | RaPi IDS Panel',
    loadComponent: () => import('./features/ids/ids').then((m) => m.Ids),
  },
  {
    path: 'setup',
    canActivate: [authGuard],
    title: 'Network setup | RaPi IDS Panel',
    loadComponent: () => import('./features/setup/setup').then((m) => m.Setup),
  },
  {
    path: 'system',
    canActivate: [authGuard],
    title: 'System | RaPi IDS Panel',
    loadComponent: () => import('./features/system/system').then((m) => m.System),
  },
  { path: '**', redirectTo: 'dashboard' },
];
