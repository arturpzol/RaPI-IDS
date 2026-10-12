import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';

import { Auth } from '../../core/auth';
import { Login } from './login';

/** The first screen anybody meets, and until now the only one with no tests.
 *
 *  What is checked here is what it says when the backend refuses, because the
 *  sentence is all the reader gets: the panel deliberately tells them nothing
 *  about which half of the credentials was wrong.
 */
describe('Login', () => {
  let fixture: ComponentFixture<Login>;
  let component: any;
  let auth: jasmine.SpyObj<Auth>;

  function build(configured = true) {
    auth.configured.set(configured);
    fixture = TestBed.createComponent(Login);
    component = fixture.componentInstance;
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  function fails(status: number, detail?: string) {
    auth.login.and.returnValue(throwError(() => ({ status, error: detail ? { detail } : {} })));
    auth.setup.and.returnValue(throwError(() => ({ status, error: detail ? { detail } : {} })));
  }

  beforeEach(() => {
    auth = jasmine.createSpyObj<Auth>('Auth', ['login', 'setup'], {
      configured: signal(true),
    });
    auth.login.and.returnValue(of({ user: { username: 'rapi' } } as any));
    auth.setup.and.returnValue(of({ user: { username: 'rapi' } } as any));
    TestBed.configureTestingModule({
      providers: [{ provide: Auth, useValue: auth }, provideRouter([])],
    });
  });

  afterEach(() => fixture?.destroy());

  it('explains a refused password length on the sign-in screen too', () => {
    // auth_router sends the same Credentials model for both screens, with
    // min_length=12 on the password, so signing in with a shorter one comes
    // back 422 before any hash is checked. Saying "the panel could not read
    // that request" there tells the reader nothing they can act on.
    fails(422);
    build();
    component.username = 'rapi';
    component.password = 'short';
    component.submit();
    expect(component.error()).toContain('12 characters');
  });

  it('does not call a refused control character a length problem', () => {
    // Both rules answer 422, and "needs at least 12 characters" on a pasted
    // password with a tab in it leaves somebody retyping the same thing.
    auth.login.and.returnValue(throwError(() => ({
      status: 422,
      error: { detail: [{ type: 'value_error', loc: ['body', 'password'],
                          msg: 'Value error, The password cannot contain control characters such as a line break' }] },
    })));
    build();
    component.username = 'rapi';
    component.password = 'a password\twith a tab';
    component.submit();
    expect(component.error()).toContain('control characters');
    expect(component.error()).not.toContain('12 characters');
  });

  it('says which field is too long instead of talking about the password', () => {
    // username has max_length=64 on the backend, and every 422 used to read as
    // "the password needs at least 12 characters".
    auth.setup.and.returnValue(throwError(() => ({
      status: 422,
      error: { detail: [{ type: 'string_too_long', loc: ['body', 'username'],
                          msg: 'String should have at most 64 characters' }] },
    })));
    build(false);
    component.username = 'u'.repeat(65);
    component.password = 'a password that is long enough';
    component.confirm = 'a password that is long enough';
    component.submit();
    expect(component.error()).toContain('username');
    expect(component.error()).not.toContain('12 characters');
  });

  it('keeps the two boxes from taking more than the backend accepts', () => {
    const dom = build(false);
    const inputs = Array.from(dom.querySelectorAll('input')) as HTMLInputElement[];
    expect(inputs.find((i) => i.name === 'username')?.maxLength).toBe(64);
    expect(inputs.find((i) => i.name === 'password')?.maxLength).toBe(256);
  });

  it('passes on what the backend said when it said something', () => {
    fails(429, 'Too many attempts. Try again in 42 s.');
    build();
    component.username = 'rapi';
    component.password = 'a password that is long enough';
    component.submit();
    expect(component.error()).toContain('42 s');
  });

  it('tells a dead backend from a refused password', () => {
    fails(0);
    build();
    component.username = 'rapi';
    component.password = 'a password that is long enough';
    component.submit();
    expect(component.error()).toContain('No contact');
  });

  it('clears the password box after a failure', () => {
    // It is wrong, and it is the one field somebody retypes anyway.
    fails(401);
    build();
    component.username = 'rapi';
    component.password = 'a password that is long enough';
    component.submit();
    expect(component.password).toBe('');
  });

  it('says the SSH login is rapi, not the name typed above', () => {
    // Read as "the panel account also works over SSH", which it does not: the
    // password is shared, the login is the system account.
    const text = build(false).querySelector('.auth-hint')!.textContent!.replace(/\s+/g, ' ');
    expect(text).toContain('as the user rapi (not the username above)');
  });

  it('checks the two boxes match before it asks the backend anything', () => {
    build(false);
    component.username = 'rapi';
    component.password = 'a password that is long enough';
    component.confirm = 'something else';
    component.submit();
    expect(component.error()).toContain('do not match');
    expect(auth.setup).not.toHaveBeenCalled();
  });
});
