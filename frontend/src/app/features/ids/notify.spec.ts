import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';

import { Api } from '../../core/api';
import { EmailState } from '../../core/models';
import { NotifyView } from './notify';

function state(overrides: Record<string, unknown> = {}): EmailState {
  return {
    settings: {
      enabled: true,
      host: 'smtp.example.net',
      port: 587,
      security: 'starttls',
      username: 'ids@example.net',
      sender: 'ids@example.net',
      recipients: ['someone@example.net'],
      min_severity: 2,
      digest_seconds: 300,
      max_per_hour: 6,
      password_set: true,
      ...(overrides['settings'] as object ?? {}),
    },
    status: {
      running: true,
      waiting: 0,
      held_back: 0,
      dropped: 0,
      sent_last_hour: 1,
      last_sent_at: 1_780_000_000,
      last_error: '',
      ...(overrides['status'] as object ?? {}),
    },
  } as EmailState;
}

describe('NotifyView', () => {
  let fixture: ComponentFixture<NotifyView>;
  let component: any;
  let api: jasmine.SpyObj<Api>;

  function build(loaded = state()) {
    api.notifications.and.returnValue(of(loaded));
    fixture = TestBed.createComponent(NotifyView);
    component = fixture.componentInstance;
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  beforeEach(() => {
    api = jasmine.createSpyObj<Api>('Api', [
      'notifications', 'saveNotifications', 'testNotification',
    ]);
    api.saveNotifications.and.returnValue(of(state()));
    api.testNotification.and.returnValue(of({ ok: true, status: state().status }));
    TestBed.configureTestingModule({ providers: [{ provide: Api, useValue: api }] });
  });

  it('says what the limit does to e-mail and what it does not do', () => {
    // Held back alerts leave the mail queue; only their count travels, and
    // only with the next message. "Not dropped" read as "will be e-mailed".
    const text = build().textContent!.replace(/\s+/g, ' ');
    expect(text).not.toContain('not dropped');
    expect(text).toContain('are not e-mailed');
    expect(text).toContain('stay in the panel');
  });

  it('fills the form from what is stored', () => {
    build();
    expect(component.form.host).toBe('smtp.example.net');
    expect(component.recipients).toBe('someone@example.net');
  });

  it('never shows the password, only that there is one', () => {
    const dom = build();
    expect(component.password).toBe('');
    expect(component.passwordSet()).toBeTrue();
    expect(dom.textContent).toContain('remove it');
  });

  it('leaves the password out of a save when the field is blank', () => {
    // The form cannot show what is stored, so a blank field means "keep it".
    build();
    component.save();
    expect(api.saveNotifications).toHaveBeenCalled();
    expect(api.saveNotifications.calls.mostRecent().args[0]['password']).toBeUndefined();
  });

  it('sends the password when one was typed', () => {
    build();
    component.password = 'new-secret';
    component.save();
    expect(api.saveNotifications.calls.mostRecent().args[0]['password']).toBe('new-secret');
  });

  it('reads recipients one per line and ignores the blanks', () => {
    build();
    component.recipients = 'a@example.net\n\nb@example.net, c@example.net\n';
    expect(component.recipientList()).toEqual(['a@example.net', 'b@example.net', 'c@example.net']);
  });

  it('saves before it tests, so the test proves something', () => {
    build();
    component.sendTest();
    expect(api.saveNotifications).toHaveBeenCalledBefore(api.testNotification);
    expect(component.message().ok).toBeTrue();
  });

  it('repeats what the mail server said when a test fails', () => {
    api.testNotification.and.returnValue(
      throwError(() => ({ error: { detail: '535 authentication failed' } })),
    );
    build();
    component.sendTest();
    expect(component.message().ok).toBeFalse();
    expect(component.message().text).toContain('535 authentication failed');
  });

  it('will not test without a server and somebody to send to', () => {
    const dom = build(state({ settings: { host: '', recipients: [] } }));
    const buttons = Array.from(dom.querySelectorAll('button'));
    const test = buttons.find((b) => b.textContent!.includes('test message')) as HTMLButtonElement;
    expect(test.disabled).toBeTrue();
  });

  it('says out loud how many messages a day this allows', () => {
    build();
    expect(component.ceiling()).toBe(6 * 24);
    component.form.max_per_hour = 2;
    expect(component.ceiling()).toBe(48);
  });

  it('shows the last failure rather than a working-looking screen', () => {
    const dom = build(state({ status: { last_error: 'Connection refused' } }));
    expect(dom.textContent).toContain('Connection refused');
  });

  it('says when alerts were dropped before reaching the sender', () => {
    const dom = build(state({ status: { dropped: 12 } }));
    expect(dom.textContent).toContain('12 alerts were dropped');
  });

  it('says never when nothing has been sent yet', () => {
    build(state({ status: { last_sent_at: null } }));
    expect(component.lastSent()).toBe('never');
  });

  it('reports settings it could not fetch', () => {
    api.notifications.and.returnValue(throwError(() => ({ error: { detail: 'no route' } })));
    fixture = TestBed.createComponent(NotifyView);
    component = fixture.componentInstance;
    fixture.detectChanges();
    expect(component.message().text).toContain('no route');
  });
});
