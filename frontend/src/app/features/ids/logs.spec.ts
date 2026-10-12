import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';

import { Api } from '../../core/api';
import { LogSettings, LogVolume } from '../../core/models';
import { LogsView } from './logs';

function settings(overrides: Partial<LogSettings> = {}): LogSettings {
  return {
    log_dir: '/var/log/suricata',
    panel_reads_from: '/var/log/suricata/eve.json',
    can_change: true,
    warnings: [],
    disk: { total: 1024 ** 3, free: 512 * 1024 ** 2, used: 512 * 1024 ** 2, percent: 50 },
    files: [{ name: 'eve.json', size_bytes: 2048, modified: 0 }],
    on_root: true,
    candidates: [],
    ...overrides,
  };
}

function volume(overrides: Partial<LogVolume> = {}): LogVolume {
  return {
    path: '/mnt/ssd/suricata',
    mount: '/mnt/ssd',
    device: '/dev/sda1',
    fstype: 'ext4',
    free: 40 * 1024 ** 3,
    total: 50 * 1024 ** 3,
    persistent: true,
    current: false,
    ...overrides,
  };
}

describe('LogsView', () => {
  let fixture: ComponentFixture<LogsView>;
  let api: jasmine.SpyObj<Api>;

  function build(state = settings()) {
    api.logSettings.and.returnValue(of(state));
    fixture = TestBed.createComponent(LogsView);
    fixture.detectChanges();
  }

  function input(): HTMLInputElement {
    return fixture.nativeElement.querySelector('.set-dir input');
  }

  function saveButton(): HTMLButtonElement {
    return fixture.nativeElement.querySelector('.set-dir button');
  }

  function type(value: string) {
    input().value = value;
    input().dispatchEvent(new Event('input'));
    fixture.detectChanges();
  }

  beforeEach(() => {
    api = jasmine.createSpyObj<Api>('Api', ['logSettings', 'setLogDir']);
    TestBed.configureTestingModule({ providers: [{ provide: Api, useValue: api }] });
  });

  it('shows the directory in use and what is in it', () => {
    build();
    const text = fixture.nativeElement.textContent;
    expect(text).toContain('/var/log/suricata');
    expect(text).toContain('1 files');
    expect(text).toContain('2.0 KB');
  });

  it('offers no list of candidate directories', () => {
    // A suggestion is read as a recommendation, and what is mounted now says
    // nothing about what will be mounted after the next boot.
    build();
    expect(fixture.nativeElement.querySelector('.targets')).toBeNull();
  });

  it('starts with the current directory in the field and nothing to save', () => {
    build();
    expect(input().value).toBe('/var/log/suricata');
    expect(saveButton().disabled).toBeTrue();
  });

  it('enables the button once the path is a different one', () => {
    build();
    type('/mnt/ssd/suricata');
    expect(saveButton().disabled).toBeFalse();
  });

  it('will not save an empty field', () => {
    build();
    type('   ');
    expect(saveButton().disabled).toBeTrue();
  });

  it('asks before restarting the engine, and does nothing if told no', () => {
    build();
    spyOn(window, 'confirm').and.returnValue(false);
    type('/mnt/ssd/suricata');
    saveButton().click();
    expect(api.setLogDir).not.toHaveBeenCalled();
  });

  it('saves the new path and reports where the logs went', () => {
    build();
    spyOn(window, 'confirm').and.returnValue(true);
    api.setLogDir.and.returnValue(of({
      ok: true,
      log_dir: '/mnt/ssd/suricata',
      previous_dir: '/var/log/suricata',
      restarted: true,
      output: '',
      state: settings({ log_dir: '/mnt/ssd/suricata' }),
    }));

    type('/mnt/ssd/suricata');
    saveButton().click();
    fixture.detectChanges();

    expect(api.setLogDir).toHaveBeenCalledWith('/mnt/ssd/suricata');
    expect(fixture.nativeElement.textContent).toContain('Logs now go to /mnt/ssd/suricata');
    expect(input().value).toBe('/mnt/ssd/suricata');
  });

  it('says so when the directory moved but the engine did not restart', () => {
    // Two outcomes, not one. The backend used to answer 500 here, which told
    // the operator nothing had happened while the move had in fact gone
    // through; reporting it as a plain success is the same lie the other way,
    // and leaves somebody waiting for alerts from an engine that is not up.
    build();
    spyOn(window, 'confirm').and.returnValue(true);
    api.setLogDir.and.returnValue(of({
      ok: false,
      log_dir: '/mnt/ssd/suricata',
      previous_dir: '/var/log/suricata',
      restarted: false,
      output: 'the engine did not finish restarting within 180s',
      state: settings({ log_dir: '/mnt/ssd/suricata' }),
    }));

    type('/mnt/ssd/suricata');
    saveButton().click();
    fixture.detectChanges();

    const text = fixture.nativeElement.textContent;
    expect(text).toContain('/mnt/ssd/suricata');
    expect(text).toContain('did not restart');
    expect(text).toContain('180s');
    expect(text).toContain('/var/log/suricata');
  });

  it('keeps what was typed when the save is refused', () => {
    // Otherwise a rejected path is wiped by the reload and has to be typed again.
    build();
    spyOn(window, 'confirm').and.returnValue(true);
    api.setLogDir.and.returnValue(
      throwError(() => ({ error: { detail: 'ProtectHome=true - not a place for logs' } })),
    );

    type('/home/rapi/logs');
    saveButton().click();
    fixture.detectChanges();

    expect(fixture.nativeElement.textContent).toContain('ProtectHome');
    expect(input().value).toBe('/home/rapi/logs');
  });

  it('locks the field when the panel cannot change the directory', () => {
    build(settings({ can_change: false, warnings: ['suricata.yaml does not include ...'] }));
    expect(input().disabled).toBeTrue();
    expect(saveButton().disabled).toBeTrue();
    expect(fixture.nativeElement.textContent).toContain('does not include');
  });

  it('says so when the settings cannot be read at all', () => {
    api.logSettings.and.returnValue(throwError(() => ({ error: { detail: 'no route' } })));
    fixture = TestBed.createComponent(LogsView);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('no route');
  });
});

describe('LogsView volumes', () => {
  let fixture: ComponentFixture<LogsView>;
  let api: jasmine.SpyObj<Api>;

  function build(state: LogSettings): HTMLElement {
    api.logSettings.and.returnValue(of(state));
    fixture = TestBed.createComponent(LogsView);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  beforeEach(() => {
    api = jasmine.createSpyObj<Api>('Api', ['logSettings', 'setLogDir']);
    TestBed.configureTestingModule({
      providers: [{ provide: Api, useValue: api }],
    });
  });

  afterEach(() => fixture?.destroy());

  it('offers a mounted volume as a button, not as a path to type', () => {
    // The whole point of the change: nobody should have to know that the disk
    // is at /mnt/ssd, when the panel can see it.
    //
    // The confirm() has to be stubbed even though the assertion is about the
    // call after it. Headless Chromium opens the real dialog and blocks the
    // renderer on it, karma stops getting a ping, and thirty seconds later the
    // whole run ends as "Disconnected" - at whichever test happened to be
    // running, which is never this one.
    spyOn(window, 'confirm').and.returnValue(true);
    api.setLogDir.and.returnValue(of({ ok: true, log_dir: '/mnt/ssd/suricata' } as any));
    const dom = build(settings({ candidates: [volume()] }));
    const button = dom.querySelector<HTMLButtonElement>('.volume .btn');
    expect(button?.textContent).toContain('Move logs here');
    button!.click();
    expect(api.setLogDir).toHaveBeenCalledWith('/mnt/ssd/suricata');
  });

  it('says out loud when a volume will not survive a reboot', () => {
    // Afterwards the mount point is an ordinary directory on the card again
    // and the engine keeps writing to it without a word.
    const dom = build(settings({ candidates: [volume({ persistent: false })] }));
    expect(dom.querySelector('.warn-inline')?.textContent).toContain('fstab');
  });

  it('states the volume in use instead of offering it again', () => {
    const dom = build(settings({
      on_root: false, log_dir: '/mnt/ssd/suricata3',
      candidates: [volume({ current: true })],
    }));
    expect(dom.querySelector('.volume .btn')).toBeNull();
    expect(dom.textContent).toContain('logs are here');
  });

  it('drops the call to action once the logs are off the boot card', () => {
    const dom = build(settings({ on_root: false, candidates: [volume({ current: true })] }));
    expect(dom.textContent).not.toContain('Move the logs off the boot card');
  });

  it('does not claim a separate filesystem is a separate disk', () => {
    // The backend compares filesystems, and a second partition of the boot
    // card is a different filesystem on the same card.
    const dom = build(settings({ on_root: false, candidates: [volume({ current: true })] }));
    const text = dom.textContent!.replace(/\s+/g, ' ');
    expect(text).not.toContain('not on the card');
    expect(text).toContain('a second partition of the same card still takes every write');
  });

  it('keeps the free-text path, out of the way', () => {
    // It answers a question almost nobody has, and having it first made the
    // common case look complicated.
    const dom = build(settings({ candidates: [volume()] }));
    expect(dom.querySelector('details.advanced .set-dir input')).toBeTruthy();
  });

  it('says what to do when there is nothing to move to', () => {
    const dom = build(settings({ candidates: [] }));
    expect(dom.querySelector('.empty')?.textContent).toContain('Attach a disk');
  });
});
