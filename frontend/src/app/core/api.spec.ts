import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { Api } from './api';

/** The endpoint each call goes to. Cheap to get wrong in a rename and invisible
 *  until a screen is empty in production. */
describe('Api', () => {
  let api: Api;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    api = TestBed.inject(Api);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('reads the log settings', () => {
    api.logSettings().subscribe();
    const request = http.expectOne('/api/suricata/logs');
    expect(request.request.method).toBe('GET');
    request.flush({});
  });

  it('sends the log directory as a path in the body', () => {
    api.setLogDir('/mnt/ssd/suricata').subscribe();
    const request = http.expectOne({ method: 'POST', url: '/api/suricata/logs/dir' });
    expect(request.request.body).toEqual({ path: '/mnt/ssd/suricata' });
    request.flush({});
  });

  it('leaves empty filters out of the query string', () => {
    // An empty severity sent as "" filters on the empty string and returns
    // nothing, which reads as "no alerts" rather than as a mistake.
    api.alerts({ severity: null, search: '', limit: 50 }).subscribe();
    const request = http.expectOne((r) => r.url === '/api/suricata/alerts');
    expect(request.request.params.has('severity')).toBeFalse();
    expect(request.request.params.has('search')).toBeFalse();
    expect(request.request.params.get('limit')).toBe('50');
    request.flush({});
  });

  it('previews a topology without saving it', () => {
    api.previewTopology('mirror', { capture: 'eth0' }).subscribe();
    const request = http.expectOne({ method: 'POST', url: '/api/network/topology' });
    expect(request.request.body.preview).toBeTrue();
    request.flush({});
  });

  it('saves a topology as a real write', () => {
    api.saveTopology('mirror', { capture: 'eth0' }).subscribe();
    const request = http.expectOne({ method: 'POST', url: '/api/network/topology' });
    expect(request.request.body.preview).toBeFalsy();
    request.flush({});
  });

  it('applies the capture layout with the home networks', () => {
    api.applyCapture(['192.168.1.0/24']).subscribe();
    const request = http.expectOne({ method: 'POST', url: '/api/network/apply' });
    expect(request.request.body).toEqual({ home_net: ['192.168.1.0/24'] });
    request.flush({});
  });
});
