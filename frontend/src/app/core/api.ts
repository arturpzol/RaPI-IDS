import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

import {
  Alert, AlertFilters, AlertPage, AlertSummary, GeoSummary, LiveEvent, ModuleInfo,
  EmailSettings, EmailState, EmailStatus,
  LogDirResult, LogSettings, NetworkInterface, Protection, ProtectionResult,
  LoadHistory, SshAccess, SuricataStatus, SystemInfo, SystemMetrics,
  ApplyResult, TopologySaved, TopologyState,
} from './models';

/** Every REST call of the panel. Paths are relative - in dev `ng serve` proxies
 *  them (proxy.conf.json), in production the backend also serves the frontend. */
@Injectable({ providedIn: 'root' })
export class Api {
  private http = inject(HttpClient);
  private base = '/api';

  // --- core ---
  modules(): Observable<{ modules: ModuleInfo[] }> {
    return this.http.get<{ modules: ModuleInfo[] }>(`${this.base}/modules`);
  }

  health(): Observable<{ status: string; version: string; ws_clients: number }> {
    return this.http.get<{ status: string; version: string; ws_clients: number }>(
      `${this.base}/health`,
    );
  }

  // --- IDS module ---
  suricataStatus(): Observable<SuricataStatus> {
    return this.http.get<SuricataStatus>(`${this.base}/suricata/status`);
  }

  alerts(filters: AlertFilters = {}): Observable<AlertPage> {
    let params = new HttpParams();
    for (const [key, value] of Object.entries(filters)) {
      if (value !== null && value !== undefined && value !== '') {
        params = params.set(key, String(value));
      }
    }
    return this.http.get<AlertPage>(`${this.base}/suricata/alerts`, { params });
  }

  alert(id: number): Observable<Alert> {
    return this.http.get<Alert>(`${this.base}/suricata/alerts/${id}`);
  }

  ackAlert(id: number, value = true): Observable<{ id: number; acknowledged: boolean }> {
    return this.http.post<{ id: number; acknowledged: boolean }>(
      `${this.base}/suricata/alerts/${id}/ack`, null, { params: { value } },
    );
  }

  /** Clears the review queue. The server picks the cutoff, so alerts arriving
   *  while this runs stay unacknowledged. */
  ackAllAlerts(): Observable<{ acknowledged: number }> {
    return this.http.post<{ acknowledged: number }>(
      `${this.base}/suricata/alerts/ack-all`, null,
    );
  }

  summary(hours = 24): Observable<AlertSummary> {
    return this.http.get<AlertSummary>(`${this.base}/suricata/summary`, {
      params: { hours },
    });
  }

  geo(hours = 24): Observable<GeoSummary> {
    return this.http.get<GeoSummary>(`${this.base}/suricata/geo`, {
      params: { hours },
    });
  }

  recentEvents(limit = 100, eventType?: string): Observable<{ items: LiveEvent[]; buffer_size: number }> {
    let params = new HttpParams().set('limit', limit);
    if (eventType) params = params.set('event_type', eventType);
    return this.http.get<{ items: LiveEvent[]; buffer_size: number }>(
      `${this.base}/suricata/events/recent`, { params },
    );
  }

  protection(): Observable<Protection> {
    return this.http.get<Protection>(`${this.base}/suricata/protection`);
  }

  /** Switch between reading a copy of the traffic and carrying it. Its own call
   *  rather than a field on the category form: it restarts the engine. */
  setProtectionMode(block: boolean): Observable<{ ok: boolean; output: string }> {
    return this.http.post<{ ok: boolean; output: string }>(
      `${this.base}/suricata/protection/mode`, { block },
    );
  }

  /** Save the protection screen: the categories and the informational rating
   *  in one call, because both end in the same disable.conf and one rebuild. */
  setProtectionCategories(
    categories: Record<string, boolean>, informational?: boolean,
  ): Observable<ProtectionResult> {
    return this.http.post<ProtectionResult>(
      `${this.base}/suricata/protection/categories`,
      { categories, informational: informational ?? null },
    );
  }

  muteSignature(signatureId: number): Observable<ProtectionResult> {
    return this.http.post<ProtectionResult>(
      `${this.base}/suricata/protection/mute`, { signature_id: signatureId },
    );
  }

  unmuteSignature(signatureId: number): Observable<ProtectionResult> {
    return this.http.delete<ProtectionResult>(
      `${this.base}/suricata/protection/mute/${signatureId}`,
    );
  }

  /** Keep alerting on one signature and never drop it. */
  allowSignature(signatureId: number): Observable<ProtectionResult> {
    return this.http.post<ProtectionResult>(
      `${this.base}/suricata/protection/allow`, { signature_id: signatureId },
    );
  }

  unallowSignature(signatureId: number): Observable<ProtectionResult> {
    return this.http.delete<ProtectionResult>(
      `${this.base}/suricata/protection/allow/${signatureId}`,
    );
  }

  /** Rebuild the rule set from what is stored, changing nothing. */
  rebuildProtection(): Observable<ProtectionResult> {
    return this.http.post<ProtectionResult>(`${this.base}/suricata/protection/rebuild`, {});
  }

  logSettings(): Observable<LogSettings> {
    return this.http.get<LogSettings>(`${this.base}/suricata/logs`);
  }

  setLogDir(path: string): Observable<LogDirResult> {
    return this.http.post<LogDirResult>(`${this.base}/suricata/logs/dir`, { path });
  }


  notifications(): Observable<EmailState> {
    return this.http.get<EmailState>(`${this.base}/suricata/notify`);
  }

  /** Partial update: whatever is left out keeps its stored value, which is how
   *  the password survives a form that cannot show it. */
  saveNotifications(settings: Partial<EmailSettings> & { password?: string }):
      Observable<EmailState> {
    return this.http.post<EmailState>(`${this.base}/suricata/notify`, settings);
  }

  testNotification(): Observable<{ ok: boolean; status: EmailStatus }> {
    return this.http.post<{ ok: boolean; status: EmailStatus }>(
      `${this.base}/suricata/notify/test`, null,
    );
  }

  updateRules(): Observable<{ ok: boolean; output: string }> {
    return this.http.post<{ ok: boolean; output: string }>(
      `${this.base}/suricata/rules/update`, null,
    );
  }

  serviceAction(action: 'reload'): Observable<{ ok: boolean; output: string }> {
    return this.http.post<{ ok: boolean; output: string }>(
      `${this.base}/suricata/service/${action}`, null,
    );
  }

  engineLog(lines = 200): Observable<{ path: string; lines: string[] }> {
    return this.http.get<{ path: string; lines: string[] }>(
      `${this.base}/suricata/log`, { params: { lines } },
    );
  }

  // --- system module ---
  systemInfo(): Observable<SystemInfo> {
    return this.http.get<SystemInfo>(`${this.base}/system/info`);
  }

  sshAccess(): Observable<SshAccess> {
    return this.http.get<SshAccess>(`${this.base}/system/ssh`);
  }

  systemMetrics(): Observable<SystemMetrics> {
    return this.http.get<SystemMetrics>(`${this.base}/system/metrics`);
  }

  systemHistory(hours = 1): Observable<LoadHistory> {
    return this.http.get<LoadHistory>(`${this.base}/system/history`, {
      params: { hours },
    });
  }

  network(): Observable<{ interfaces: NetworkInterface[] }> {
    return this.http.get<{ interfaces: NetworkInterface[] }>(`${this.base}/system/network`);
  }

  // --- network topology ---
  topology(): Observable<TopologyState> {
    return this.http.get<TopologyState>(`${this.base}/network/topology`);
  }

  saveTopology(profile: string, roles: Record<string, string>): Observable<TopologySaved> {
    return this.http.post<TopologySaved>(`${this.base}/network/topology`, { profile, roles });
  }

  homeNetSuggestion(): Observable<{ suggested: string[] }> {
    return this.http.get<{ suggested: string[] }>(`${this.base}/network/home-net`);
  }

  applyCapture(homeNet: string[]): Observable<ApplyResult> {
    return this.http.post<ApplyResult>(`${this.base}/network/apply`, { home_net: homeNet });
  }


  /** Same validation and the same warnings, nothing written. */
  previewTopology(profile: string, roles: Record<string, string>): Observable<TopologySaved> {
    return this.http.post<TopologySaved>(
      `${this.base}/network/topology`, { profile, roles, preview: true },
    );
  }
}
