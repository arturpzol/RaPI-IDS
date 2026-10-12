/** Types mirroring the backend responses (backend/app). */

export interface ModuleInfo {
  id: string;
  name: string;
  description: string;
  icon: string;
  route: string;
  enabled: boolean;
  tags: string[];
  api_prefix: string;
}

export interface Alert {
  id: number;
  /** Unix seconds. The engine writes local time with an offset; the backend
   *  converts once on the way in so nothing here has to know its timezone. */
  ts: number;
  event_type: string;
  src_ip: string | null;
  src_port: number | null;
  dest_ip: string | null;
  dest_port: number | null;
  proto: string | null;
  app_proto: string | null;
  signature: string | null;
  signature_id: number | null;
  category: string | null;
  /** Suricata's own number, 1 worst. Kept because it is what the engine
   *  recorded, but not what the panel colours or filters by - see ET_SEVERITIES. */
  severity: number | null;
  /** ET's rating of the rule, null when it has none. This is the one to show. */
  et_severity: string | null;
  /** What the engine did with the packet: 'blocked' or 'allowed'. Only ever
   *  'blocked' while it is inline on a queue; reading a copy it can report and
   *  nothing else. Null on rows stored before the panel recorded it. */
  action: string | null;
  iface: string | null;
  /** Country of src_ip, or 'home' / 'private' / 'unknown'. */
  src_cc: string | null;
  acknowledged: boolean;
  raw?: Record<string, unknown>;
}

export interface AlertPage {
  total: number;
  limit: number;
  offset: number;
  items: Alert[];
}

export interface AlertFilters {
  limit?: number;
  offset?: number;
  /** An ET rating, or 'unrated'. See ET_SEVERITIES. */
  severity?: string | null;
  src_ip?: string | null;
  dest_ip?: string | null;
  src_cc?: string | null;
  signature_id?: number | null;
  search?: string | null;
  /** Last N hours. The cutoff is worked out by the backend, see the note there. */
  hours?: number | null;
  /** One calendar day, 'today' or 'yesterday', also resolved by the backend.
   *  The dashboard tiles count days, so a link from one has to ask for the
   *  same day rather than for a window that merely overlaps it. */
  day?: string | null;
  acknowledged?: boolean | null;
  /** 'alert' (the default the backend applies), 'diagnostic' or 'all'. The
   *  screen never sets it; it exists because the endpoint takes it. */
  kind?: string | null;
  /** Only alerts where the engine stopped the packet. */
  blocked?: boolean | null;
}

export interface CountRow {
  count: number;
}

export interface AlertSummary {
  window_hours: number;
  /** Width of one timeline bucket: 1 on the short window, 24 on the long ones.
   *  The bucket string alone does not say which, and the axis label has to. */
  timeline_step_hours: number;
  total_all_time: number;
  total_window: number;
  unacknowledged: number;
  /** The review queue: everything not yet marked reviewed, whole table, no
   *  window. The one count on the dashboard that never falls on its own. */
  pending: number;
  /** Calendar days in local time, which is where the operator is. Today only
   *  climbs and resets at a midnight everybody can predict; yesterday is the
   *  full day beside it, because one day's count alone says nothing. */
  today: number;
  yesterday: number;
  /** The engine's own notes for today, over the same calendar day as `today`
   *  and never inside it. Printed beside it so the exclusion is visible. */
  diagnostics_today: number;
  /** The engine's own event rules in the same window, counted apart. Not part
   *  of any figure above: they report on the traffic and on the sensor, not on
   *  anything anybody did. Shown under the tile so nothing is hidden. */
  diagnostics: number;
  /** Alerts the engine stopped rather than only reported. Zero unless it is
   *  inline on a queue: reading a copy, everything is "allowed". */
  blocked: number;
  /** Keyed by ET rating; '' for rules ET has not rated. */
  by_severity: Array<CountRow & { severity: string | null }>;
  /** The same split over the two calendar days the tiles show. A total says
   *  how many and never how serious, and this is what makes the top of the
   *  dashboard answer the second question. */
  today_by_severity: Array<CountRow & { severity: string | null }>;
  yesterday_by_severity: Array<CountRow & { severity: string | null }>;
  top_signatures: Array<CountRow & {
    signature: string; signature_id: number; severity: string | null;
  }>;
  top_sources: Array<CountRow & { src_ip: string }>;
  top_destinations: Array<CountRow & { dest_ip: string }>;
  top_categories: Array<CountRow & { category: string }>;
  timeline: Array<CountRow & { bucket: string; by_severity: Record<string, number> }>;
}

/** One country on the alert map. lat/lon are null when the country cannot be
 *  placed - registry buckets like 'Anonymous proxy' have no location. */
export interface GeoCountry {
  code: string;
  name: string;
  lat: number | null;
  lon: number | null;
  count: number;
  sources: number;
  /** Worst ET rating seen from this country, null when none were rated. */
  severity: string | null;
  last_seen: string;
}

export interface GeoSummary {
  window_hours: number;
  countries: GeoCountry[];
  unplaced: GeoCountry[];
  /** Traffic with no country: our own segment, other private ranges, and
   *  public addresses the database has no entry for. */
  local: { home: number; private: number; unknown: number };
  database: { available: boolean; path: string; updated: string | null };
}

export interface EngineStats {
  uptime_seconds: number | null;
  packets: number;
  bytes: number;
  /** null where the engine publishes no capture counters - see loss_measured. */
  kernel_packets: number | null;
  kernel_drops: number | null;
  capture_errors: number | null;
  drop_rate_percent: number | null;
  /** How the engine is taking packets, according to the engine's own stats. */
  capture_mode: 'af-packet' | 'nfqueue' | null;
  /** Whether it has a verdict to give on each packet: reading from a netfilter
   *  queue, or forwarding an inline pair itself. Separate from the method,
   *  because an inline pair publishes both sections and naming the queue there
   *  described a kernel bridge as something it is not. */
  blocking: boolean;
  /** Whether capture loss can be known at all here. NFQUEUE has no ring to
   *  overflow and reports no kernel_drops, and "not measured" has to reach the
   *  screen as something other than "nothing was lost". */
  loss_measured: boolean;
  /** Packets the engine stopped while inline, and how many of those any rule
   *  asked for. They differ: exception policies drop flows on their own. */
  blocked: number | null;
  blocked_by_rules: number | null;
  tcp_sessions: number;
  reassembly_gaps: number;
  gap_rate_percent: number;
  /** Which of the three the operator has to be told about, worst first, or
   *  null when the sensor is keeping up. The thresholds live in the backend:
   *  having them in two languages is how they drift apart. */
  sensor_problem: 'drops' | 'errors' | 'gaps' | null;
  alerts_detected: number;
  /** How many of those the panel has in its table, over the same period, and
   *  how many are missing once the clock slack is allowed for. The counter is
   *  only worth showing as this pair: on its own it is a number the reader
   *  lines up against the alert count beside it, which measures a different
   *  kind, a different period and a different set of filters. */
  alerts_stored: number | null;
  alerts_missing: number | null;
  flows: number;
}

export interface SuricataStatus {
  reader_alive: boolean;
  eve_path: string;
  panel_started_at: string;
  lines_read: number;
  parse_errors: number;
  last_event_at: number | null;
  last_stats_at: number | null;
  event_counts: Record<string, number>;
  engine: EngineStats;
  service?: {
    name: string;
    active: string;
    running: boolean;
    enabled: string;
    version: string;
  };
  /** Link state of what the engine captures on. Absent on the stream, which is
   *  why Live merges it field by field rather than letting the stream win. */
  capture?: CaptureLink;
}

/** "The engine is running" and "the engine is being handed traffic" are not the
 *  same statement. This is the second one. */
export interface CaptureLink {
  interfaces: {
    name: string;
    present: boolean;
    up: boolean;
    carrier: boolean;
    operstate: string | null;
    /** IFF_PROMISC. Without it the kernel drops every frame addressed to
     *  another machine, which is all a mirror port ever delivers. */
    promisc: boolean;
  }[];
  state: 'ok' | 'warn' | 'bad';
  /** A whole sentence, written by the backend, or null when there is nothing
   *  wrong. The panel never assembles this text: what counts as a problem is
   *  decided where the kernel is read. */
  problem: string | null;
}

export interface LiveEvent {
  /** Unix seconds, as on Alert. */
  ts: number | null;
  event_type: string;
  src_ip: string | null;
  src_port: number | null;
  dest_ip: string | null;
  dest_port: number | null;
  proto: string | null;
  app_proto: string | null;
  detail?: string | null;
}

/** Intrusion prevention screen - detection categories instead of rule files. */
export interface ProtectionCategory {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  locked: boolean;
  signatures: number;
  active_signatures: number;
  /** How many of this category's rules the signature set rates informational,
   *  counted over the whole category so the number reads the same whether they
   *  are loaded or not. It is what the switch below the categories costs here:
   *  6 188 of the 6 720 in "botnet" are ET DYN_DNS, so flipping it drops that
   *  category to 517 - which the screen used to do without a word. */
  informational: number;
  /** Loaded and alerting, never dropped when blocking is on. */
  alert_only: boolean;
}

export interface ProtectionMode {
  id: 'ids' | 'ips';
  label: string;
  can_block: boolean;
  /** Whether this panel can change the mode, or only report it. */
  can_switch: boolean;
  /** Rules loaded with `drop` rather than `alert`. Blocking with this at zero
   *  is a switch that reports itself on and stops nothing. */
  drop_rules: number;
  /** Rules the blocking policy says should drop that the running set still
   *  has as alerts. Above zero, the rule set needs a rebuild before blocking
   *  is what the categories say it is. */
  drop_pending: number;
  /** Whether blocking here means the engine doing the forwarding. True on a
   *  layout the traffic crosses, where the link then lives and dies with the
   *  engine; false where the queue only protects this device. */
  inline: boolean;
  /** False on a mirror layout: a copy cannot be stopped, and the queue would
   *  stop the engine reading the mirror port. Detection stays switchable. */
  blocking_possible: boolean;
  /** Why, when blocking_possible is false; empty otherwise. */
  blocking_unavailable: string;
  reason: string;
  interfaces: string[];
  capture: string;
}

/** A signature silenced one by one from the alert view. */
export interface MutedSignature {
  signature_id: number;
  signature: string | null;
}

/** The rule set's own rating, as a switch. Not a category: the categories come
 *  from the msg prefix and this comes from the rule metadata, so an
 *  informational rule can carry any prefix at all. `signatures` therefore
 *  overlaps the per-category counts and must not be added to them. */
export interface ProtectionInformational {
  enabled: boolean;
  signatures: number;
  active_signatures: number;
}

export interface Protection {
  signatures: { total: number; active: number };
  /** Unix seconds. When the panel last rebuilt the merged rule file. */
  updated_at: number | null;
  /** Unix seconds. When the vendor built this set - the age of the detection. */
  built_at: number | null;
  /** Unix seconds. When this device downloaded it. */
  fetched_at: number | null;
  source: string;
  applied: boolean;
  applied_at: string | null;
  mode: ProtectionMode;
  categories: ProtectionCategory[];
  informational: ProtectionInformational;
  muted: MutedSignature[];
  /** Signatures that alert and are never dropped. Same shape as the muted. */
  allowed: MutedSignature[];
}

export interface ProtectionResult {
  ok: boolean;
  output: string;
  state: Protection;
}

/** Logs screen - where the engine writes its events. */
export interface LogFile {
  name: string;
  size_bytes: number;
  modified: number;
}

/** A volume the logs could move to. Offered, not recommended: `persistent`
 *  says whether /etc/fstab will bring it back after a reboot, and a volume
 *  mounted by hand is still listed - with that flag false, because logs on a
 *  directory that stops being a mount point end up on the card again, silently. */
export interface LogVolume {
  path: string;
  mount: string;
  device: string;
  fstype: string;
  free: number;
  total: number;
  persistent: boolean;
  /** The logs already live on this volume, whatever the directory is called. */
  current: boolean;
}

export interface LogSettings {
  log_dir: string;
  panel_reads_from: string;
  can_change: boolean;
  warnings: string[];
  disk: { total: number; free: number; used: number; percent: number };
  files: LogFile[];
  /** Whether the logs share the volume the system boots from - on a Pi, the
   *  SD card, which is the whole reason this screen exists. */
  on_root: boolean;
  candidates: LogVolume[];
}

export interface LogDirResult {
  ok: boolean;
  log_dir: string;
  previous_dir: string;
  restarted: boolean;
  output: string;
  state: LogSettings;
}

/** Mail settings as the panel hands them out: never the password itself. */
export interface EmailSettings {
  enabled: boolean;
  host: string;
  port: number;
  security: 'none' | 'starttls' | 'ssl';
  username: string;
  sender: string;
  recipients: string[];
  min_severity: number;
  digest_seconds: number;
  max_per_hour: number;
  password_set: boolean;
}

export interface EmailStatus {
  running: boolean;
  /** Alerts collected and not sent yet. */
  waiting: number;
  /** Held back by the hourly limit; they go into the next message. */
  held_back: number;
  dropped: number;
  sent_last_hour: number;
  last_sent_at: number | null;
  last_error: string;
}

export interface EmailState {
  settings: EmailSettings;
  status: EmailStatus;
}

/** GET /api/system/ssh. `source` is how the SSH login gets in: a password
 *  or only a key set when the card was prepared, the panel password, the
 *  account's own password the panel leaves alone, or nothing yet. Null when
 *  the device cannot say. */
export interface SshAccess {
  active: boolean;
  source: 'card' | 'key' | 'panel' | 'other' | 'none' | null;
  login: string | null;
}

export interface SystemInfo {
  hostname: string;
  model: string;
  cpu_count: number;
  boot_time: number;
  uptime_seconds: number;
  kernel: string;
}

export interface SystemMetrics {
  timestamp: number;
  cpu: {
    percent: number;
    per_core: number[];
    temperature_c: number | null;
    load_avg: { '1m': number; '5m': number; '15m': number };
  };
  memory: { total: number; used: number; available: number; percent: number };
  swap: { total: number; used: number; percent: number };
  disk: { total: number; used: number; free: number; percent: number };
  throttling: {
    raw: string;
    under_voltage_now: boolean;
    frequency_capped_now: boolean;
    throttled_now: boolean;
    soft_temp_limit_now: boolean;
  } | null;
  uptime_seconds: number;
}

/** One point of the device load history. `cpu` is the mean over the step,
 *  `cpu_peak` the highest single reading inside it. */
export interface LoadPoint {
  ts: number;
  cpu: number;
  cpu_peak: number;
  temp: number | null;
  memory: number;
}

export interface LoadHistory {
  /** Requested window in hours; 0 means everything on record. */
  hours: number;
  /** Which table answered: minute samples or hourly averages. */
  source: 'minute' | 'hour';
  /** Seconds one point covers - grows with the window. */
  resolution_seconds: number;
  /** How far back minute-by-minute detail is kept. Hourly averages are kept
   *  for good, so the history itself reaches back to first_sample. */
  retention_hours: number;
  /** Unix seconds of the oldest reading this device has, or null when it has
   *  none yet. */
  first_sample: number | null;
  points: LoadPoint[];
}

export interface NetworkInterface {
  name: string;
  is_up: boolean;
  speed_mbps: number;
  mtu: number;
  mac: string | null;
  ipv4: string[];
  ipv6: string[];
  bytes_sent: number;
  bytes_recv: number;
  packets_sent: number;
  packets_recv: number;
  errors_in: number;
  errors_out: number;
  drops_in: number;
}

/** A message from the WebSocket stream. */
export interface WsMessage {
  topic: 'suricata.alert' | 'suricata.event' | 'suricata.stats' | string;
  data: unknown;
}

/** How Emerging Threats rates its own rules, worst first.
 *
 *  This is `metadata: signature_severity` from the rule, not Suricata's numeric
 *  `alert.severity`. ET says outright that they "do not reference suricata's own
 *  alert.severity", and on the shipped rule set the two disagree constantly:
 *  8 879 rules ET calls Informational carry engine priority 1 or 2, and 296
 *  rules ET calls Critical or Major carry priority 3. The panel showed the
 *  number first and got both directions wrong at once - `GPL ATTACK_RESPONSE id
 *  check returned root` rendered as "High" while ET rates it Informational.
 *
 *  Must agree with db.ET_SEVERITIES on the backend.
 */
export const ET_SEVERITIES = ['Critical', 'Major', 'Minor', 'Informational'] as const;
export type EtSeverity = (typeof ET_SEVERITIES)[number];

/** ET's definition: activity that may not be malicious in itself, but is worth
 *  recording for the context it gives other alerts. Stored, not shown. */
export const INFORMATIONAL: EtSeverity = 'Informational';

/** What to call a rule ET has not rated - GPL, Suricata's own stream events,
 *  anything local. Not a claim that it is harmless, only that ET has no opinion,
 *  which is why it gets its own word rather than being folded into a tier. */
export const UNRATED = 'unrated';

/** What a rating is called wherever it is shown.
 *
 *  One name for one thing: the badge in the table said "unrated", the tile on
 *  the dashboard "Not rated" and the filter "Not rated by ET", which is three
 *  names for the rules Emerging Threats ships without a rating. The filter
 *  keeps its longer form because it sits among other ratings in a list where
 *  "by ET" is the distinction being drawn. */
export const UNRATED_LABEL = 'Not rated';

export function severityLabel(severity: string | null | undefined): string {
  return severity || UNRATED_LABEL;
}

export function severityClass(severity: string | null | undefined): string {
  switch (severity) {
    case 'Critical': return 'sev-1';
    case 'Major': return 'sev-2';
    case 'Minor': return 'sev-3';
    case 'Informational': return 'sev-4';
    default: return 'sev-none';
  }
}

// --- network topology ---

/** One network interface, as the topology wizard needs to see it. Richer than
 *  NetworkInterface above, which exists for the System page's counters. */
export interface NetworkLink {
  name: string;
  kind: 'wired' | 'wireless' | 'bridge' | 'virtual' | 'other';
  driver: string;
  usb: boolean;
  is_up: boolean;
  carrier: boolean;
  speed_mbps: number | null;
  mtu: number;
  mac: string | null;
  ipv4: string[];
  ipv6: string[];
  subnets: string[];
  blocked: boolean;
  is_management: boolean;
}

export interface Hardware {
  links: NetworkLink[];
  management: string;
  counts: { usable: number; wired: number; wireless: number };
  wireless_blocked: boolean;
}

export interface TopologyRole {
  id: string;
  label: string;
}

export interface CaptureStep {
  step: string;
  ok: boolean;
  output: string;
}

export interface ApplyResult {
  ok: boolean;
  interface: string;
  home_net: string;
  steps: CaptureStep[];
}

export interface TopologyProfile {
  id: string;
  name: string;
  summary: string;
  sees: string;
  blind_to: string;
  hardware: string;
  steps: string[];
  roles: TopologyRole[];
  passive: boolean;
  can_block: boolean;
  /** What dropping would take, where the traffic passes through the Pi but the
   *  configuration the panel writes still only reports. Empty where it does not
   *  arise. */
  blocking_needs: string;
  /** What blocking costs where it is possible. The opposite of the field above:
   *  that one says why a layout cannot block, this one what it gives up. */
  blocking_cost: string;
  capture_has_address: boolean;
  can_apply: boolean;
  available: boolean;
  reason: string;
}

export interface TopologyChoice {
  profile: string;
  roles: Record<string, string>;
  chosen_at: string;
  applied: boolean;
  applied_at: string;
  home_net: string;
}

export interface TopologyState {
  hardware: Hardware;
  profiles: TopologyProfile[];
  current: TopologyChoice;
  engine: { interfaces: string[] };
}

export interface TopologySaved {
  profile: string;
  roles: Record<string, string>;
  warnings: string[];
}

