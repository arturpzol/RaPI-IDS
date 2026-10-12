import { formatBytes, formatDateTime, formatDuration, formatNumber, formatTime } from './format';

/** Formatting is where a panel quietly lies: a missing value printed as 0, or a
 *  timestamp silently shifted into another timezone. */
describe('formatBytes', () => {
  it('counts in binary units', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1024)).toBe('1.0 KB');
    expect(formatBytes(1024 * 1024)).toBe('1.0 MB');
    expect(formatBytes(1024 ** 4)).toBe('1.0 TB');
  });

  it('takes the number of digits it is asked for', () => {
    expect(formatBytes(1536, 2)).toBe('1.50 KB');
  });

  it('says nothing rather than zero when there is no value', () => {
    expect(formatBytes(null)).toBe('-');
    expect(formatBytes(undefined)).toBe('-');
    expect(formatBytes(NaN)).toBe('-');
  });
});

describe('formatDuration', () => {
  it('drops the units that would read as zero', () => {
    expect(formatDuration(45)).toBe('45s');
    expect(formatDuration(90)).toBe('1m 30s');
    expect(formatDuration(3600 + 120)).toBe('1h 2m');
    expect(formatDuration(86400 * 2 + 3600)).toBe('2d 1h 0m');
  });

  it('has no value for a missing one', () => {
    expect(formatDuration(null)).toBe('-');
  });
});

describe('formatNumber', () => {
  it('groups thousands', () => {
    expect(formatNumber(68411)).toBe('68,411');
  });

  it('has no value for a missing one', () => {
    expect(formatNumber(undefined)).toBe('-');
  });
});

describe('timestamps', () => {
  /** Unix seconds, the way the backend now sends them. */
  const at = (iso: string) => Math.floor(new Date(iso).getTime() / 1000);

  it('reads an engine timestamp in the reader\'s own zone', () => {
    // The engine writes local time with an offset and the backend turns that
    // into seconds once, on the way in. Seconds carry no zone at all, so there
    // is no longer a way for the panel to print an alert an hour from the log
    // line it came from.
    const iso = '2026-08-23T10:15:00+0200';
    const expected = new Date(iso).toLocaleTimeString('en-GB', { hour12: false });
    expect(formatTime(at(iso), new Date(iso))).toBe(expected);
  });

  it('uses a 24 hour clock', () => {
    expect(formatTime(at('2026-08-23T22:15:00+0200'))).not.toContain('PM');
  });

  it('says which day, once the clock alone stops saying it', () => {
    // The alert list holds up to a week. "22:41" on its own left the reader
    // guessing which night, which is the whole complaint.
    const iso = '2026-08-23T22:41:00+0200';
    const shown = formatTime(at(iso), new Date('2026-08-25T09:00:00+0200'));
    expect(shown).toContain('23/08');
    expect(shown).toContain(new Date(iso).toLocaleTimeString('en-GB', { hour12: false }));
  });

  it('stays short for today, so a column of rows is not a wall of dates', () => {
    const iso = '2026-08-25T22:41:00+0200';
    expect(formatTime(at(iso), new Date('2026-08-25T23:00:00+0200'))).not.toContain('/');
  });

  it('adds the year only when it differs', () => {
    const now = new Date('2026-08-25T09:00:00+0200');
    expect(formatTime(at('2026-01-02T08:00:00+0100'), now)).toBe('02/01 08:00:00');
    expect(formatTime(at('2025-12-31T08:00:00+0100'), now)).toContain('2025');
  });

  it('midnight is a different day, not a different hour', () => {
    // 00:04 today and 00:04 yesterday are the pair this exists to separate.
    const shown = formatTime(at('2026-08-24T00:04:00+0200'),
                             new Date('2026-08-25T00:20:00+0200'));
    expect(shown).toContain('24/08');
  });

  it('has no value for a missing one', () => {
    // Nothing here produces a zero timestamp, so zero means absent rather than
    // 1970 - which is the only reading that puts a row somewhere useful.
    expect(formatTime(null)).toBe('-');
    expect(formatTime(0)).toBe('-');
    expect(formatDateTime(undefined)).toBe('-');
    expect(formatDateTime(0)).toBe('-');
  });

  it('survives a number that is not a time', () => {
    expect(formatTime(Number.NaN)).toBe('-');
    expect(formatDateTime(Number.POSITIVE_INFINITY)).toBe('-');
  });
});
