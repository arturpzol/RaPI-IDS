import { Pipe, PipeTransform } from '@angular/core';

/** en-GB rather than en-US: 24-hour clock and day-first dates, which is what
 *  log lines and the engine's own timestamps use. */
const LOCALE = 'en-GB';

export function formatBytes(bytes: number | null | undefined, digits = 1): string {
  if (bytes === null || bytes === undefined || Number.isNaN(bytes)) return '-';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let value = bytes / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(digits)} ${units[i]}`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '-';
  const s = Math.floor(seconds);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return '-';
  return value.toLocaleString(LOCALE);
}

/** Clock time out of an EVE timestamp (ISO8601 with an offset), with the date
 *  added as soon as the clock alone stops identifying the moment.
 *
 *  It used to be clock only. That reads correctly on a live view, where every
 *  row arrived seconds ago, and lies everywhere else: the alert list can hold a
 *  week, so a row saying "22:41" left the reader to guess which night. The date
 *  appears exactly when it is needed, so today's rows stay as narrow as before
 *  and a column of them does not turn into a wall of repeated dates.
 *
 *  `now` is a parameter so the boundary can be tested without moving the clock.
 */
/** Unix seconds to a Date. Zero is not a timestamp anything here produces, so
 *  it is treated as absent rather than as 1970. */
function moment(ts: number | null | undefined): Date | null {
  if (!ts) return null;
  const d = new Date(ts * 1000);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatTime(ts: number | null | undefined, now: Date = new Date()): string {
  const d = moment(ts);
  if (!d) return '-';
  const clock = d.toLocaleTimeString(LOCALE, { hour12: false });
  if (d.toDateString() === now.toDateString()) return clock;
  const date = d.toLocaleDateString(LOCALE, {
    day: '2-digit',
    month: '2-digit',
    // The year only once it differs, which on a device that has been running a
    // long time is the difference between a stale row and a misread one.
    ...(d.getFullYear() === now.getFullYear() ? {} : { year: 'numeric' }),
  });
  return `${date} ${clock}`;
}

export function formatDateTime(ts: number | null | undefined): string {
  const d = moment(ts);
  return d ? d.toLocaleString(LOCALE, { hour12: false }) : '-';
}

@Pipe({ name: 'bytes' })
export class BytesPipe implements PipeTransform {
  transform(value: number | null | undefined, digits = 1): string {
    return formatBytes(value, digits);
  }
}

@Pipe({ name: 'duration' })
export class DurationPipe implements PipeTransform {
  transform(value: number | null | undefined): string {
    return formatDuration(value);
  }
}

@Pipe({ name: 'num' })
export class NumberPipe implements PipeTransform {
  transform(value: number | null | undefined): string {
    return formatNumber(value);
  }
}

@Pipe({ name: 'time' })
export class TimePipe implements PipeTransform {
  transform(value: number | null | undefined): string {
    return formatTime(value);
  }
}

@Pipe({ name: 'datetime' })
export class DateTimePipe implements PipeTransform {
  transform(value: number | null | undefined): string {
    return formatDateTime(value);
  }
}
