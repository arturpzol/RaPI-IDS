"""Time series of device load, kept at two resolutions.

The panel used to draw this chart from whatever the browser had collected since
the tab was opened: forty samples three seconds apart, thrown away on every
navigation. Two minutes of history answers no question anyone has. "Was the Pi
pegged last night" does, and that needs the sampling to happen where the panel
runs, not where it is being looked at.

That first fix kept a day of samples in memory, which answered the question
about last night and no question about last month - and lost even that on every
restart. So the history now lives in SQLite, at two resolutions on purpose:

* **minute samples**, kept for `RAPI_LOAD_SAMPLE_DAYS` (a week by default).
  This is the resolution that shows a rule rebuild or a stall,
* **hourly averages**, kept for good. 24 rows a day is 9k rows a year, small
  enough that the honest retention is "since this image first booted".

The cost that had to stay small is writing to the card. Minute samples are
written in batches of five, so it is 288 small transactions a day rather than
1440, and the rollup runs once an hour. Against the engine's own log, which is
tens of megabytes a day, this is noise.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, NamedTuple

import psutil

from ... import config, db

log = logging.getLogger(__name__)

# How often a reading is taken, and how many go into one stored sample. Ten
# seconds is short enough to catch a build or a rule reload, six of them make
# the minute that gets kept.
SAMPLE_SECONDS = 10
BUCKET_SECONDS = 60
HOUR_SECONDS = 3600

# Minute samples buffered before a write. Five minutes of data is a small enough
# thing to lose in a power cut and a fifth of the writes.
FLUSH_SAMPLES = 5

# Above this the chart is drawn from the hourly rollups. A window wider than two
# days cannot show minutes anyway - 180 points across 48 hours is already one
# point per sixteen minutes.
MINUTE_WINDOW_HOURS = 48

# Points the API will return at most. A chart a thousand pixels wide cannot show
# more, and sending 1440 of them just makes the browser average them itself.
MAX_POINTS = 180


class Sample(NamedTuple):
    """One minute of device load."""

    ts: float
    cpu: float       # mean over the minute
    cpu_peak: float  # highest single reading in the minute
    temp: float | None
    memory: float


class _Sampler:
    def __init__(self) -> None:
        self._pending: list[tuple[float, float | None, float]] = []
        self._bucket_start = 0.0
        self._prev_times: Any = None
        self._task: asyncio.Task | None = None
        # Minutes taken but not yet written, and the last hour folded into the
        # rollup table. Both are recovered from the database on start.
        self._unsaved: list[Sample] = []
        self._rolled_through = 0
        self._purged_on = 0.0

    # --- reading ---

    def _cpu_percent(self) -> float | None:
        """Busy share of the CPU since the previous call.

        Computed from cpu_times() rather than through psutil.cpu_percent():
        that function keeps one global reference point, which the /metrics
        endpoint also moves every time the browser polls it. Sharing it would
        make this sampler measure the gap since the last page refresh instead
        of the gap since its own last reading.
        """
        times = psutil.cpu_times()
        previous, self._prev_times = self._prev_times, times
        if previous is None:
            return None

        total = sum(times) - sum(previous)
        # iowait counts as idle here, the same way psutil treats it: the core is
        # not doing work, it is waiting for a disk.
        idle = (times.idle - previous.idle) + (
            getattr(times, "iowait", 0.0) - getattr(previous, "iowait", 0.0)
        )
        if total <= 0:
            return None
        return round(max(0.0, min(100.0, (1 - idle / total) * 100)), 1)

    @staticmethod
    def _temperature() -> float | None:
        # Imported here, not at module level, to keep the reading in one place.
        from .router import _cpu_temperature

        return _cpu_temperature()

    def _tick(self) -> None:
        if not self._bucket_start:
            # Guard rather than an assumption about who calls first: started
            # from a zero the first tick would close a bucket immediately.
            self._bucket_start = time.time()
        cpu = self._cpu_percent()
        if cpu is None:
            return  # first call has nothing to compare against
        self._pending.append((cpu, self._temperature(), psutil.virtual_memory().percent))

        now = time.time()
        if now - self._bucket_start >= BUCKET_SECONDS:
            self._close_bucket(now)

    def _close_bucket(self, now: float) -> None:
        if self._pending:
            self._unsaved.append(self._bucket(now))
            self._pending = []
            if len(self._unsaved) >= FLUSH_SAMPLES:
                self.flush()
        self._bucket_start = now

    def _bucket(self, ts: float, samples: list[Any] | None = None) -> Sample:
        """Average one minute's readings.

        Takes the samples rather than reading self._pending three times: the
        reader runs on a worker thread and the writer on the event loop, and a
        bucket closing in between left this dividing by an empty list.
        """
        pending = self._pending if samples is None else samples
        cpus = [p[0] for p in pending]
        temps = [p[1] for p in pending if p[1] is not None]
        mems = [p[2] for p in pending]
        return Sample(
            ts=ts,
            cpu=round(sum(cpus) / len(cpus), 1),
            cpu_peak=round(max(cpus), 1),
            temp=round(sum(temps) / len(temps), 1) if temps else None,
            memory=round(sum(mems) / len(mems), 1),
        )

    # --- writing ---

    def flush(self) -> None:
        """Write the buffered minutes, then keep the rollup up to date.

        Failures are logged and the buffer is kept: a database locked by the
        alert writer for a moment should cost a retry, not five minutes of
        history.
        """
        if not self._unsaved:
            self._rollup()
            return
        rows = [(int(s.ts), s.cpu, s.cpu_peak, s.temp, s.memory) for s in self._unsaved]
        try:
            db.insert_load_samples(rows)
        except Exception:
            log.exception("Could not store %d load samples", len(rows))
            return
        self._unsaved = []
        self._rollup()

    def _rollup(self) -> None:
        """Fold every finished hour into the hourly table, then trim the minutes."""
        this_hour = int(time.time()) // HOUR_SECONDS * HOUR_SECONDS
        if self._rolled_through >= this_hour:
            return
        try:
            db.rollup_load_hours(self._rolled_through, this_hour)
            self._rolled_through = this_hour
        except Exception:
            log.exception("Could not roll up the load history")
            return

        # Once a day, and only after a successful rollup - dropping minutes that
        # never made it into an hourly row would lose them for good.
        now = time.time()
        if now - self._purged_on >= 86400:
            self._purged_on = now
            try:
                removed = db.purge_load_samples(config.LOAD_SAMPLE_DAYS)
                if removed:
                    log.info("Load history: dropped %d minute samples past retention", removed)
            except Exception:
                log.exception("Could not trim the load history")

    # --- lifecycle ---

    async def _run(self) -> None:
        self._bucket_start = time.time()
        while True:
            try:
                self._tick()
            except Exception:
                log.exception("Load sampling failed")
            await asyncio.sleep(SAMPLE_SECONDS)

    def start(self) -> None:
        if self._task is not None:
            return
        # Where the previous run left off, so a restart does not re-aggregate a
        # week of samples on the first hour.
        try:
            hours = db.load_hours_since(0)
            self._rolled_through = hours[-1]["hour"] + HOUR_SECONDS if hours else 0
        except Exception:
            log.exception("Could not read the load history")
        self._task = asyncio.create_task(self._run())

    def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            self._task = None
        # A clean shutdown keeps the minutes it has; a kill loses up to five.
        try:
            self.flush()
        except Exception:
            log.exception("Could not flush the load history")

    # --- reads ---

    def window(self, hours: int) -> dict[str, Any]:
        """The last `hours` of history, or everything there is when hours <= 0.

        Which table answers depends on the span. Minutes for the last two days,
        hourly averages beyond that, because 180 points is all the chart can
        draw either way and asking SQLite for a year of minutes to average them
        in Python would be work done twice.
        """
        now = time.time()
        everything = hours <= 0
        cutoff = 0.0 if everything else now - hours * HOUR_SECONDS
        by_minute = not everything and hours <= MINUTE_WINDOW_HOURS

        samples = self._minutes(cutoff) if by_minute else self._hours(cutoff)
        step = max(1, -(-len(samples) // MAX_POINTS))  # ceil
        points = [self._merge(samples[i:i + step]) for i in range(0, len(samples), step)]

        try:
            first = db.load_history_start()
        except Exception:
            first = None
        if first is None and samples:
            first = int(samples[0].ts)

        return {
            "hours": hours,
            "source": "minute" if by_minute else "hour",
            "resolution_seconds": step * (BUCKET_SECONDS if by_minute else HOUR_SECONDS),
            # What the two tables keep, so the screen can say why a window is
            # short on detail rather than looking broken.
            "retention_hours": config.LOAD_SAMPLE_DAYS * 24,
            "first_sample": first,
            "points": points,
        }

    def _minutes(self, cutoff: float) -> list[Sample]:
        """Stored minutes, plus the ones not written yet and the one in progress."""
        try:
            stored = [
                Sample(r["ts"], r["cpu"], r["cpu_peak"], r["temp"], r["memory"])
                for r in db.load_samples_since(int(cutoff))
            ]
        except Exception:
            log.exception("Could not read the load history")
            stored = []
        return stored + self._live(cutoff)

    def _live(self, cutoff: float) -> list[Sample]:
        # One snapshot of the list, then work from it. This runs on the worker
        # thread FastAPI gives a sync route, while _close_bucket empties
        # self._pending on the event loop: re-reading the attribute inside
        # _bucket meant the samples could vanish between the check above and
        # the averages below, and the history endpoint answered 500 with a
        # ZeroDivisionError.
        pending = list(self._pending)
        live = [self._bucket(time.time(), pending)] if pending else []
        return [s for s in [*self._unsaved, *live] if s.ts >= cutoff]

    def _hours(self, cutoff: float) -> list[Sample]:
        """Hourly averages, with the hour in progress worked out on the spot.

        Without that last part a long window would end up to an hour behind,
        which on the "everything" view reads as the panel having stopped.
        """
        try:
            stored = [
                Sample(r["hour"], r["cpu"], r["cpu_peak"], r["temp"], r["memory"])
                for r in db.load_hours_since(int(cutoff))
            ]
        except Exception:
            log.exception("Could not read the load history")
            stored = []

        recent = self._minutes(max(cutoff, self._rolled_through))
        return stored + _fold_into_hours(recent)

    @staticmethod
    def _merge(group: list[Sample]) -> dict[str, Any]:
        """Thin several samples into one point.

        The mean is what gets drawn and the peak is carried alongside it. Over
        an eight-minute step a mean on its own would hide a burst that pinned
        every core for half a minute, which is exactly the event worth seeing.
        """
        temps = [s.temp for s in group if s.temp is not None]
        return {
            "ts": group[-1].ts,
            "cpu": round(sum(s.cpu for s in group) / len(group), 1),
            "cpu_peak": round(max(s.cpu_peak for s in group), 1),
            "temp": round(sum(temps) / len(temps), 1) if temps else None,
            "memory": round(sum(s.memory for s in group) / len(group), 1),
        }


def _fold_into_hours(samples: list[Sample]) -> list[Sample]:
    """Group minute samples by the hour they fall in, the way the rollup does."""
    buckets: dict[int, list[Sample]] = {}
    for sample in samples:
        buckets.setdefault(int(sample.ts) // HOUR_SECONDS * HOUR_SECONDS, []).append(sample)

    out: list[Sample] = []
    for hour in sorted(buckets):
        group = buckets[hour]
        temps = [s.temp for s in group if s.temp is not None]
        out.append(Sample(
            ts=hour,
            cpu=round(sum(s.cpu for s in group) / len(group), 1),
            cpu_peak=round(max(s.cpu_peak for s in group), 1),
            temp=round(sum(temps) / len(temps), 1) if temps else None,
            memory=round(sum(s.memory for s in group) / len(group), 1),
        ))
    return out


sampler = _Sampler()
