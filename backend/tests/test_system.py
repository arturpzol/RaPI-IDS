"""Device health: the readings and the day of history behind them."""
from __future__ import annotations

import subprocess
import time
from unittest.mock import patch

from app import config, db
from app.modules.system import history
from app.modules.system import router as system_router

from .helpers import BackendTestCase


class TemperatureTest(BackendTestCase):
    def test_a_missing_sensor_is_none_not_a_crash(self):
        # Not every board exposes one, and the image runs on more than one board.
        with patch.object(system_router.psutil, "sensors_temperatures", return_value={}):
            with patch.object(system_router.Path, "read_text", side_effect=OSError):
                self.assertIsNone(system_router._cpu_temperature())

    def test_a_reading_comes_back_in_degrees(self):
        temp = system_router._cpu_temperature()
        if temp is not None:
            self.assertLess(temp, 150)   # millidegrees would sail past this
            self.assertGreater(temp, -50)


class ThrottlingTest(BackendTestCase):
    """What the board says about power and heat, and what of it is worth showing.

    vcgencmd reports eight bits: four for what is happening now, four sticky
    ones for what happened at some point since boot. The sticky half was on
    screen until an image build pushed this device to 81.6 C for a quarter of an
    hour and left "There was throttling since the last boot" standing for three
    days, on a machine that had been at 54 C ever since, without saying when it
    happened or how hot it got.
    """

    def _read(self, raw: str):
        completed = subprocess.CompletedProcess([], 0, stdout=f"throttled={raw}\n", stderr="")
        with patch.object(system_router.subprocess, "run", return_value=completed):
            return system_router._throttled()

    def test_a_board_that_is_fine_reports_nothing_wrong(self):
        self.assertEqual(
            {k: v for k, v in self._read("0x0").items() if k != "raw"},
            {"under_voltage_now": False, "frequency_capped_now": False,
             "throttled_now": False, "soft_temp_limit_now": False},
        )

    def test_a_bad_power_supply_is_still_reported(self):
        # The one warning in this box worth keeping: it is the usual cause of
        # strange failures on a Pi, and it clears itself when the cause goes.
        self.assertTrue(self._read("0x1")["under_voltage_now"])

    def test_heat_right_now_is_reported(self):
        state = self._read("0xc")
        self.assertTrue(state["throttled_now"])
        self.assertTrue(state["soft_temp_limit_now"])

    def test_a_hot_quarter_of_an_hour_three_days_ago_is_not_a_warning(self):
        # 0xe0000 is exactly what this device reported after the image build:
        # every sticky bit lit, nothing wrong now. A warning that cannot be
        # cleared teaches people to ignore the box it lives in, and the live
        # under-voltage line lives in that same box.
        state = self._read("0xe0000")
        self.assertEqual([k for k, v in state.items() if v is True], [])

    def test_the_sticky_bits_are_gone_from_the_answer_not_merely_false(self):
        # Left in as always-false fields they would read as "this never happens".
        state = self._read("0xe0000")
        self.assertNotIn("under_voltage_since_boot", state)
        self.assertNotIn("throttled_since_boot", state)

    def test_the_raw_value_still_carries_everything(self):
        # Nothing is lost from the API: whoever wants the history can decode it.
        self.assertEqual(self._read("0xe0000")["raw"], "0xe0000")

    def test_a_board_with_no_vcgencmd_says_so_rather_than_guessing(self):
        with patch.object(system_router.subprocess, "run", side_effect=OSError):
            self.assertIsNone(system_router._throttled())

    def test_an_answer_that_makes_no_sense_is_not_a_crash(self):
        completed = subprocess.CompletedProcess([], 0, stdout="throttled=banana\n", stderr="")
        with patch.object(system_router.subprocess, "run", return_value=completed):
            self.assertIsNone(system_router._throttled())


class SamplerTest(BackendTestCase):
    """Device load: minutes for the near past, hourly averages for the rest."""

    def setUp(self):
        super().setUp()
        self.sampler = history._Sampler()

    def _sample(self, ts: float, cpu: float = 10.0, peak: float | None = None,
                temp: float | None = 45.0, memory: float = 30.0) -> history.Sample:
        return history.Sample(ts=ts, cpu=cpu, cpu_peak=peak if peak is not None else cpu,
                              temp=temp, memory=memory)

    def _store(self, samples):
        db.insert_load_samples(
            [(int(s.ts), s.cpu, s.cpu_peak, s.temp, s.memory) for s in samples]
        )

    def _minutes(self, count: int, end: float | None = None, **kwargs):
        end = end if end is not None else time.time()
        return [self._sample(end - (count - i) * 60, **kwargs) for i in range(count)]

    def test_an_empty_history_still_answers(self):
        window = self.sampler.window(1)
        self.assertEqual(window["points"], [])
        self.assertEqual(window["hours"], 1)
        self.assertIsNone(window["first_sample"])

    def test_minutes_survive_a_restart(self):
        # The whole reason this moved out of memory: a panel restart used to
        # take the chart with it.
        self._store(self._minutes(30))
        self.assertEqual(len(history._Sampler().window(1)["points"]), 30)

    def test_a_window_only_contains_what_falls_inside_it(self):
        self._store(self._minutes(180))
        self.assertLessEqual(len(self.sampler.window(1)["points"]), 60)

    def test_the_minutes_not_written_yet_are_shown_too(self):
        # Samples are written five at a time, so without this the chart would
        # trail the present by up to five minutes.
        self.sampler._unsaved = self._minutes(3)
        self.assertEqual(len(self.sampler.window(1)["points"]), 3)

    def test_the_minute_in_progress_is_shown_too(self):
        # So a panel that has only just started draws something.
        self.sampler._pending = [(12.0, 44.0, 30.0)]
        points = self.sampler.window(1)["points"]
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0]["cpu"], 12.0)

    def test_a_batch_is_written_once_it_is_full(self):
        for index in range(history.FLUSH_SAMPLES):
            self.sampler._pending = [(10.0, 45.0, 30.0)]
            self.sampler._close_bucket(time.time() + index)
        self.assertEqual(self.sampler._unsaved, [])
        self.assertEqual(len(db.load_samples_since(0)), history.FLUSH_SAMPLES)

    def test_nothing_is_written_before_the_batch_is_full(self):
        # 288 transactions a day instead of 1440. The card is the reason.
        self.sampler._pending = [(10.0, 45.0, 30.0)]
        self.sampler._close_bucket(time.time())
        self.assertEqual(db.load_samples_since(0), [])
        self.assertEqual(len(self.sampler._unsaved), 1)

    def test_a_database_that_will_not_take_the_batch_keeps_it(self):
        # A moment's lock contention should cost a retry, not five minutes.
        self.sampler._unsaved = self._minutes(2)
        with patch.object(db, "insert_load_samples", side_effect=RuntimeError("locked")):
            self.sampler.flush()
        self.assertEqual(len(self.sampler._unsaved), 2)

    def test_stopping_writes_what_it_has(self):
        self.sampler._unsaved = self._minutes(2)
        self.sampler.stop()
        self.assertEqual(len(db.load_samples_since(0)), 2)

    def test_finished_hours_become_hourly_averages(self):
        hour = int(time.time()) // 3600 * 3600 - 7200
        self._store([self._sample(hour + 60, cpu=10.0), self._sample(hour + 120, cpu=30.0, peak=90.0)])
        self.sampler.flush()
        rows = db.load_hours_since(0)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["cpu"], rows[0]["cpu_peak"], rows[0]["samples"]), (20.0, 90.0, 2))

    def test_the_hour_in_progress_is_not_rolled_up_yet(self):
        # Anchored to the start of the current hour, not to "three minutes ago":
        # run in the first minutes of an hour, three minutes ago is the previous
        # hour, which is finished and rolls up exactly as it should - and the
        # test then failed for asserting the opposite of what it is named after.
        hour = int(time.time()) // 3600 * 3600
        self._store([self._sample(hour + offset) for offset in (0, 1, 2)])
        self.sampler.flush()
        self.assertEqual(db.load_hours_since(0), [])

    def test_a_long_window_is_drawn_from_the_hourly_table(self):
        hour = int(time.time()) // 3600 * 3600
        self._store([self._sample(hour - 3600 * (i + 1)) for i in range(72)])
        self.sampler.flush()
        window = self.sampler.window(24 * 30)
        self.assertEqual(window["source"], "hour")
        self.assertEqual(window["resolution_seconds"], 3600)
        self.assertEqual(len(window["points"]), 72)

    def test_everything_means_everything_on_record(self):
        hour = int(time.time()) // 3600 * 3600
        oldest = hour - 3600 * 24 * 400
        self._store([self._sample(oldest + 60), self._sample(hour - 3600)])
        self.sampler.flush()
        window = self.sampler.window(0)
        self.assertEqual(window["source"], "hour")
        self.assertEqual(len(window["points"]), 2)
        # The hourly row is stamped with the start of its hour, which is what
        # "since" means once the minutes behind it have been dropped.
        self.assertEqual(window["first_sample"], oldest)

    def test_a_long_window_still_reaches_the_current_hour(self):
        # Otherwise the newest point is up to an hour old, which on the
        # "everything" view reads as the panel having stopped.
        hour = int(time.time()) // 3600 * 3600
        self._store([self._sample(hour - 3600 * 5)])
        self.sampler.flush()
        self.sampler._unsaved = [self._sample(time.time(), cpu=55.0)]
        points = self.sampler.window(0)["points"]
        self.assertEqual(points[-1]["cpu"], 55.0)

    def test_minute_samples_are_dropped_after_their_retention(self):
        # Anchored to an hour boundary rather than to "now minus eight days":
        # started in the last minute of an hour, the sample a minute later fell
        # into the next hour and the row this asserts on was one bucket further
        # along. A test that fails for one minute in sixty is worse than no test.
        old_hour = (int(time.time()) - (config.LOAD_SAMPLE_DAYS + 1) * 86400) // 3600 * 3600
        self._store([self._sample(old_hour + 60), self._sample(time.time() - 120)])
        self.sampler.flush()          # rolls the old hour up first
        self.sampler._purged_on = 0.0
        self.sampler._rolled_through = 0
        self.sampler._rollup()
        self.assertEqual(len(db.load_samples_since(0)), 1)
        # The hourly row for that day is still there - that is the point.
        self.assertIn(old_hour, [r["hour"] for r in db.load_hours_since(0)])

    def test_long_windows_are_thinned_not_truncated(self):
        # A chart a thousand pixels wide cannot draw a year of hours, and
        # sending them only makes the browser average them itself.
        hour = int(time.time()) // 3600 * 3600
        self._store([self._sample(hour - 3600 * (i + 1)) for i in range(24 * 60)])
        self.sampler.flush()
        window = self.sampler.window(0)
        self.assertLessEqual(len(window["points"]), history.MAX_POINTS)
        self.assertGreater(window["resolution_seconds"], history.HOUR_SECONDS)

    def test_thinning_keeps_the_peak(self):
        # Over an eight minute step a mean alone would hide the burst that
        # pinned every core for half a minute, which is the event worth seeing.
        samples = self._minutes(600)
        samples[-5] = self._sample(samples[-5].ts, cpu=10.0, peak=99.0)
        self._store(samples)
        peaks = [point["cpu_peak"] for point in self.sampler.window(24)["points"]]
        self.assertIn(99.0, peaks)

    def test_a_board_with_no_thermal_zone_reports_no_temperature(self):
        self._store(self._minutes(3, temp=None))
        self.assertIsNone(self.sampler.window(1)["points"][0]["temp"])

    def test_the_first_reading_has_nothing_to_compare_against(self):
        self.assertIsNone(self.sampler._cpu_percent())

    def test_two_readings_with_no_time_between_them_are_not_a_division(self):
        same = _times(idle=100.0, user=10.0)
        with patch.object(history.psutil, "cpu_times", side_effect=[same, same]):
            self.sampler._cpu_percent()
            self.assertIsNone(self.sampler._cpu_percent())

    def test_cpu_share_is_measured_against_this_sampler_only(self):
        # Computed from cpu_times() rather than psutil.cpu_percent(), which
        # keeps one global reference point that /metrics also moves.
        idle_only = _times(idle=100.0, user=0.0)
        busy = _times(idle=100.0, user=100.0)
        with patch.object(history.psutil, "cpu_times", side_effect=[idle_only, busy]):
            self.assertIsNone(self.sampler._cpu_percent())
            self.assertEqual(self.sampler._cpu_percent(), 100.0)

    def test_a_bucket_averages_and_keeps_the_peak(self):
        self.sampler._pending = [(10.0, 40.0, 20.0), (30.0, 50.0, 40.0)]
        sample = self.sampler._bucket(1.0)
        self.assertEqual((sample.cpu, sample.cpu_peak), (20.0, 30.0))
        self.assertEqual((sample.temp, sample.memory), (45.0, 30.0))

    def test_a_bucket_without_a_temperature_reading(self):
        self.sampler._pending = [(10.0, None, 20.0)]
        self.assertIsNone(self.sampler._bucket(1.0).temp)

    def test_an_unreadable_database_leaves_the_page_drawable(self):
        with patch.object(db, "load_samples_since", side_effect=RuntimeError("no db")):
            window = self.sampler.window(1)
        self.assertEqual(window["points"], [])

    def test_the_minute_in_progress_survives_the_writer_clearing_it(self):
        """The reader runs on a worker thread, the writer on the event loop.

        `window()` is reached from the sync history route, which FastAPI hands
        to a thread, while `_close_bucket` empties `_pending` on the loop. The
        averages used to re-read the attribute three times after checking it,
        so a bucket closing in between divided by an empty list and the history
        endpoint answered 500.
        """
        self.sampler._pending = [(10.0, 40.0, 20.0)]
        original = self.sampler._bucket

        def closing(ts, samples=None):
            # The writer, landing between the check and the arithmetic.
            self.sampler._pending = []
            return original(ts, samples)

        self.sampler._bucket = closing
        live = self.sampler._live(0)
        self.assertEqual(len(live), 1)
        self.assertEqual(live[0].cpu, 10.0)

    def test_the_bucket_averages_what_it_was_handed(self):
        # Handed the samples rather than reaching for the attribute, which is
        # the whole of the fix above.
        self.sampler._pending = []
        sample = self.sampler._bucket(100.0, [(10.0, 40.0, 20.0), (30.0, None, 40.0)])
        self.assertEqual(sample.cpu, 20.0)
        self.assertEqual(sample.cpu_peak, 30.0)
        self.assertEqual(sample.temp, 40.0)
        self.assertEqual(sample.memory, 30.0)

def _times(idle: float, user: float):
    """A cpu_times() tuple with only the two fields the code reads."""
    from collections import namedtuple
    Times = namedtuple("Times", "user nice system idle iowait")
    return Times(user=user, nice=0.0, system=0.0, idle=idle, iowait=0.0)


class FirstReadingTest(BackendTestCase):
    """The first request after a start, which has no earlier reading to compare with."""

    def test_the_cores_are_measured_not_compared_with_a_call_that_never_was(self):
        # psutil as it behaves: with interval=None it measures since the
        # previous call and gives 0.0 per core when there was none. The screen
        # then showed "CPU 71%" above four cores at 0%.
        def cpu_percent(interval=None, percpu=False):
            if interval is None:
                return [0.0, 0.0, 0.0, 0.0] if percpu else 0.0
            return [60.0, 80.0, 70.0, 74.0] if percpu else 71.0

        with patch.object(system_router.psutil, "cpu_percent", side_effect=cpu_percent):
            cpu = system_router.system_metrics()["cpu"]
        self.assertEqual(cpu["per_core"], [60.0, 80.0, 70.0, 74.0])
        self.assertEqual(cpu["percent"], 71.0)
