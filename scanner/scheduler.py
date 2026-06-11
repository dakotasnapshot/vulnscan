"""In-process scan scheduler.

Evaluates rows in the ``scan_schedules`` table and fires scans when they come
due. Pure stdlib — no croniter/APScheduler — to keep VulnScan dependency-free.

Supports standard 5-field cron expressions:

    minute  hour  day-of-month  month  day-of-week

Each field accepts ``*``, single values, comma lists, ``a-b`` ranges, and
``*/step`` or ``a-b/step`` steps. Day-of-week is 0-6 with 0 = Sunday (``7`` is
also accepted as Sunday). This covers the expressions the dashboard offers
(``0 2 * * *``, ``*/30 * * * *``, ``0 3 * * 0`` …) and most hand-written ones.
"""

import logging
import threading
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("vulnscan.scheduler")

# How often the scheduler wakes to look for due jobs.
TICK_SECONDS = 30

_FIELD_BOUNDS = [
    (0, 59),   # minute
    (0, 23),   # hour
    (1, 31),   # day of month
    (1, 12),   # month
    (0, 6),    # day of week (0 = Sunday)
]


def _parse_field(field: str, lo: int, hi: int) -> set[int]:
    """Expand one cron field into the explicit set of values it matches."""
    values: set[int] = set()
    for part in field.split(","):
        part = part.strip()
        if not part:
            continue
        step = 1
        if "/" in part:
            base, step_str = part.split("/", 1)
            step = int(step_str)
            if step <= 0:
                raise ValueError(f"invalid step in cron field: {part}")
        else:
            base = part

        if base in ("*", ""):
            start, end = lo, hi
        elif "-" in base:
            start_str, end_str = base.split("-", 1)
            start, end = int(start_str), int(end_str)
        else:
            start = end = int(base)

        if start < lo or end > hi or start > end:
            raise ValueError(f"cron field out of range: {part}")
        values.update(range(start, end + 1, step))
    return values


def _matches(dt: datetime, fields: list[set[int]]) -> bool:
    minute, hour, dom, month, dow = fields
    # Cron day-of-week: 0 and 7 both mean Sunday. Python weekday(): Mon=0..Sun=6.
    py_dow = (dt.weekday() + 1) % 7  # convert to cron Sun=0..Sat=6
    if dt.minute not in minute:
        return False
    if dt.hour not in hour:
        return False
    if dt.month not in month:
        return False
    # Standard cron semantics: when BOTH dom and dow are restricted (not '*'),
    # a match on EITHER is sufficient. Detect restriction by comparing to the
    # full range.
    dom_restricted = dom != set(range(1, 32))
    dow_restricted = dow != set(range(0, 7))
    dom_ok = dt.day in dom
    dow_ok = py_dow in dow
    if dom_restricted and dow_restricted:
        return dom_ok or dow_ok
    return dom_ok and dow_ok


def compute_next_run(cron_expr: str, after: datetime | None = None) -> str | None:
    """Return ISO-8601 (UTC) timestamp of the next time ``cron_expr`` fires.

    Returns None if the expression is malformed. Searches up to ~4 years out so
    sparse expressions (e.g. ``0 0 29 2 *``) still resolve.
    """
    parts = cron_expr.split()
    if len(parts) != 5:
        logger.warning("ignoring non-5-field cron expression: %r", cron_expr)
        return None
    try:
        fields = [_parse_field(p, lo, hi) for p, (lo, hi) in zip(parts, _FIELD_BOUNDS)]
    except (ValueError, TypeError) as e:
        logger.warning("unparseable cron expression %r: %s", cron_expr, e)
        return None

    base = (after or datetime.now(timezone.utc)).astimezone(timezone.utc)
    # Start at the next whole minute; cron has minute resolution.
    candidate = base.replace(second=0, microsecond=0) + timedelta(minutes=1)
    limit = candidate + timedelta(days=366 * 4)
    while candidate <= limit:
        if _matches(candidate, fields):
            return candidate.isoformat()
        candidate += timedelta(minutes=1)
    return None


class SchedulerThread(threading.Thread):
    """Daemon thread that fires due scans and reschedules them.

    Decoupled from the scan implementation via the ``scan_host``/``scan_all``
    callables so it is easy to test and avoids import cycles.
    """

    def __init__(self, db_module, scan_host, scan_all, tick_seconds: int = TICK_SECONDS):
        super().__init__(daemon=True, name="vulnscan-scheduler")
        self._db = db_module
        self._scan_host = scan_host
        self._scan_all = scan_all
        self._tick = tick_seconds
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        logger.info("Scheduler started (tick=%ss)", self._tick)
        # Backfill next_run for any enabled schedule missing one.
        self._backfill_next_runs()
        while not self._stop.is_set():
            try:
                self._tick_once()
            except Exception:  # never let the loop die
                logger.exception("scheduler tick failed")
            self._stop.wait(self._tick)

    def _backfill_next_runs(self):
        try:
            for sched in self._db.list_scan_schedules():
                if sched.get("enabled") and not sched.get("next_run"):
                    nxt = compute_next_run(sched["cron_expr"])
                    if nxt:
                        self._db.update_scan_schedule(sched["id"], next_run=nxt)
        except Exception:
            logger.exception("failed to backfill next_run values")

    def _tick_once(self):
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        for sched in self._db.list_scan_schedules():
            if not sched.get("enabled"):
                continue
            next_run = sched.get("next_run")
            if not next_run:
                nxt = compute_next_run(sched["cron_expr"], now)
                if nxt:
                    self._db.update_scan_schedule(sched["id"], next_run=nxt)
                continue
            if next_run <= now_iso:
                self._fire(sched, now_iso)

    def _fire(self, sched: dict, now_iso: str):
        name = sched.get("name", sched["id"])
        host_id = sched.get("host_id")
        # Reschedule BEFORE running so a long scan can't cause a missed-tick
        # double fire, and a crash mid-scan still advances the timer.
        next_run = compute_next_run(sched["cron_expr"])
        self._db.update_scan_schedule(
            sched["id"], last_run=now_iso, next_run=next_run
        )
        logger.info("Firing schedule %r (host_id=%s); next run %s", name, host_id, next_run)

        def _runner():
            try:
                if host_id:
                    self._scan_host(int(host_id))
                else:
                    self._scan_all()
            except Exception:
                logger.exception("scheduled scan for %r failed", name)

        threading.Thread(target=_runner, daemon=True, name=f"sched-scan-{sched['id']}").start()


if __name__ == "__main__":
    # Self-test of the cron math — run directly: python3 -m scanner.scheduler
    import sys

    def _check(expr, after_iso, expect_iso):
        after = datetime.fromisoformat(after_iso)
        got = compute_next_run(expr, after)
        ok = got == expect_iso
        print(f"{'ok ' if ok else 'FAIL'} {expr!r:18} after {after_iso} -> {got} (want {expect_iso})")
        return ok

    base = "2026-06-11T14:24:00+00:00"
    all_ok = all([
        _check("*/30 * * * *", base, "2026-06-11T14:30:00+00:00"),
        _check("0 2 * * *", base, "2026-06-12T02:00:00+00:00"),
        _check("0 3 * * 0", base, "2026-06-14T03:00:00+00:00"),   # next Sunday
        _check("15 10 1 * *", base, "2026-07-01T10:15:00+00:00"),
        _check("0 0 29 2 *", base, "2028-02-29T00:00:00+00:00"),  # leap-year only
        _check("*/15 9-17 * * 1-5", base, "2026-06-11T14:30:00+00:00"),
    ])
    print("ALL PASS" if all_ok else "SOME FAILED")
    sys.exit(0 if all_ok else 1)
