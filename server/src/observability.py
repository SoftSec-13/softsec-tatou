"""Observability helpers for Tatou.

This module provides lightweight in-process metrics collection and
structured event helpers without adding external dependencies. Metrics
are exposed in Prometheus text exposition format via the /metrics
endpoint (see server.py for route registration).

Design goals:
 - Zero third-party dependency (no prometheus_client) to keep the
   educational environment simple.
 - Low cardinality labels (method, route template, status, reason)
   to avoid unbounded metric growth.
 - Thread-safe updates using a single lock (sufficient for modest
   throughput typical of coursework deployments).

NOTE: Under a multi-process server (e.g. gunicorn with multiple
workers) each process maintains its own counters; aggregate at scrape
time by summing across targets if needed.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from time import time


@dataclass(slots=True)
class CounterMetric:
    name: str
    help: str
    # key: tuple(label_values) -> value
    values: dict[tuple[str, ...], float]
    label_names: tuple[str, ...]

    def inc(self, *label_values: str, amount: float = 1.0) -> None:
        if len(label_values) != len(self.label_names):  # defensive
            raise ValueError("Label cardinality mismatch")
        key = tuple(label_values)
        self.values[key] = self.values.get(key, 0.0) + amount

    def render(self) -> str:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} counter"]
        for labels, value in sorted(self.values.items()):
            label_frag = ",".join(
                f"{k}={_quote(v)}"
                for k, v in zip(self.label_names, labels, strict=True)
            )
            lines.append(f"{self.name}{{{label_frag}}} {value}")
        return "\n".join(lines)


@dataclass(slots=True)
class HistogramMetric:
    name: str
    help: str
    label_names: tuple[str, ...]
    # buckets in ascending order
    buckets: tuple[float, ...]
    # mapping: (labels, bucket_le) -> count; special +Inf bucket
    counts: dict[tuple[tuple[str, ...], float], int]
    sums: dict[tuple[str, ...], float]

    def observe(self, value: float, *label_values: str) -> None:
        if len(label_values) != len(self.label_names):
            raise ValueError("Label cardinality mismatch")
        labels = tuple(label_values)
        # increment buckets
        placed = False
        for b in self.buckets:
            if value <= b:
                self.counts[(labels, b)] = self.counts.get((labels, b), 0) + 1
                placed = True
        # Always increment +Inf
        inf_key = (labels, float("inf"))
        self.counts[inf_key] = self.counts.get(inf_key, 0) + 1
        if not placed:
            # value was greater than all buckets, only +Inf updated above
            pass
        self.sums[labels] = self.sums.get(labels, 0.0) + value

    def render(self) -> str:
        # Prometheus histogram:
        # <name>_bucket{le="0.5",...} <count>
        # <name>_bucket{le="+Inf",...} <count>
        # <name>_sum{...} <sum>
        # <name>_count{...} <total>
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} histogram"]
        # Group by label set
        label_sets = sorted({lbl for (lbl, _le) in self.counts.keys()})
        for labels in label_sets:
            cumulative = 0
            for b in self.buckets + (float("inf"),):
                c = self.counts.get((labels, b), 0)
                cumulative = c  # counts stored as cumulative already for <= logic
                b_label = "+Inf" if b == float("inf") else repr(b)
                label_frag = ",".join(
                    f"{k}={_quote(v)}"
                    for k, v in zip(self.label_names, labels, strict=True)
                )
                lines.append(
                    f"{self.name}_bucket{{{label_frag},le={_quote(b_label)}}}"
                    f" {cumulative}"
                )
            total = self.counts.get((labels, float("inf")), 0)
            label_frag = ",".join(
                f"{k}={_quote(v)}"
                for k, v in zip(self.label_names, labels, strict=True)
            )
            lines.append(
                f"{self.name}_sum{{{label_frag}}} {self.sums.get(labels, 0.0)}"
            )
            lines.append(f"{self.name}_count{{{label_frag}}} {total}")
        return "\n".join(lines)


def _quote(v: str) -> str:
    return '"' + v.replace('"', '\\"') + '"'


_lock = Lock()

# ------------------ Metric registry ------------------
REQUESTS = CounterMetric(
    name="tatou_http_requests_total",
    help="Total HTTP requests",
    label_names=("method", "route", "status"),
    values={},
)
REQUEST_LATENCY = HistogramMetric(
    name="tatou_http_request_duration_seconds",
    help="Latency in seconds of HTTP requests",
    label_names=("method", "route"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    counts={},
    sums={},
)
LOGIN_FAILURES = CounterMetric(
    name="tatou_login_failures_total",
    help="Number of failed login attempts",
    label_names=("reason",),
    values={},
)
WATERMARK_CREATED = CounterMetric(
    name="tatou_watermarks_created_total",
    help="Watermarks created",
    label_names=("method",),
    values={},
)
WATERMARK_READ = CounterMetric(
    name="tatou_watermarks_read_total",
    help="Watermarks read",
    label_names=("method",),
    values={},
)
UPLOADS = CounterMetric(
    name="tatou_uploads_total",
    help="Number of PDF uploads",
    label_names=(),
    values={},
)
UPLOAD_BYTES = CounterMetric(
    name="tatou_upload_bytes_total",
    help="Aggregate size in bytes of uploaded PDFs",
    label_names=(),
    values={},
)
SUSPICIOUS = CounterMetric(
    name="tatou_suspicious_events_total",
    help="Suspicious validation / probing events",
    label_names=("reason",),
    values={},
)
DB_ERRORS = CounterMetric(
    name="tatou_db_errors_total",
    help="Database operation errors",
    label_names=("operation",),
    values={},
)

_ALL = [
    REQUESTS,
    REQUEST_LATENCY,
    LOGIN_FAILURES,
    WATERMARK_CREATED,
    WATERMARK_READ,
    UPLOADS,
    UPLOAD_BYTES,
    SUSPICIOUS,
    DB_ERRORS,
]


def record_request(method: str, route: str, status: int, duration: float) -> None:
    with _lock:
        REQUESTS.inc(method, route, str(status))
        REQUEST_LATENCY.observe(duration, method, route)


def inc_login_failure(reason: str) -> None:
    with _lock:
        LOGIN_FAILURES.inc(reason)


def inc_watermark_created(method: str) -> None:
    with _lock:
        WATERMARK_CREATED.inc(method)


def inc_watermark_read(method: str) -> None:
    with _lock:
        WATERMARK_READ.inc(method)


def inc_upload(size: int) -> None:
    with _lock:
        UPLOADS.inc()
        UPLOAD_BYTES.inc(amount=float(size))


def inc_suspicious(reason: str) -> None:
    with _lock:
        SUSPICIOUS.inc(reason)


def inc_db_error(op: str) -> None:
    with _lock:
        DB_ERRORS.inc(op)


def render_prometheus() -> str:
    parts = [m.render() for m in _ALL]  # type: ignore[attr-defined]
    return "\n".join(parts) + "\n"


# Convenience timer context manager (not widely used yet, but available)
class Timer:
    def __enter__(self):
        self._start = time()
        return self

    def __exit__(self):
        self.elapsed = time() - self._start
        return False
