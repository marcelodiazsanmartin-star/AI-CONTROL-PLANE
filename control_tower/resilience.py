"""Resilience, bounded timeouts, circuit breakers, and backoff with jitter for CONTROL TOWER CT-04."""

from __future__ import annotations

import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from control_tower.logging import tower_logger
from control_tower.models import AdapterResult, SourceStatus
from control_tower.security import sanitize_error

DEFAULT_ADAPTER_TIMEOUT_SECONDS = 2.0
DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_RECOVERY_TIMEOUT_SECONDS = 10.0
MAX_WORKER_THREADS = 4
MAX_BACKOFF_DELAY_SECONDS = 2.0
BASE_BACKOFF_DELAY_SECONDS = 0.1
DEFAULT_MAX_RETRIES = 1  # 1 retry on recoverable timeout/exception


MAX_PENDING_QUEUE_DEPTH = 4


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


def calculate_backoff_delay(
    attempt: int,
    base_delay: float = BASE_BACKOFF_DELAY_SECONDS,
    max_delay: float = MAX_BACKOFF_DELAY_SECONDS,
    jitter_fraction: float = 0.2,
    random_seed: int | None = None,
) -> float:
    """Calculate exponential backoff with bounded additive jitter.

    Guaranteed properties:
    1. Result is >= 0.0 (non-negative).
    2. Result is <= max_delay * 1.5 (strictly upper-bounded).
    3. Monotonically scales with attempt up to cap.
    """
    if attempt < 0:
        attempt = 0
    raw_delay = min(max_delay, base_delay * (2 ** attempt))
    jitter_bound = raw_delay * jitter_fraction

    rng = random.Random(random_seed) if random_seed is not None else random
    jitter = rng.uniform(-jitter_bound, jitter_bound)
    final_delay = max(0.0, min(max_delay * 1.5, raw_delay + jitter))
    return round(final_delay, 4)


class CircuitBreaker:
    """Per-adapter circuit breaker to isolate slow, hung, or failing upstream sources."""

    def __init__(
        self,
        source_id: str,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        recovery_timeout_seconds: float = DEFAULT_RECOVERY_TIMEOUT_SECONDS,
    ) -> None:
        self.source_id = source_id
        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self.state: CircuitState = CircuitState.CLOSED
        self.consecutive_failures: int = 0
        self.last_failure_time: float = 0.0
        self.last_success_time: float = 0.0
        self._lock = threading.Lock()

    def allow_request(self) -> bool:
        """Check if circuit allows request execution."""
        with self._lock:
            if self.state is CircuitState.CLOSED:
                return True
            now = time.monotonic()
            if self.state is CircuitState.OPEN:
                if now - self.last_failure_time >= self.recovery_timeout_seconds:
                    self.state = CircuitState.HALF_OPEN
                    return True
                return False
            if self.state is CircuitState.HALF_OPEN:
                return True
            return False

    def record_success(self) -> None:
        """Record a successful execution, closing the circuit."""
        with self._lock:
            self.consecutive_failures = 0
            self.state = CircuitState.CLOSED
            self.last_success_time = time.monotonic()

    def record_failure(self) -> None:
        """Record a failed/timed out execution, tripping circuit if threshold reached."""
        with self._lock:
            self.consecutive_failures += 1
            self.last_failure_time = time.monotonic()
            if self.consecutive_failures >= self.failure_threshold:
                self.state = CircuitState.OPEN


class ResilientAdapterExecutor:
    """Bounded executor that runs adapters with timeouts, circuit breakers, backoff, admission control, and logging."""

    def __init__(
        self,
        timeout_seconds: float = DEFAULT_ADAPTER_TIMEOUT_SECONDS,
        max_workers: int = MAX_WORKER_THREADS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        max_queue_depth: int = MAX_PENDING_QUEUE_DEPTH,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_workers = max_workers
        self.max_retries = max_retries
        self.max_queue_depth = max_queue_depth
        self._executor: ThreadPoolExecutor | None = None
        self._is_shutdown = False
        self._breakers: dict[str, CircuitBreaker] = {}
        self._last_known_results: dict[str, AdapterResult] = {}
        self._lock = threading.Lock()
        self._admission_semaphore = threading.BoundedSemaphore(self.max_workers + self.max_queue_depth)

    def _get_executor(self) -> ThreadPoolExecutor:
        with self._lock:
            if self._executor is None or self._is_shutdown:
                self._executor = ThreadPoolExecutor(
                    max_workers=self.max_workers,
                    thread_name_prefix="TowerAdapter",
                )
                self._is_shutdown = False
            return self._executor

    def get_breaker(self, source_id: str) -> CircuitBreaker:
        """Get or create circuit breaker for source_id."""
        with self._lock:
            if source_id not in self._breakers:
                self._breakers[source_id] = CircuitBreaker(source_id)
            return self._breakers[source_id]

    def _execute_single_attempt(
        self,
        adapter_func: Callable[[datetime], AdapterResult],
        source_id: str,
        now: datetime,
    ) -> tuple[AdapterResult | None, str | None, Exception | None]:
        """Submit and wait for adapter execution bounded by timeout, admission capacity, and release-once ownership."""
        admitted = self._admission_semaphore.acquire(blocking=False)
        if not admitted:
            return None, "CAPACITY_EXHAUSTED", None

        lease_lock = threading.Lock()
        lease_released = False

        def release_once() -> None:
            nonlocal lease_released
            with lease_lock:
                if not lease_released:
                    lease_released = True
                    try:
                        self._admission_semaphore.release()
                    except ValueError:
                        pass

        def adapter_worker_wrapper() -> AdapterResult:
            try:
                return adapter_func(now)
            finally:
                release_once()

        try:
            executor = self._get_executor()
            future = executor.submit(adapter_worker_wrapper)
        except Exception as e:
            # Submission failed before Future creation; release permit immediately
            release_once()
            return None, "EXCEPTION", e

        try:
            future.add_done_callback(lambda fut: release_once())
        except Exception:
            # If callback registration fails, attempt cancellation. If cancelled before start,
            # release permit; if already running on worker thread, wrapper finally will release.
            if future.cancel():
                release_once()

        try:
            res = future.result(timeout=self.timeout_seconds)
            return res, None, None
        except FutureTimeoutError:
            # Slot remains held by running background worker until completion, providing true backpressure
            return None, "TIMEOUT", None
        except Exception as e:
            return None, "EXCEPTION", e

    def execute_adapter(
        self,
        adapter_func: Callable[[datetime], AdapterResult],
        source_id: str,
        source_kind: str,
        source_ref: str,
        freshness_sla_seconds: float,
        now: datetime,
    ) -> AdapterResult:
        """Execute adapter safely within bounded timeout, circuit breaker, and retry."""
        breaker = self.get_breaker(source_id)
        start_time = time.monotonic()

        if not breaker.allow_request():
            latency = (time.monotonic() - start_time) * 1000
            tower_logger.log(
                component=source_id,
                result_class="CIRCUIT_BREAKER_OPEN",
                latency_ms=latency,
                error_code="CIRCUIT_BREAKER_OPEN",
                error_detail="Circuit breaker is open due to repeated failures",
            )
            last_known = self._last_known_results.get(source_id)
            return AdapterResult(
                source_id=source_id,
                source_kind=source_kind,
                source_ref=source_ref,
                fetched_at=now.isoformat(),
                observed_at=last_known.observed_at if last_known else None,
                freshness_sla_seconds=freshness_sla_seconds,
                status=SourceStatus.DEGRADED,
                adapter_health=SourceStatus.DEGRADED,
                truth_status=SourceStatus.DEGRADED,
                last_known_status=last_known.last_known_status if last_known else None,
                last_known_conflict=last_known.last_known_conflict if last_known else None,
                last_known_observed_at=last_known.last_known_observed_at if last_known else None,
                payload=last_known.payload if last_known else {},
                provenance=last_known.provenance if last_known else None,
                error_code="CIRCUIT_BREAKER_OPEN",
                error_detail=f"Circuit breaker OPEN for {source_id}",
            )

        attempts_allowed = 1 + self.max_retries
        for attempt in range(attempts_allowed):
            res, failure_type, exc = self._execute_single_attempt(adapter_func, source_id, now)

            if res is not None:
                latency = (time.monotonic() - start_time) * 1000
                if res.truth_status in (SourceStatus.HEALTHY, SourceStatus.STALE):
                    breaker.record_success()
                    with self._lock:
                        self._last_known_results[source_id] = res
                    tower_logger.log(
                        component=source_id,
                        result_class=res.truth_status.value,
                        latency_ms=latency,
                    )
                else:
                    breaker.record_failure()
                    tower_logger.log(
                        component=source_id,
                        result_class=res.truth_status.value,
                        latency_ms=latency,
                        error_code=res.error_code,
                        error_detail=res.error_detail,
                    )
                return res

            if attempt < attempts_allowed - 1:
                # Apply exponential backoff delay with bounded jitter before retry
                backoff_s = calculate_backoff_delay(attempt=attempt)
                time.sleep(min(backoff_s, 0.1))  # Keep in-process sleep small

        # If loop exhausts without success
        latency = (time.monotonic() - start_time) * 1000
        breaker.record_failure()

        if failure_type == "CAPACITY_EXHAUSTED":
            tower_logger.log(
                component=source_id,
                result_class="CAPACITY_EXHAUSTED",
                latency_ms=latency,
                error_code="CAPACITY_EXHAUSTED",
                error_detail="Executor admission queue exhausted due to hung workers",
            )
            last_known = self._last_known_results.get(source_id)
            return AdapterResult(
                source_id=source_id,
                source_kind=source_kind,
                source_ref=source_ref,
                fetched_at=now.isoformat(),
                observed_at=last_known.observed_at if last_known else None,
                freshness_sla_seconds=freshness_sla_seconds,
                status=SourceStatus.UNKNOWN,
                adapter_health=SourceStatus.DEGRADED,
                truth_status=SourceStatus.UNKNOWN,
                last_known_status=last_known.last_known_status if last_known else None,
                last_known_conflict=last_known.last_known_conflict if last_known else None,
                last_known_observed_at=last_known.last_known_observed_at if last_known else None,
                payload=last_known.payload if last_known else {},
                provenance=last_known.provenance if last_known else None,
                error_code="CAPACITY_EXHAUSTED",
                error_detail="Executor admission capacity exhausted",
            )
        elif failure_type == "TIMEOUT":
            tower_logger.log(
                component=source_id,
                result_class="TIMEOUT",
                latency_ms=latency,
                error_code="ADAPTER_TIMEOUT",
                error_detail=f"Adapter execution exceeded {self.timeout_seconds}s limit",
            )
            last_known = self._last_known_results.get(source_id)
            return AdapterResult(
                source_id=source_id,
                source_kind=source_kind,
                source_ref=source_ref,
                fetched_at=now.isoformat(),
                observed_at=last_known.observed_at if last_known else None,
                freshness_sla_seconds=freshness_sla_seconds,
                status=SourceStatus.UNKNOWN,
                adapter_health=SourceStatus.DEGRADED,
                truth_status=SourceStatus.UNKNOWN,
                last_known_status=last_known.last_known_status if last_known else None,
                last_known_conflict=last_known.last_known_conflict if last_known else None,
                last_known_observed_at=last_known.last_known_observed_at if last_known else None,
                payload=last_known.payload if last_known else {},
                provenance=last_known.provenance if last_known else None,
                error_code="ADAPTER_TIMEOUT",
                error_detail=f"Adapter timed out after {self.timeout_seconds}s",
            )
        else:
            tower_logger.log(
                component=source_id,
                result_class="EXCEPTION",
                latency_ms=latency,
                error_code=type(exc).__name__ if exc else "EXECUTION_ERROR",
                error_detail=sanitize_error(exc) if exc else "Unknown error",
            )
            return AdapterResult(
                source_id=source_id,
                source_kind=source_kind,
                source_ref=source_ref,
                fetched_at=now.isoformat(),
                observed_at=None,
                freshness_sla_seconds=freshness_sla_seconds,
                status=SourceStatus.UNKNOWN,
                adapter_health=SourceStatus.UNKNOWN,
                truth_status=SourceStatus.UNKNOWN,
                last_known_status=None,
                last_known_conflict=None,
                last_known_observed_at=None,
                payload={},
                provenance=None,
                error_code=type(exc).__name__ if exc else "EXECUTION_ERROR",
                error_detail=sanitize_error(exc) if exc else "Unknown error",
            )

    def shutdown(self, wait: bool = False) -> None:
        """Gracefully shutdown worker threads without resetting persistent admission bounds."""
        with self._lock:
            if self._executor is not None:
                self._executor.shutdown(wait=wait, cancel_futures=True)
                self._executor = None
            self._is_shutdown = True


# Global resilient executor instance
resilient_executor = ResilientAdapterExecutor()
