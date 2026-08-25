"""Resilience, bounded timeouts, circuit breakers, and backoff with jitter for CONTROL TOWER CT-03."""

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
    2. Result is <= max_delay + jitter_bound (strictly upper-bounded).
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
    """Bounded executor that runs adapters with timeouts, circuit breakers, and logging."""

    def __init__(
        self,
        timeout_seconds: float = DEFAULT_ADAPTER_TIMEOUT_SECONDS,
        max_workers: int = MAX_WORKER_THREADS,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="TowerAdapter")
        self._breakers: dict[str, CircuitBreaker] = {}
        self._last_known_results: dict[str, AdapterResult] = {}
        self._lock = threading.Lock()

    def get_breaker(self, source_id: str) -> CircuitBreaker:
        """Get or create circuit breaker for source_id."""
        with self._lock:
            if source_id not in self._breakers:
                self._breakers[source_id] = CircuitBreaker(source_id)
            return self._breakers[source_id]

    def execute_adapter(
        self,
        adapter_func: Callable[[datetime], AdapterResult],
        source_id: str,
        source_kind: str,
        source_ref: str,
        freshness_sla_seconds: float,
        now: datetime,
    ) -> AdapterResult:
        """Execute adapter safely within bounded timeout and circuit breaker."""
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

        future = self._executor.submit(adapter_func, now)
        try:
            result = future.result(timeout=self.timeout_seconds)
            latency = (time.monotonic() - start_time) * 1000

            if result.truth_status in (SourceStatus.HEALTHY, SourceStatus.STALE):
                breaker.record_success()
                with self._lock:
                    self._last_known_results[source_id] = result
                tower_logger.log(
                    component=source_id,
                    result_class=result.truth_status.value,
                    latency_ms=latency,
                )
            else:
                breaker.record_failure()
                tower_logger.log(
                    component=source_id,
                    result_class=result.truth_status.value,
                    latency_ms=latency,
                    error_code=result.error_code,
                    error_detail=result.error_detail,
                )
            return result
        except FutureTimeoutError:
            latency = (time.monotonic() - start_time) * 1000
            breaker.record_failure()
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
        except Exception as e:
            latency = (time.monotonic() - start_time) * 1000
            breaker.record_failure()
            tower_logger.log(
                component=source_id,
                result_class="EXCEPTION",
                latency_ms=latency,
                error_code=type(e).__name__,
                error_detail=sanitize_error(e),
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
                error_code=type(e).__name__,
                error_detail=sanitize_error(e),
            )

    def shutdown(self, wait: bool = True) -> None:
        """Gracefully shutdown worker threads."""
        self._executor.shutdown(wait=wait, cancel_futures=True)


# Global resilient executor instance
resilient_executor = ResilientAdapterExecutor()
