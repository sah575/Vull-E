import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")


class RagIndexBatchError(RuntimeError):
    pass


@dataclass
class RetryPolicy:
    attempts: int
    base_delay_seconds: float
    sleep: Callable[[float], None] = time.sleep


def batched(items: Sequence[T], batch_size: int) -> Iterable[list[T]]:
    if batch_size <= 0:
        raise ValueError("batch_size must be greater than zero")
    for start in range(0, len(items), batch_size):
        yield list(items[start : start + batch_size])


def batch_count(item_count: int, batch_size: int) -> int:
    if item_count == 0:
        return 0
    return (item_count + batch_size - 1) // batch_size


def run_with_retry(
    operation: Callable[[], R],
    *,
    operation_name: str,
    batch_number: int,
    total_batches: int,
    policy: RetryPolicy,
) -> tuple[R, int]:
    failures = 0
    max_attempts = max(policy.attempts, 1)
    last_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return operation(), failures
        except Exception as exc:
            failures += 1
            last_error = exc
            if attempt >= max_attempts:
                break
            policy.sleep(policy.base_delay_seconds * attempt)
    error_type = last_error.__class__.__name__ if last_error else "UnknownError"
    raise RagIndexBatchError(
        f"{operation_name} batch {batch_number}/{total_batches} failed after "
        f"{max_attempts} attempt(s): {error_type}"
    ) from last_error
