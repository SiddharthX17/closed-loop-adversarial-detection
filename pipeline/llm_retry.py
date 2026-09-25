"""
pipeline/llm_retry.py

Shared retry/backoff wrapper for Anthropic API calls. Retries only on
transient, request-independent failures (rate limits, server overload,
5xx, network/timeout) — never on 4xx errors like BadRequestError, since
those mean the request itself was malformed and retrying it unchanged
will fail identically every time.

Drop-in replacement for `client.messages.create(**kwargs)`. On exhausted
retries, re-raises the last exception unchanged — every call site's
existing try/except around `.messages.create(...)` catches it exactly as
before, so no caller-side exception handling needs to change.
"""

import os
import anthropic
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception


def _log_retry(retry_state):
    if os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true"):
        exc = retry_state.outcome.exception()
        print(f"[llm_retry] attempt {retry_state.attempt_number} failed "
              f"({type(exc).__name__}) — retrying")


_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504, 529}


def _is_retryable(exc: BaseException) -> bool:
    # Covers APITimeoutError too — it subclasses APIConnectionError.
    if isinstance(exc, anthropic.APIConnectionError):
        return True
    if isinstance(exc, anthropic.APIStatusError):
        return exc.status_code in _RETRYABLE_STATUS_CODES
    return False


@retry(
    retry=retry_if_exception(_is_retryable),
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=1, min=2, max=20),
    reraise=True,
    before_sleep=_log_retry,
)
def create_with_retry(client: anthropic.Anthropic, **kwargs):
    return client.messages.create(**kwargs)
