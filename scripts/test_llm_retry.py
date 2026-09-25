# scripts/test_llm_retry.py
"""Verifies pipeline/llm_retry.py's retry/backoff without touching the
real Anthropic API — simulates 500/529/400 via fake HTTP responses."""
import httpx
import anthropic
from pipeline.llm_retry import create_with_retry


def _make_error(status_code: int):
    resp = httpx.Response(status_code, request=httpx.Request(
        "POST", "https://api.anthropic.com/v1/messages"))
    if status_code == 400:
        return anthropic.BadRequestError("bad", response=resp, body=None)
    if status_code == 529:
        from anthropic._exceptions import OverloadedError
        return OverloadedError("overloaded", response=resp, body=None)
    return anthropic.InternalServerError("boom", response=resp, body=None)


class _FlakyMessages:
    def __init__(self, outer):
        self.outer = outer

    def create(self, **kwargs):
        self.outer.calls += 1
        if self.outer.calls <= self.outer.fail_times:
            raise _make_error(self.outer.status_code)
        return "ok"


class _FlakyClient:
    def __init__(self, fail_times: int, status_code: int):
        self.fail_times = fail_times
        self.status_code = status_code
        self.calls = 0
        self.messages = _FlakyMessages(self)


def _run(fail_times, status_code):
    return create_with_retry(_FlakyClient(fail_times, status_code), model="x", max_tokens=1, messages=[])


assert _run(2, 500) == "ok"
assert _run(2, 529) == "ok"
try:
    _run(99, 500)
    raise AssertionError("should have raised")
except anthropic.InternalServerError:
    pass
try:
    _run(99, 400)
    raise AssertionError("should have raised")
except anthropic.BadRequestError:
    pass
print("All retry/backoff behavior verified.")
