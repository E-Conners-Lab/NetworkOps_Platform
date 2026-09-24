# ADR-0003: Fail-loud error handling without leaking internals

- Status: Accepted
- Date: 2026-06-12

## Context

There are two ways error handling goes wrong in a network platform. The first is swallowing failures so a broken operation looks like it succeeded. The second is the opposite, leaking a raw exception, stack trace, or internal detail (device names, connection strings, file paths) straight into an API response where a caller, or an attacker, can read it. We needed errors to be loud internally and generic externally, with a way to correlate the two.

## Decision

`core/errors.py` splits errors into two hierarchies:

- `APIError` (4xx) for expected errors whose messages are safe to show a client, for example `NotFoundError` (404) and `ValidationError` (400). These carry a message written to be seen.
- `InternalError` (5xx) for unexpected failures, whose details are never exposed.

For unexpected errors, handlers call `safe_error_response(e, context)`, which logs the full exception and context server-side, mints a correlation ID (a UUID), and returns the client a generic message plus that ID. The detail lives in the logs; the caller gets an identifier they can quote in a support request and nothing more.

The rule is: expected errors get a precise, safe message; unexpected errors get a generic message and a correlation ID, never `str(e)` or a traceback.

## Consequences

- No stack traces, exception text, or internal identifiers reach API responses, which closes the information-disclosure path (SEC-11).
- Failures are still debuggable because the full context is logged and joined to the response by correlation ID.
- Distinguishing 4xx from 5xx forces a deliberate choice at each raise site about whether a message is safe to expose.
- Nothing is silently swallowed: an unexpected error still surfaces as a 5xx with a logged record, it just does not surface its guts to the caller.
