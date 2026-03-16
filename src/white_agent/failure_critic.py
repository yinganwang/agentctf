"""FailureCritic — signal-matching failure classifier, no LLM by default.

After every bash command execution, the white agent calls classify_failure()
before deciding whether to retry, inject a repair hint, or escalate to an LLM call.
LLM is only used when failure class is UNKNOWN (no signal matched).
"""

from dataclasses import dataclass
from enum import Enum


class FailureClass(str, Enum):
    CONNECTIVITY = "connectivity"
    ENDPOINT_404 = "endpoint_404"
    PAYLOAD_FORMAT = "payload_format"
    PAYLOAD_EXECUTION_BLOCKED = "payload_execution_blocked"
    AUTH_REQUIRED = "auth_required"
    EMPTY_RESPONSE = "empty_response"
    UNKNOWN = "unknown"


@dataclass
class FailureAnalysis:
    failure_class: FailureClass
    repair_hint: str   # injected verbatim into the next LLM/retry message
    requires_llm: bool  # True only when class == UNKNOWN


# ── Signal tables ──────────────────────────────────────────────────────────────

CONNECTIVITY_SIGNALS: list[str] = [
    "could not resolve host",
    "connection refused",
    "curl: (6)",
    "curl: (7)",
    "curl: (28)",   # timeout
    "name or service not known",
    "failed to connect",
    "no route to host",
    "network unreachable",
]

AUTH_SIGNALS: list[str] = [
    '"status":401',
    '"status": 401',
    "401 unauthorized",
    "http/1.1 401",
    "http/2 401",
    '"status":403',
    '"status": 403',
    "403 forbidden",
    "http/1.1 403",
    "http/2 403",
    "unauthorized",
    "forbidden",
    "authentication required",
    "access denied",
]

ENDPOINT_404_SIGNALS: list[str] = [
    '"status":404',
    '"status": 404',
    "404 not found",
    "http/1.1 404",
    "http/2 404",
    "not found",
    "no such route",
    "no route found",
    "path not found",
    "endpoint not found",
]

PAYLOAD_FORMAT_SIGNALS: list[str] = [
    '"status":422',
    '"status": 422',
    "422 unprocessable",
    "unprocessable entity",
    "http/1.1 422",
    "http/2 422",
    "field required",
    "validation error",
    "value_error",
    "missing field",
    "extra inputs are not permitted",
    "invalid json",
    '"detail":[',  # FastAPI validation error array
    "type_error",
]

PAYLOAD_BLOCKED_SIGNALS: list[str] = [
    "undefinederror",
    "securityerror",
    "nameerror",
    "sandbox",
    "blocked",
    "templateerror",
    "template syntax error",
    "jinja2.exceptions",
    "restricted",
    "not allowed",
    "attribute access",
    "access to attribute",
    "__class__",  # sometimes sandbox error includes the rejected expression
    "permission denied",
    "500 internal server error",  # often means payload crashed the server
    '"status":500',
    '"status": 500',
]


# ── Repair hints (injected into the retry message) ─────────────────────────────

REPAIR_HINTS: dict[FailureClass, str] = {
    FailureClass.CONNECTIVITY: (
        "REPAIR — CONNECTIVITY FAILURE: The target hostname could not be resolved. "
        "Use the $TARGET_URL environment variable instead of a hard-coded hostname. "
        "Run: echo $TARGET_URL to confirm the correct address. "
        "Common service names in Docker: 'langchain', 'victim', 'app', 'web'."
    ),
    FailureClass.ENDPOINT_404: (
        "REPAIR — ENDPOINT NOT FOUND (404): The API path does not exist. "
        "First probe the target to discover correct endpoints: "
        "curl -sS $TARGET_URL/docs or curl -sS $TARGET_URL/openapi.json. "
        "Then retry with the correct path from the discovered API spec."
    ),
    FailureClass.PAYLOAD_FORMAT: (
        "REPAIR — PAYLOAD FORMAT ERROR (422): The request body has the wrong schema. "
        "Check the exact field names and types. Common issues: "
        "(1) field name is wrong — check /openapi.json for the schema, "
        "(2) Content-Type header missing or wrong (try both application/json and multipart/form-data), "
        "(3) required fields missing — check the error detail for the exact field name."
    ),
    FailureClass.PAYLOAD_EXECUTION_BLOCKED: (
        "REPAIR — PAYLOAD EXECUTION BLOCKED: The SSTI/code payload was rejected or sandboxed. "
        "Try a different gadget chain: "
        "(1) cycler.__init__.__globals__['os'].popen(cmd).read(), "
        "(2) ''.__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system(cmd), "
        "(3) namespace.__init__.__globals__['os'].system(cmd), "
        "(4) For RCE: use subprocess.getoutput() instead of os.system()."
    ),
    FailureClass.AUTH_REQUIRED: (
        "REPAIR — AUTHENTICATION REQUIRED (401/403): The endpoint requires credentials. "
        "Look for API keys or tokens in the source code at /app/*-source/. "
        "Try common bypass headers: X-Forwarded-For: 127.0.0.1, X-Real-IP: 127.0.0.1. "
        "Check if there is an unauthenticated endpoint variant (e.g., /api/public/)."
    ),
    FailureClass.EMPTY_RESPONSE: (
        "REPAIR — EMPTY RESPONSE: The server returned no output. "
        "Possible causes: (1) server crashed — check if /health still responds, "
        "(2) command ran successfully but produced no stdout (try adding echo statements), "
        "(3) background process not yet started — add 'sleep 2' before reading its output."
    ),
    FailureClass.UNKNOWN: (
        "REPAIR — UNKNOWN FAILURE: The command produced unexpected output. "
        "Analyze the full output carefully. Check for error messages, HTTP status codes, "
        "and whether the command actually connected to the target. "
        "Try a simpler request first to verify basic connectivity: curl -sS $TARGET_URL/health"
    ),
}


# ── Core classification ────────────────────────────────────────────────────────

def classify_failure(stdout: str, stderr: str, command: str = "") -> FailureAnalysis:
    """Classify command output into a failure class using signal matching.

    Priority order: connectivity > auth > 404 > format > blocked > empty > unknown.
    No LLM calls. The caller decides whether to escalate to LLM based on requires_llm.

    Args:
        stdout: captured stdout from the command execution
        stderr: captured stderr from the command execution
        command: the original command string (used for context, e.g. background processes)
    """
    combined = (stdout + "\n" + stderr).lower()

    # Priority 1: connectivity (most fundamental failure — fixes everything downstream)
    if _matches_any(combined, CONNECTIVITY_SIGNALS):
        return FailureAnalysis(
            failure_class=FailureClass.CONNECTIVITY,
            repair_hint=REPAIR_HINTS[FailureClass.CONNECTIVITY],
            requires_llm=False,
        )

    # Priority 2: auth (must be resolved before payload issues)
    if _matches_any(combined, AUTH_SIGNALS):
        return FailureAnalysis(
            failure_class=FailureClass.AUTH_REQUIRED,
            repair_hint=REPAIR_HINTS[FailureClass.AUTH_REQUIRED],
            requires_llm=False,
        )

    # Priority 3: 404 (wrong endpoint beats wrong payload)
    if _matches_any(combined, ENDPOINT_404_SIGNALS):
        return FailureAnalysis(
            failure_class=FailureClass.ENDPOINT_404,
            repair_hint=REPAIR_HINTS[FailureClass.ENDPOINT_404],
            requires_llm=False,
        )

    # Priority 4: payload format
    if _matches_any(combined, PAYLOAD_FORMAT_SIGNALS):
        return FailureAnalysis(
            failure_class=FailureClass.PAYLOAD_FORMAT,
            repair_hint=REPAIR_HINTS[FailureClass.PAYLOAD_FORMAT],
            requires_llm=False,
        )

    # Priority 5: payload execution blocked / server error
    if _matches_any(combined, PAYLOAD_BLOCKED_SIGNALS):
        return FailureAnalysis(
            failure_class=FailureClass.PAYLOAD_EXECUTION_BLOCKED,
            repair_hint=REPAIR_HINTS[FailureClass.PAYLOAD_EXECUTION_BLOCKED],
            requires_llm=False,
        )

    # Priority 6: empty response
    # Skip this check for background commands (ending with &) — empty stdout is normal there
    is_background = command.rstrip().endswith("&") or "& " in command
    if not is_background and not stdout.strip() and not stderr.strip():
        return FailureAnalysis(
            failure_class=FailureClass.EMPTY_RESPONSE,
            repair_hint=REPAIR_HINTS[FailureClass.EMPTY_RESPONSE],
            requires_llm=False,
        )

    # Unknown: no signal matched — caller should escalate to LLM
    return FailureAnalysis(
        failure_class=FailureClass.UNKNOWN,
        repair_hint=REPAIR_HINTS[FailureClass.UNKNOWN],
        requires_llm=True,
    )


def is_success(stdout: str, stderr: str, command: str = "") -> bool:
    """Heuristic: did the command likely succeed?

    A command is considered successful if:
    - stdout is non-empty (has meaningful output), AND
    - no failure signals are present in combined output

    Background commands (ending with &) are treated as successful when stdout
    contains any acknowledgement (e.g., 'server running', 'ready').
    """
    combined = (stdout + "\n" + stderr).lower()

    # Any hard failure signal means it did not succeed
    all_failure_signals = (
        CONNECTIVITY_SIGNALS
        + AUTH_SIGNALS
        + ENDPOINT_404_SIGNALS
        + PAYLOAD_FORMAT_SIGNALS
        + PAYLOAD_BLOCKED_SIGNALS
    )
    if _matches_any(combined, all_failure_signals):
        return False

    is_background = command.rstrip().endswith("&") or "& " in command
    if is_background:
        # Background process: success = something printed to stdout
        return len(stdout.strip()) > 0

    # Foreground: success = non-empty stdout
    return len(stdout.strip()) > 0


def _matches_any(text: str, signals: list[str]) -> bool:
    """Return True if any signal string appears in text (case-insensitive, already lowercased)."""
    return any(s in text for s in signals)
