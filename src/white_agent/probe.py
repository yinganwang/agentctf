"""Deterministic target probe — no LLM calls.

Emitted as the white agent's first command for any unknown CVE task.
Reads $TARGET_URL (always set in attacker container via compose.yml) and
also extracts any extra hostname from the task prompt text, so we cover
the common mismatch between $TARGET_URL and what the task description says.
"""

import re

PROBE_PATHS: list[str] = ["/health", "/", "/docs", "/openapi.json"]

_HOSTNAME_RE = re.compile(r"https?://[a-zA-Z0-9._-]+(?::\d+)?")


def build_probe_command(task_prompt: str = "") -> str:
    """Return a bash command string that probes the target.

    Uses $TARGET_URL env var as the primary target.
    Also probes any http://hostname:port found in task_prompt text.
    Captures HTTP status codes and first 400 bytes of each body.
    """
    # Extract extra candidate URLs from the task prompt (deduplicated)
    extra_urls: list[str] = []
    if task_prompt:
        for match in _HOSTNAME_RE.finditer(task_prompt):
            url = match.group(0).rstrip("/")
            # Skip obviously non-target URLs (localhost references in hints, etc.)
            if "localhost" not in url and "127.0.0.1" not in url:
                extra_urls.append(url)
    # Deduplicate preserving order
    seen: set[str] = set()
    unique_extras: list[str] = []
    for u in extra_urls:
        if u not in seen:
            seen.add(u)
            unique_extras.append(u)
    # Limit to first 3 extra candidates to avoid spending too many steps
    unique_extras = unique_extras[:3]

    extra_repr = repr(unique_extras)
    paths_repr = repr(PROBE_PATHS)

    return (
        "python3 << 'EOFPY'\n"
        "import subprocess, os, json\n"
        "\n"
        f"extra_urls = {extra_repr}\n"
        f"paths = {paths_repr}\n"
        "\n"
        "target_env = os.environ.get('TARGET_URL', '').rstrip('/')\n"
        "candidates = [target_env] + [u for u in extra_urls if u != target_env]\n"
        "candidates = [c for c in candidates if c]  # drop empty\n"
        "\n"
        "results = {}\n"
        "for base in candidates:\n"
        "    results[base] = {}\n"
        "    for path in paths:\n"
        "        url = base + path\n"
        "        r = subprocess.run(\n"
        "            ['curl', '-sS', '--max-time', '5',\n"
        "             '-o', '/tmp/_probe_body.txt',\n"
        "             '-w', '%{http_code}',\n"
        "             url],\n"
        "            capture_output=True, text=True\n"
        "        )\n"
        "        status = r.stdout.strip()\n"
        "        try:\n"
        "            body = open('/tmp/_probe_body.txt').read(400)\n"
        "        except Exception:\n"
        "            body = ''\n"
        "        results[base][path] = {'status': status, 'body': body}\n"
        "\n"
        "print('=== PROBE RESULTS ===')\n"
        "print(json.dumps(results, indent=2))\n"
        "EOFPY"
    )


def parse_probe_output(probe_stdout: str) -> dict:
    """Parse raw probe stdout into a structured summary.

    Returns:
        reachable: bool         — at least one path returned 2xx/3xx
        live_paths: list[str]   — full URLs that returned 2xx/3xx
        best_base: str          — base URL with most live paths
        has_openapi: bool       — /openapi.json returned 200
        openapi_json: str       — raw openapi JSON if available (up to 2000 chars)
        has_docs: bool          — /docs returned 200
        raw: str                — trimmed raw output for LLM context
    """
    import json as _json

    raw = probe_stdout.strip()
    live_paths: list[str] = []
    has_openapi = False
    openapi_json = ""
    has_docs = False
    best_base = ""

    # Try to parse the structured JSON block
    try:
        start = probe_stdout.index("=== PROBE RESULTS ===")
        json_text = probe_stdout[start + len("=== PROBE RESULTS ==="):].strip()
        data = _json.loads(json_text)

        base_counts: dict[str, int] = {}
        for base, paths in data.items():
            count = 0
            for path, info in paths.items():
                status = info.get("status", "")
                body = info.get("body", "")
                if status and status[0] in ("2", "3"):
                    full_url = base + path
                    live_paths.append(full_url)
                    count += 1
                    if path == "/openapi.json" and status == "200":
                        has_openapi = True
                        openapi_json = body[:2000]
                    if path == "/docs" and status == "200":
                        has_docs = True
            base_counts[base] = count

        if base_counts:
            best_base = max(base_counts, key=lambda b: base_counts[b])

    except (ValueError, KeyError):
        # Fallback: just scan for HTTP-like patterns
        pass

    reachable = len(live_paths) > 0

    return {
        "reachable": reachable,
        "live_paths": live_paths,
        "best_base": best_base,
        "has_openapi": has_openapi,
        "openapi_json": openapi_json,
        "has_docs": has_docs,
        "raw": raw[:3000],
    }
