# Implementation Plan: State-Machine Exploit Synthesis

Branch: `yinganwang/state-machine-exploit`

## Goal

Replace the current "Layer 2+3 LLM path" (free-form bash generation) in the White Agent
with a deterministic 4-phase state machine that dramatically reduces LLM calls and improves
reliability on unknown CVEs.

**Only `src/white_agent/` and `pyproject.toml` are modified.** Green Agent code and task
configurations are not touched.

---

## Architecture

```
execute(ctx_id, message)
        │
        ├─ ctx in ctx_id_to_playbook?  ──YES──> _playbook_next_step()   [unchanged]
        ├─ match_playbook(message)?    ──YES──> init playbook + step()   [unchanged]
        ├─ ctx in ctx_id_to_state?     ──YES──> _state_machine_next()    [NEW]
        └─ else                               ──> _init_state_machine()  [NEW]


  [PROBE]  ──probe output──>  [FILLING]  ──fill fails twice──>  [legacy _llm_response]
                                   │
                              fill succeeds
                                   │
                              [EXPLOITING]  ──step < len(steps)──> emit next command
                                   │                    ▲
                              FailureCritic             │
                                   ├─ known class ──> inject repair_hint, retry same step
                                   └─ unknown     ──> cheap LLM (max 3x), retry
                                   │
                              step >= len(steps)
                                   │
                               [DONE]
```

**LLM calls per unknown task:**
- Best case (known failure signals only): 1 call to `gpt-4o-mini` (~$0.02)
- Typical (1 unrecognized failure): 2 calls (~$0.04)
- Worst case (fill retry + 3 critic calls): 5 calls (~$0.10)
- Fallback to full model (no template): ~$0.20

---

## File Changes

### New Files

| File | Status | Purpose |
|------|--------|---------|
| `src/white_agent/probe.py` | [ ] TODO | Deterministic target recon, no LLM |
| `src/white_agent/failure_critic.py` | [ ] TODO | Signal-matching failure classifier |
| `src/white_agent/exploit_templates.py` | [ ] TODO | Parameterized bash templates per vuln class |
| `TODOS.md` | [x] DONE | This file |

### Modified Files

| File | Status | Changes |
|------|--------|---------|
| `src/white_agent/agent.py` | [ ] TODO | Add state machine, wire new components |
| `src/white_agent/playbooks.py` | [x] DONE | Fix SSTI hostname + payload (prior work) |

---

## TODO Items

### Phase 1 — Infrastructure (no behavior change)

- [ ] **1.1** Create `src/white_agent/probe.py`
  - `PROBE_PATHS: list[str]` — `["/health", "/", "/docs", "/openapi.json"]`
  - `build_probe_command() -> str` — python3 heredoc that curls each path capturing HTTP
    status + first 400 bytes of body. Also extracts and probes any `http://hostname:port`
    found in task prompt text (handles `$TARGET_URL` ≠ task hostname mismatch).
  - `parse_probe_output(stdout: str) -> dict` — returns:
    `{reachable, live_paths, has_openapi, openapi_json, raw}`

- [ ] **1.2** Create `src/white_agent/failure_critic.py`
  - `FailureClass(Enum)` — six classes: `CONNECTIVITY`, `ENDPOINT_404`, `PAYLOAD_FORMAT`,
    `PAYLOAD_EXECUTION_BLOCKED`, `AUTH_REQUIRED`, `EMPTY_RESPONSE`, `UNKNOWN`
  - `FailureAnalysis(dataclass)` — `{failure_class, repair_hint, requires_llm}`
  - Signal lists (module-level constants):
    - `CONNECTIVITY_SIGNALS` — "Could not resolve host", "Connection refused", "curl: (6)", "curl: (7)"
    - `ENDPOINT_404_SIGNALS` — "404", "Not Found", "No route"
    - `PAYLOAD_FORMAT_SIGNALS` — "422", "Unprocessable", "field required", "validation error"
    - `PAYLOAD_BLOCKED_SIGNALS` — "UndefinedError", "SecurityError", "NameError", "Sandbox", "blocked"
    - `AUTH_SIGNALS` — "401", "403", "Unauthorized", "Forbidden"
  - `REPAIR_HINTS: dict[FailureClass, str]` — one pre-written repair hint per class
  - `classify_failure(stdout, stderr) -> FailureAnalysis` — signal matching only, no LLM.
    Priority: connectivity > auth > 404 > format > blocked > empty > unknown.
  - `is_success(stdout, stderr) -> bool` — heuristic (non-empty output, no error signals).
    Background commands (`&` in command string) treat empty stdout as success.

- [ ] **1.3** Create `src/white_agent/exploit_templates.py`
  - `ExploitTemplate(dataclass)` — `{vuln_class, param_slots, fill_instructions, steps, step_reasonings}`
  - `EXPLOIT_TEMPLATES: dict[str, ExploitTemplate]` — 8 vuln class templates (see below)
  - `get_template(vuln_class) -> ExploitTemplate | None`
  - `fill_template(template, params) -> list[tuple[str, str]]` — substitute params into steps
  - `build_fill_prompt(template, task_prompt, probe_output) -> str` — builds the single LLM
    message used to extract params; includes OpenAPI JSON if available

  **Template: `server_side_template_injection`**
  - param_slots: `target`, `upload_endpoint`, `format_endpoint`, `variable_name`, `result_file`
  - Step 1: Upload payload — tries gadgets in order within single script:
    1. `cycler.__init__.__globals__['os'].popen(cmd).read()`
    2. `''.__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system(cmd)`
    3. `namespace.__init__.__globals__['os'].system(cmd)`
  - Step 2: Append marker + copy to proof file

  **Template: `arbitrary_code_execution`**
  - param_slots: `target`, `rce_endpoint`, `payload_field`, `result_file`
  - Step 1: Send code block to create `/tmp/pwned.txt` — tries python block + direct expression
  - Step 2: Read proof back via second RCE call
  - Step 3: Append marker + save

  **Template: `ssrf`**
  - param_slots: `target`, `proxy_endpoint`, `content_type`, `result_file`
  - Step 1: Probe with first internal URL
  - Step 2: Try fallback internal URLs (localhost:8000, 127.0.0.1:8000, 169.254.169.254, localhost:8889/internal-api)

  **Template: `sql_injection`**
  - param_slots: `target`, `sql_endpoint`, `db_name`, `flag_table`, `result_file`, `proof_file`
  - Step 1: `SELECT * FROM {flag_table} WHERE key='secret_flag'`
  - Step 2: Full table dump fallback
  - Step 3: Extract `flag{...}` pattern + save proof

  **Template: `path_traversal`**
  - param_slots: `target`, `delete_endpoint`, `target_file`, `result_file`
  - Step 1: Try `{"data": [...]}`, `{"filename": ...}`, `{"file": ...}` within single script
  - Step 2: Verify + save

  **Template: `information_disclosure`**
  - param_slots: `target`, `chat_endpoint`, `attacker_hostname`, `attacker_port`, `result_file`
  - Step 1: Start capture server (background)
  - Step 2: Craft auth token + send request
  - Step 3: Read captured result

  **Template: `authentication_bypass`**
  - param_slots: `target`, `bypass_endpoint`, `result_file`, `proof_file`
  - Step 1: Access endpoint without auth + secondary endpoint
  - Step 2: Save proof

  **Template: `prompt_injection_to_code_execution`**
  - param_slots: `target`, `pal_endpoint`, `result_file`, `proof_file`
  - Step 1: Send injection with `use_fake_llm=True` + `os.system` call
  - Step 2: Save proof

  **Template: `cypher_injection`**
  - param_slots: `target`, `direct_endpoint`, `agent_endpoint`, `result_file`, `proof_file`
  - Steps: extract documents, dump all nodes, prompt injection, CREATE proof node

### Phase 2 — Wire state machine in `agent.py`

- [ ] **2.1** Add `ExploitState` TypedDict:
  ```python
  ExploitState = TypedDict("ExploitState", {
      "phase": Literal["probe", "filling", "exploiting"],
      "probe_output": str,
      "template_steps": list[tuple[str, str]],
      "step": int,
      "failure_count": int,   # capped at 3
      "vuln_type": str | None,
      "task_prompt": str,
  })
  ```

- [ ] **2.2** Add to `__init__`:
  ```python
  self.ctx_id_to_state: dict[str, ExploitState] = {}
  self.cheap_model = os.getenv("LITELLM_CHEAP_MODEL", "openai/gpt-4o-mini")
  ```

- [ ] **2.3** Implement `_init_state_machine(ctx_id, task_prompt) -> str`
  - Creates state with `phase="probe"`
  - Calls `build_probe_command()` passing task_prompt for hostname extraction
  - Returns probe action JSON

- [ ] **2.4** Implement `_state_machine_next(ctx_id, command_output) -> str`
  - Dispatches to `_handle_probe_result` / `_handle_exploit_step` based on phase

- [ ] **2.5** Implement `_handle_probe_result(ctx_id, probe_stdout) -> str`
  - Calls `parse_probe_output()`
  - Detects vuln type via `_detect_vuln_type()` (existing method, keep it)
  - Calls `_fill_template_via_llm()`

- [ ] **2.6** Implement `_fill_template_via_llm(ctx_id) -> str`
  - `get_template(vuln_type)` — if None, fall back to `_llm_response`
  - Single structured LLM call (cheap model) using `build_fill_prompt()`
  - Parse JSON params; retry once with stricter prompt on failure
  - On second failure, fall back to `_llm_response`
  - On success: call `fill_template()`, store steps in state, set `phase="exploiting"`, emit step 0

- [ ] **2.7** Implement `_handle_exploit_step(ctx_id, command_output) -> str`
  - Extract stdout/stderr from green agent's formatted output
  - If `is_success()`: advance `step`, emit next step or `"done"`
  - If not success: call `_apply_failure_critic()`

- [ ] **2.8** Implement `_apply_failure_critic(ctx_id, command, stdout, stderr) -> str`
  - `classify_failure(stdout, stderr)`
  - If known class and `failure_count < 3`: inject `repair_hint` into retry message, increment `failure_count`, re-emit same step with hint prepended
  - If `UNKNOWN` and `failure_count < 3`: cheap LLM call with full context + hint, increment `failure_count`
  - If `failure_count >= 3`: force-advance `step` (avoid blowout), emit next step

- [ ] **2.9** Update routing gate in `execute()`
  - Insert `ctx_id_to_state` check between playbook check and LLM path
  - Parse stdout/stderr from green agent's "Command execution result" wrapper

### Phase 3 — Validation

- [ ] **3.1** Smoke test: bypass `match_playbook` for `cve-2023-36281` temporarily → verify
  probe fires → LLM fills params (target=`http://langchain:8080`, upload_endpoint=`/upload_prompt`,
  format_endpoint=`/format_prompt`, variable_name=`name`) → 2 steps execute → proof file created

- [ ] **3.2** Fallback test: remove `ssti` from `EXPLOIT_TEMPLATES` → confirm graceful
  degradation to `_llm_response` without crash

- [ ] **3.3** Failure cap test: mock 5 consecutive UNKNOWN failures → confirm exactly 3 LLM calls
  and exploit advances past stuck step

---

## Key Design Decisions

**Why `python3 << 'EOFPY'` heredoc for all template steps?**
Proven shell-safe in existing playbooks. Avoids nested quoting issues in curl payloads.

**Why `$TARGET_URL` as the base for probing?**
Always set by Docker compose (e.g., `TARGET_URL=http://langchain:8080`). The probe also
extracts any `http://hostname:port` from the task prompt text via regex as a secondary target,
covering cases where task description and compose env differ.

**Why `gpt-4o-mini` for fill + critic?**
Single structured JSON output call; task is well-constrained (fill 5-6 named params from
probe output + task description). Full `gpt-4o` reserved for when no template exists.

**Why cap `failure_count` at 3?**
Budget protection. 3 × $0.01 = $0.03 worst-case critic overhead per task. After 3 failures
on the same step, advance to next step — a stuck step should not block subsequent ones.
