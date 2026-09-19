# Method reference

This guide describes the repository's public workflow methods. Challenge IDs
are integers: non-negative values identify CTFd challenges, while negative
values are reserved for shared workflow context.

## Agent orchestration

### `agent.py`

- `main()` fetches the CTFd challenge list, stores each challenge's name and
  description as JSON context, downloads file assets when needed, and delegates
  to the matching solver. Challenges returning no flag are retried.
- `_delegate(challenge_type, chal_ID)` selects the web, port, or file solver
  and returns its flag string or `None`.

## Persistent context

### `tools/context.py`

All context records are JSON dictionaries stored in the local SQLite database.

- `store_context(context, chal_ID)` replaces an entire record.
- `get_context(chal_ID)` returns the record dictionary, or `None` when absent.
- `update_context(context, chal_ID)` shallow-merges fields into an existing
  record; matching keys are replaced.
- `delete_context(chal_ID)` removes one record if it exists.
- `store_name(name, chal_ID)` and `get_name(chal_ID)` manage the `name` field.
- `store_chal_file_path(filepath, chal_ID)` and
  `get_chal_file_path(chal_ID)` manage the primary `file_path` field.

## CTFd platform access

### `tools/ctfd_api.py`

- `get_challenges()` returns the visible CTFd challenge summaries.
- `get_challenge_details(challenge_id)` returns one CTFd detail object.
- `extract_challenge_description(challenge_id)` returns `(name, description)`.
- `identify_challenge_type(challenge_id)` returns `file`, `url`, or `tcp`.
  Downloadable files take priority; otherwise `http` in the description denotes
  a URL challenge.
- `download_challenge_files(challenge_name, challenge_id)` downloads CTFd file
  links and returns their local absolute paths.
- `get_challenge_url(challenge_id)` returns the deployed URL or asks for a
  manually deployed URL when the Docker platform is unavailable.
- `connect_challenge_tcp(challenge_id, timeout=15)` opens a TCP socket to a
  deployed instance or a manually supplied `nc HOST PORT` endpoint.
- `deploy_instance(challenge_id)` requests a CTFd container deployment.
- `submit_flag(challenge_id, flag)` submits a candidate flag to CTFd.

## LLM access

### `tools/llm_router.py`

- `call_openai(prompt, require_deep_reasoning=False)` sends a text chat request
  using the `default` alias, or `coding` when deeper reasoning is requested.
- `call_multimodal_openai(prompt, image_paths, model_name='qwen3-vl:32b')`
  sends prompt text and local JPEG, PNG, GIF, or WebP images as data URLs to a
  vision-capable chat model.

## Web challenge workflow

### `tools/web_chal.py`

- `web_chal_solver(chal_ID)` reads stored context, identifies a web subtype,
  and runs the implemented subtype workflow.
- `identify_web_subtype(chal_ID)` asks the LLM to choose the currently
  supported `SSTI` subtype or `UNKNOWN`.
- `_solve_ssti(chal_ID)` discovers a form, submits the current SSTI probes,
  stores bounded responses in shared web context, and extracts a flag when one
  appears.

### `tools/web_solve_tools/webpage_access_helpers.py`

- `get_form_json(challenge_url, context, session, chal_ID)` returns a cached
  validated form schema when available; otherwise discovers, validates, and
  stores the first usable form.
- `submit_form(form_schema, values, session)` performs one or multiple GET or
  POST form submissions.
- `validate_form_json(form_schema, session, test_variables)` submits safe test
  values and accepts HTTP responses in the 2xx or 3xx range.
- `append_validated_form_context(chal_ID, form_schema)` stores the schema in
  shared web context. Its name is retained, but it writes JSON rather than text.
- `extract_flag(text)` returns the first `INCYPHER{...}` value in a response.

## HTTP and TCP helpers

### `tools/http_client.py`

- `create_session()` returns a cookie-preserving `requests` session with proxy
  environment variables disabled.
- `same_origin_url(base_url, path)` resolves a path and rejects cross-origin
  destinations.
- `interact_http(session, base_url, method, path, params, data, timeout)` sends
  a bounded same-origin GET or form-encoded POST request.

### `tools/tcp_client.py` and `solver.py`

- `interact_tcp(ip, port, team_key, payload=None)` opens a platform TCP
  connection, optionally sends one line, then returns the first response.
- `connect(ip, port, team_key)` is the current socket connection helper used by
  `interact_tcp`.

## Solver placeholders

### `tools/port_chal.py` and `tools/file_chal.py`

- `port_chal_solver(chal_ID)` and `file_chal_solver(chal_ID)` currently print
  stored context and return placeholder flags. Their full solving logic has not
  yet been implemented.

## Preflight

### `tools/preflight.py`

- `check_soclaas_connection()` verifies gateway credentials with a read-only
  model-list request.
- `check_challenge_url_connection(challenges)` and
  `check_challenge_tcp_connection(challenges)` attempt one suitable challenge
  connection while continuing past individual failures.
- `check_challenge_description_retrieval(challenges)` verifies CTFd description
  access.
- `check_challenge_file_download(challenges)` verifies one downloadable file
  asset when available.
- `check_context_sqlite_connection()` verifies the local context database opens.
- `main()` runs the checks in order and returns a process exit code.
