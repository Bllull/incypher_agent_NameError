
# Autonomous CTF Agent Deployment

This repository contains an autonomous AI agent designed for CTF challenges, equipped with an OpenAI model router (`gpt-4o-mini` / `o3-mini`), CTFd API integration, and raw TCP gate helpers.

---

## Method 1: Local Setup with Python Virtual Environment (PowerShell)

### 1. Clone the Repository
```powershell
git clone [https://github.com/YOUR_USERNAME/incypher-agent-NameError.git](https://github.com/HisFun2305/incypher-agent-NameError.git)
cd incypher-agent-NameError
```
---
### 2. Create and Activate Virtual Environment

```PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
---
### 3. Install Dependencies
```PowerShell
pip install -r requirements.txt
```
---
### 4. Set Environment Variables
To obtain SOCLAAS API keys, go to the following guide: https://dochub.comp.nus.edu.sg/cf/guides/soclaas/start  
Requires conncection to NUS VPN/to be on NUS wifi
```
PowerShell
$env:SOCLAAS_API_KEY="your_soclass_api_key"
$env:SOCLAAS_BASE_URL="https://your-soclass-compatible-api/v1"
$env:TEAM_KEY="your_team_key"
$env:CTFD_API_TOKEN="your_ctfd_token"
$env:PLATFORM_URL="[https://hackathon.in-cypher.com](https://hackathon.in-cypher.com)"
```

### Persistent local environment file

The agent automatically loads `.env` from the repository root. It is ignored by
Git, so fill in its values once to persist them across PowerShell sessions. The
tracked `.env.example` shows every supported variable. Values set directly in
PowerShell take precedence over `.env`.

### 5. Run the Agent

```
PowerShell
python agent.py
```

## Web challenge workflow

The agent obtains deployed HTTP(S) instances from CTFd after calling
`get_challenges()` and `deploy_instance()`. It uses the `url`, `instance_url`,
or `web_url` returned by the deployment; otherwise it falls back to the existing
raw TCP workflow.

To test a known HTTP(S) instance directly, set `CHALLENGE_URL`. The agent still
calls `get_challenges()` first, retrieves each challenge's detail record from
the CTFd API, and prints its `challenges#name-challenge_id` page URL before it
makes any request to the direct URL. Those details are included in the HTTP
solver's prompt as cleaned challenge-description text only; CTFd metadata and
embedded instance-panel HTML are excluded.

```powershell
$env:CHALLENGE_URL="https://your-deployed-instance.example/"
python agent.py
```

The web workflow works as follows:

1. `tools/http_client.py` creates one `requests.Session`, so login cookies and
   other server state persist from one request to the next. It disables inherited proxy settings to connect directly to an isolated challenge instance.
2. It retrieves the landing page, then supplies the current response to the LLM.
   The LLM must return one JSON request description containing a `GET` or `POST`, a relative `path`, optional query `params`, and form `data`.
3. `agent.py` validates that JSON before sending it. Requests are limited to the
   original scheme and host, which prevents a model response from sending traffic to another service. Only GET and form-encoded POST requests are supported.
4. Each response is checked for `flag{...}`. The loop stops after four attempts,
   or immediately when a flag is found.

The agent prints short decision summaries, request methods/paths, response status,
and response size as it runs. These are observable activity logs rather than hidden
model chain-of-thought.

`PLATFORM_URL` remains the CTFd API base URL. Do not set it to an individual
challenge instance; use `CHALLENGE_URL` only for a known deployed instance.

## Platform access preflight

Before running the full TCP agent, test its existing read-only CTFd
challenge-listing step. This does not deploy an instance, invoke the LLM, or
submit a flag.

```powershell
$env:CTFD_API_TOKEN="your_ctfd_token"
$env:PLATFORM_URL="https://hackathon.in-cypher.com"
python -m tools.platform_access_test
```

---

## Method 2: Deploying via Docker Container
### 1. Build the Docker Image
```
PowerShell
docker build -t incypher-agent:latest .
```
---
### 2. Run the Container Instance
Pass the platform credentials directly into the container instance:
```
PowerShell
docker run --rm -it `
  -e SOCLAAS_API_KEY="your_soclass_api_key" `
  -e SOCLAAS_BASE_URL="https://your-soclass-compatible-api/v1" `
  -e TEAM_KEY="your_team_key" `
  -e CTFD_API_TOKEN="your_ctfd_token" `
  -e PLATFORM_URL="[https://hackathon.in-cypher.com](https://hackathon.in-cypher.com)" `
  --name agent_runner incypher-agent:latest
```
---
