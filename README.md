
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
```
PowerShell
$env:OPENAI_API_KEY="your_openai_api_key"
$env:TEAM_KEY="your_team_key"
$env:CTFD_API_TOKEN="your_ctfd_token"
$env:PLATFORM_URL="[https://hackathon.in-cypher.com](https://hackathon.in-cypher.com)"
```
---
### 5. Run the Agent

```
PowerShell
python agent.py
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
  -e OPENAI_API_KEY="your_openai_api_key" `
  -e TEAM_KEY="your_team_key" `
  -e CTFD_API_TOKEN="your_ctfd_token" `
  -e PLATFORM_URL="[https://hackathon.in-cypher.com](https://hackathon.in-cypher.com)" `
  --name agent_runner incypher-agent:latest
```
---