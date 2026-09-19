# Installation

## Local setup (PowerShell)

```powershell
git clone https://github.com/HisFun2305/incypher_agent_NameError.git
cd incypher_agent_NameError
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Configure `.env` with your credentials. For SOCLAAS, follow [https://dochub.comp.nus.edu.sg/cf/guides/soclaas/start](https://dochub.comp.nus.edu.sg/cf/guides/soclaas/start) (You need to be on NUS wifi or be logged into the NUS VPN):

```dotenv
IN_CYPHER_DOCKER_PLATFORM_AVAILABLE=false
SOCLAAS_API_KEY=your_soclass_api_key
SOCLAAS_BASE_URL=https://your-soclass-compatible-api/v1
CTFD_API_TOKEN=your_ctfd_token
PLATFORM_URL=https://hackathon.in-cypher.com
TEAM_KEY=your_team_key
```

## Docker setup

```powershell
docker build -t incypher-agent:latest .
docker run --rm -it `
  -e IN_CYPHER_DOCKER_PLATFORM_AVAILABLE="false" `
  -e SOCLAAS_API_KEY="your_soclass_api_key" `
  -e SOCLAAS_BASE_URL="https://your-soclass-compatible-api/v1" `
  -e CTFD_API_TOKEN="your_ctfd_token" `
  -e PLATFORM_URL="https://hackathon.in-cypher.com" `
  -e TEAM_KEY="your_team_key" `
  --name agent_runner `
  incypher-agent:latest
```

## Module diagram

For a concise reference of the public methods, see [METHODS.md](METHODS.md).

```mermaid
classDiagram
    class agent_py {
        +_delegate(challenge_type, chal_ID) str | None
        +main()
    }
    class ctfd_api_py {
        +get_challenges()
        +get_challenge_details()
        +identify_challenge_type()
        +extract_challenge_description()
        +download_challenge_files()
        +get_challenge_url()
        +connect_challenge_tcp()
        +submit_flag()
    }
    class preflight_py {
        +main()
        +check_soclaas_connection()
        +check_challenge_url_connection()
        +check_challenge_tcp_connection()
        +check_challenge_description_retrieval()
        +check_challenge_file_download()
        +check_context_sqlite_connection()
    }
    class context_py {
        <<JSON dictionaries; non-negative IDs: challenges; negative IDs: shared context>>
        +store_context(context, chal_ID)
        +get_context(chal_ID) dict | None
        +update_context(context, chal_ID)
        +delete_context(chal_ID)
        +store_name()
        +get_name()
        +store_chal_file_path()
        +get_chal_file_path()
    }
    class config_py {
        +load_dotenv()
    }
    class llm_router_py {
        +call_openai()
        +call_multimodal_openai(prompt, image_paths, model_name)
    }
    class web_chal_py {
        +web_chal_solver(chal_ID) str | None
    }
    class port_chal_py {
        +port_chal_solver(chal_ID) str | None
    }
    class file_chal_py {
        +file_chal_solver(chal_ID) str | None
    }
    class tcp_client_py {
        +interact_tcp()
    }
    class http_client_py {
        +create_session()
        +interact_http()
    }
    class webpage_access_helpers_py {
        +get_form_json()
        +submit_form()
        +validate_form_json()
        +append_validated_form_context()
        +extract_flag()
    }
    class solver_py {
        +connect()
    }

    agent_py --> ctfd_api_py : retrieves challenge data
    agent_py --> context_py : stores JSON challenge context
    agent_py --> web_chal_py : delegates URL challenge
    agent_py --> port_chal_py : delegates TCP challenge
    agent_py --> file_chal_py : delegates file challenge
    web_chal_py --> agent_py : str flag (solved) or None (retry)
    port_chal_py --> agent_py : str flag (solved) or None (retry)
    file_chal_py --> agent_py : str flag (solved) or None (retry)
    preflight_py --> ctfd_api_py : verifies API data
    preflight_py --> context_py : verifies SQLite storage
    ctfd_api_py --> config_py : loads credentials
    llm_router_py --> config_py : loads credentials
    tcp_client_py --> solver_py : opens TCP connection
    web_chal_py --> context_py : reads and updates JSON context
    web_chal_py --> llm_router_py : classifies web subtype
    web_chal_py --> http_client_py : creates challenge session
    web_chal_py --> webpage_access_helpers_py : discovers and submits forms
    webpage_access_helpers_py --> context_py : stores validated schema
    port_chal_py --> context_py : reads challenge context
    port_chal_py --> tcp_client_py : planned TCP use
    file_chal_py --> context_py : reads challenge context
```
