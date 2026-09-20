param(
    [string]$ImagePath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $repoRoot "venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $python)) {
    throw "Virtual-environment Python was not found at $python"
}

$env:SOCLAAS_TEST_IMAGE = $ImagePath
$testCode = @'
import os
from pathlib import Path

from tools.llm_router import call_multimodal_openai, call_openai, list_openai_models

models = list_openai_models(max_attempts=1)
print(f"Models ({len(models)}): {models}")
print("Text response:")
print(call_openai("Reply with exactly: SOCLAAS connection successful", max_attempts=1))

image_path = os.environ.get("SOCLAAS_TEST_IMAGE", "").strip()
if image_path:
    print("Multimodal response:")
    print(
        call_multimodal_openai(
            "Briefly describe this image.",
            [Path(image_path)],
            max_attempts=1,
        )
    )
'@

Push-Location $repoRoot
try {
    & $python -c $testCode
    if ($LASTEXITCODE -ne 0) {
        throw "SOCLAas test exited with code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
    Remove-Item Env:SOCLAAS_TEST_IMAGE -ErrorAction SilentlyContinue
}
