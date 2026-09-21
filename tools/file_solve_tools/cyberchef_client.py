"""Bounded local CyberChef Node.js API access for file artifacts."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from tools.file_solve_tools.external_process import resolve_tool, run_external_tool
from tools.flags import extract_flag_from_json


MAX_INPUT_BYTES = 48 * 1024
MAX_RECIPE_BYTES = 16 * 1024
_NODE_BAKE_SCRIPT = r"""
const fs = require("fs");
const chef = require("cyberchef");

async function main() {
  const request = JSON.parse(fs.readFileSync(0, "utf8"));
  const input = Buffer.from(request.input_b64, "base64");
  const dish = await chef.bake(input, request.recipe);
  const value = dish.value;
  let result;
  if (Buffer.isBuffer(value)) {
    result = { encoding: "base64", value: value.toString("base64") };
  } else if (value instanceof ArrayBuffer) {
    result = { encoding: "base64", value: Buffer.from(value).toString("base64") };
  } else if (ArrayBuffer.isView(value)) {
    result = { encoding: "base64", value: Buffer.from(value.buffer).toString("base64") };
  } else {
    result = { encoding: "json", value: value };
  }
  process.stdout.write(JSON.stringify({ type: dish.type, result: result }));
}

main().catch((error) => {
  process.stderr.write(String(error && error.stack || error));
  process.exitCode = 1;
});
"""


class CyberChefError(RuntimeError):
    """A local CyberChef Node.js operation could not complete safely."""


def _artifact_bytes(path: Path) -> bytes:
    if not path.is_file():
        raise FileNotFoundError(f"Artifact does not exist or is not a file: {path}")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise CyberChefError(f"Artifact exceeds the {MAX_INPUT_BYTES}-byte CyberChef input limit")
    return path.read_bytes()


def run_cyberchef_analysis(
    artifact_path: str | Path,
    *,
    recipe: str | dict[str, Any] | list[Any],
    node_path: str | Path | None = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Bake bounded artifact bytes through a locally installed CyberChef package.

    The CyberChef Node.js API accepts buffers and compatible saved-recipe JSON.
    This wrapper does not make network requests and requires Node.js plus the
    local ``cyberchef`` npm package to be resolvable from the artifact directory.
    """
    target = Path(artifact_path).resolve()
    data = _artifact_bytes(target)
    try:
        recipe_size = len(json.dumps(recipe).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise TypeError("recipe must be JSON-serializable") from exc
    if recipe_size > MAX_RECIPE_BYTES:
        raise ValueError(f"recipe exceeds the {MAX_RECIPE_BYTES}-byte limit")
    executable = resolve_tool(
        configured_path=node_path,
        environment_variable="CYBERCHEF_NODE_PATH",
        candidates=("node", "node.exe"),
    )
    request = json.dumps(
        {"input_b64": base64.b64encode(data).decode("ascii"), "recipe": recipe}
    ).encode("utf-8")
    process = run_external_tool(
        [executable, "--input-type=commonjs", "--eval", _NODE_BAKE_SCRIPT],
        timeout=timeout,
        cwd=target.parent,
        input_data=request,
    )
    if process.returncode != 0:
        raise CyberChefError(process.stderr or "CyberChef Node.js recipe failed")
    try:
        payload = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise CyberChefError("CyberChef Node.js API returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise CyberChefError("CyberChef Node.js API returned an invalid result")
    return {
        "recipe": recipe,
        "response": payload,
        "output_truncated": process.output_truncated,
        "flag": extract_flag_from_json(payload),
    }
