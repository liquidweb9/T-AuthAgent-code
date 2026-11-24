"""Offline replacement for tool.py:api_request.

Activated by SECAGENT_FAKE_LLM=True. The fixture file lives at
SECAGENT_FAKE_POLICY_FILE and has this shape:

    {
      "init":    [ {"name": "<tool>", "args": {...}}, ... ],
      "updates": {
         "<tool_name_called>": [ {"name": "<tool>", "args": {...}}, ... ],
         "*":                  [ ... fallback ... ]
      }
    }

For generate_security_policy the sys prompt is SYS_PROMPT/SYS_PROMPT_ASB:
return ``init``. For generate_update_security_policy the sys prompt is
SYS_PROMPT_2/SYS_PROMPT_2_ASB and the user prompt contains
``TOOL_CALL_PARAM: [...]``: look up the called tool name in ``updates``.

The return shape mimics what real LLMs produce -- a JSON code block string
that ``extract_json`` can parse.
"""
import json
import os
import re
import sys
from functools import lru_cache


_INIT_MARKERS = ("set permissions for each tool based on the user's query",)
_UPDATE_MARKERS = ("propose an update", "Given the tool call", "TOOL_CALL_PARAM")


@lru_cache(maxsize=4)
def _load_fixture(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _fixture() -> dict:
    path = os.getenv("SECAGENT_FAKE_POLICY_FILE")
    if not path:
        raise RuntimeError(
            "SECAGENT_FAKE_LLM=True but SECAGENT_FAKE_POLICY_FILE is unset."
        )
    return _load_fixture(path)


def _is_init_prompt(sys_prompt: str, user_prompt: str) -> bool:
    """Init system prompts don't mention TOOL_CALL_PARAM/CURRENT_RESTRICTIONS."""
    return "TOOL_CALL_PARAM" not in user_prompt


def _is_decide_prompt(sys_prompt: str) -> bool:
    """SYS_PROMPT_UPDATE opens with "determine whether"; SYS_PROMPT_2 opens
    with "update the restrictions". Match on the leading sentence so we
    don't confuse the two (both end with "Yes or No")."""
    return sys_prompt.startswith("Your task is to determine whether")


def _extract_called_tool(user_prompt: str) -> str | None:
    m = re.search(r"TOOL_CALL_PARAM:\s*(\[.*?\])\s*(?:\n|$)", user_prompt, re.DOTALL)
    if not m:
        return None
    try:
        call = json.loads(m.group(1))
        if isinstance(call, list) and call:
            return call[0].get("name")
    except json.JSONDecodeError:
        pass
    return None


def _format_json(payload) -> str:
    """Wrap as a fenced code block so extract_json (claude path) also works."""
    return "```json\n" + json.dumps(payload, indent=2) + "\n```"


def fake_api_response(sys_prompt: str, user_prompt: str) -> str:
    if _is_decide_prompt(sys_prompt):
        # Decision call: just say yes so the update flow proceeds.
        return "Yes, update."
    fx = _fixture()
    if _is_init_prompt(sys_prompt, user_prompt):
        policies = fx.get("init", [])
        print(f"[fake_llm] init -> {len(policies)} tool entries", file=sys.stderr)
        return _format_json(policies)

    tool_name = _extract_called_tool(user_prompt)
    updates = fx.get("updates", {})
    if tool_name and tool_name in updates:
        policies = updates[tool_name]
    elif "*" in updates:
        policies = updates["*"]
    else:
        policies = fx.get("init", [])
    print(
        f"[fake_llm] update after {tool_name!r} -> {len(policies)} tool entries",
        file=sys.stderr,
    )
    return _format_json(policies)
