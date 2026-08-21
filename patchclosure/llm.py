from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from patchclosure import config


class LLMError(RuntimeError):
    pass


def available() -> bool:
    return bool(config.LLM_API_KEY)


def chat(messages: list[dict], *, temperature: float = 0.2, max_tokens: int = 2000) -> str:
    if not config.LLM_API_KEY:
        raise LLMError(
            "no LLM key: set PATCHCLOSURE_LLM_API_KEY (or DEEPSEEK_API_KEY / OPENAI_API_KEY)"
        )
    url = config.LLM_BASE_URL.rstrip("/") + "/chat/completions"
    body = json.dumps(
        {
            "model": config.LLM_MODEL,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
    ).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + config.LLM_API_KEY,
            "User-Agent": "patchclosure/0.1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise LLMError(f"HTTP {exc.code}: {detail}") from exc
    return payload["choices"][0]["message"]["content"]


def parse_json_object(raw: str) -> dict:
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        raise LLMError("no JSON object in model output: " + raw[:200])
    blob = match.group(0)
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        depth = 0
        last = 0
        for i, ch in enumerate(blob):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    last = i + 1
        if last:
            return json.loads(blob[:last])
        raise LLMError("unparseable JSON: " + blob[:200]) from None


def tagged_block(raw: str, name: str) -> str:
    match = re.search(rf"<{name}>\s*(.*?)\s*</{name}>", raw, re.S)
    if not match:
        return ""
    body = match.group(1).strip()
    return re.sub(r"^```(?:python)?|```$", "", body, flags=re.M).strip()
