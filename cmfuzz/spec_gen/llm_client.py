"""Pluggable LLM backend for spec / oracle generation (Pillar 1).

Design goal: the *semantic extraction* step of CLFuzz (input constraints +
function signatures) and the *oracle synthesis* step are automated by an LLM
instead of hand-written per algorithm. This module isolates the LLM call so the
rest of the framework does not depend on any particular provider.

If no API key is configured, ``LLMClient.available`` is False and callers fall
back to the offline heuristic templates in ``generate_specs.py`` — so the whole
pipeline runs end-to-end without network access, and "plugs in" an LLM when a
key (OPENAI_API_KEY / DEEPSEEK_API_KEY) is present.
"""
from __future__ import annotations
import json
import os
import textwrap
from typing import Optional


PROMPT_TEMPLATE = textwrap.dedent(
    """\
    You are a cryptography-implementation testing expert. Given the C API header
    and standard name of a cryptographic algorithm, output a STRICT JSON object
    describing (1) input constraints for each parameter, (2) the function
    signature, and (3) a list of metamorphic / security oracles that a correct
    implementation must satisfy. Base security oracles on the stated security
    notion (e.g. IND-CCA2 => ciphertext non-malleability; EUF-CMA/SUF-CMA =>
    message-binding / signature non-malleability).

    Algorithm: {name}
    Kind: {kind}
    Security notion: {notion}
    Header excerpt:
    ---
    {header}
    ---
    Respond with ONLY the JSON object, no prose.
    """
)


class LLMClient:
    def __init__(self) -> None:
        self.provider: Optional[str] = None
        self.api_key: Optional[str] = None
        self.model: Optional[str] = None
        if os.environ.get("OPENAI_API_KEY"):
            self.provider = "openai"
            self.api_key = os.environ["OPENAI_API_KEY"]
            self.model = os.environ.get("CMF_LLM_MODEL", "gpt-4o-mini")
        elif os.environ.get("DEEPSEEK_API_KEY"):
            self.provider = "deepseek"
            self.api_key = os.environ["DEEPSEEK_API_KEY"]
            self.model = os.environ.get("CMF_LLM_MODEL", "deepseek-chat")

    @property
    def available(self) -> bool:
        return self.api_key is not None

    def extract_spec(self, name: str, kind: str, notion: str, header: str) -> Optional[dict]:
        """Return an LLM-generated spec dict, or None if unavailable/failed."""
        if not self.available:
            return None
        prompt = PROMPT_TEMPLATE.format(name=name, kind=kind, notion=notion,
                                        header=header[:6000])
        try:
            import urllib.request

            if self.provider == "openai":
                url = "https://api.openai.com/v1/chat/completions"
            else:
                url = "https://api.deepseek.com/chat/completions"
            body = json.dumps({
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "response_format": {"type": "json_object"},
            }).encode()
            req = urllib.request.Request(url, data=body, headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            })
            with urllib.request.urlopen(req, timeout=60) as resp:
                out = json.loads(resp.read())
            content = out["choices"][0]["message"]["content"]
            return json.loads(content)
        except Exception as exc:  # pragma: no cover - network dependent
            print(f"[llm] extraction failed ({exc}); falling back to offline template")
            return None
