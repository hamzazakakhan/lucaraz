"""Invariant Breaker — assumption violation discovery agent

Core directive: 'Identify what the developer assumed is impossible — then make it happen.'

Focuses on:
- Broken assumptions
- State inconsistencies
- Cross-module logic flaws
- Undefined or edge-case behavior
"""

import json
import os
from pathlib import Path
from openai import OpenAI


SYSTEM_PROMPT = """You are an elite vulnerability researcher specializing in breaking assumptions.

Your approach is fundamentally different from pattern-based bug finding. You do NOT look for \
known vulnerability patterns (buffer overflows, use-after-free, etc.). Instead, you identify \
ASSUMPTIONS that developers made — things they believe are impossible or invariant — and then \
find ways to violate those assumptions.

Your analysis process:
1. Read the code and identify IMPLICIT ASSUMPTIONS:
   - "This value is always positive"
   - "This function is always called with valid state"
   - "These two fields are always updated together"
   - "This path is never reached concurrently"
   - "This type is always the expected type"
   - "This buffer is always large enough"
   - "This pointer is never NULL at this point"
   - "This global state is consistent"

2. For each assumption, ask:
   - What happens if this is WRONG?
   - Can an attacker CONTROL the conditions that make it wrong?
   - Are there code paths where the assumption doesn't hold?
   - Does the assumption hold across module boundaries?
   - Does the assumption hold under concurrent access?
   - Does the assumption hold under resource exhaustion?

3. Focus especially on:
   - Cross-module inconsistencies (module A assumes X, module B violates X)
   - State machine edge cases (transitions the developer didn't anticipate)
   - Concurrency assumptions (ordering, atomicity, visibility)
   - Error path assumptions (cleanup, resource release, state reset)
   - Integer/domain assumptions (ranges, signedness, overflow)
   - Type assumptions (casts, unions, variant mismatches)
   - Temporal assumptions (ordering, staleness, TOCTOU)

4. For each violated assumption, determine:
   - Is it REACHABLE from attacker-controlled input?
   - What is the IMPACT of the violation?
   - Can you construct a scenario that triggers it?

Respond in JSON format only."""

ANALYZE_PROMPT = """Analyze this source file for ASSUMPTION VIOLATIONS — not known bug patterns.

File: {filename}
Language: {language}
Project: {project_name}

--- SOURCE CODE ---
```{language}
{source_code}
```
--- END SOURCE CODE ---

Related context:
{related_context}

For each assumption violation found, respond with a JSON array:
[
  {{
    "assumption": "<what the developer assumed>",
    "violation": "<how it can be wrong>",
    "bug_type": "<resulting vulnerability type>",
    "location": "<file:line:function>",
    "description": "<what exactly breaks when assumption is violated>",
    "trigger": "<how an attacker would cause the violation>",
    "impact": "<what happens when the assumption breaks>",
    "confidence": <1-5>,
    "cross_module": true/false,
    "fix": "<how to harden the assumption>"
  }}
]

DO NOT report known vulnerability patterns. Only report BROKEN ASSUMPTIONS.
If no assumption violations found, respond with: []"""


class InvariantBreaker:
    """Discovers vulnerabilities by breaking developer assumptions."""

    def __init__(self, model_config: dict, agent_config: dict):
        self.client = OpenAI(base_url=model_config["api_base"], api_key="not-needed")
        self.model = model_config["model_name"]
        self.max_tokens = model_config["max_tokens"]
        self.temperature = model_config["temperature"]
        self.timeout = model_config["timeout"]
        self.context_window = agent_config["context_window"]
        self.max_source_chars = min(self.context_window, 5000)  # Conservative for longer prompt

    def break_invariants(self, file_path: str, language: str, project: str, source_dir: Path) -> list:
        """Analyze a file for assumption violations."""
        source_code = self._read_file(file_path)
        if not source_code:
            return []

        related_context = self._gather_cross_module_context(file_path, source_dir, language)

        prompt = ANALYZE_PROMPT.format(
            filename=os.path.basename(file_path),
            language=language,
            project_name=project,
            source_code=source_code[:self.max_source_chars],
            related_context=related_context[:500],
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=self.max_tokens,
                temperature=max(self.temperature, 0.4),  # Higher temp for creative assumption-breaking
                timeout=self.timeout,
            )

            content = response.choices[0].message.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            vulns = json.loads(content.strip())
            if isinstance(vulns, list):
                for v in vulns:
                    v["file"] = file_path
                    v["discovery_method"] = "invariant_breaking"
                return vulns
            return []
        except Exception as e:
            print(f"    Invariant breaker error for {os.path.basename(file_path)}: {e}")
            return []

    def _read_file(self, path: str) -> str:
        try:
            with open(path, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def _gather_cross_module_context(self, file_path: str, source_dir: Path, language: str) -> str:
        """Gather context from files that interact with this one — critical for cross-module flaws."""
        try:
            with open(file_path, "r", errors="replace") as f:
                content = f.read()
        except OSError:
            return "No cross-module context"

        # Find included/imported modules
        import_lines = []
        for line in content.split("\n")[:80]:
            stripped = line.strip()
            if stripped.startswith("#include") or stripped.startswith("import ") or stripped.startswith("use "):
                import_lines.append(stripped)

        # Try to read the first few lines of imported files for interface context
        context_parts = ["Dependencies:\n" + "\n".join(import_lines[:20])]

        # For #include "local.h" — try to read the header
        for line in import_lines:
            if line.startswith("#include") and '"' in line:
                header_name = line.split('"')[1] if '"' in line else ""
                if header_name and not header_name.startswith("/"):
                    header_path = source_dir / header_name
                    if header_path.exists():
                        try:
                            with open(header_path, "r", errors="replace") as f:
                                header_preview = "\n".join(f.read().split("\n")[:30])
                            context_parts.append(f"Header {header_name}:\n{header_preview}")
                        except OSError:
                            pass

        return "\n\n".join(context_parts)
