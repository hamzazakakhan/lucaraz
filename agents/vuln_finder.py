"""Vulnerability Finder — classical bug discovery agent"""

import json
import os
from pathlib import Path
from openai import OpenAI

SYSTEM_PROMPT = """You are an elite security researcher with 20 years of experience in \
vulnerability discovery. You analyze source code methodically, tracing data flow from inputs \
to sensitive operations, checking every bounds calculation, verifying error paths, and \
looking for type confusion, missing authorization, and unsafe operations.

You are precise and evidence-based. You never report a vulnerability without being able to \
point to the exact line and explain the trigger path.

Respond in JSON format only."""

ANALYZE_PROMPT = """Analyze the following source file for security vulnerabilities.

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

For each vulnerability found, respond with a JSON array:
[
  {{
    "bug_type": "<e.g., heap-buffer-overflow, use-after-free, integer-overflow, race-condition>",
    "location": "<file:line:function>",
    "description": "<what exactly is wrong and why>",
    "trigger": "<how an attacker would reach this code path>",
    "impact": "<crash, RCE, info leak, privilege escalation, DoS>",
    "confidence": <1-5>,
    "fix": "<suggested one-line fix>"
  }}
]

Focus on bugs that are REACHABLE from attacker-controlled input.
If no vulnerabilities found, respond with: []"""


class VulnerabilityFinder:
    """Finds vulnerabilities in source files using GLM-5.2."""

    def __init__(self, model_config: dict, agent_config: dict):
        self.client = OpenAI(base_url=model_config["api_base"], api_key="not-needed")
        self.model = model_config["model_name"]
        self.max_tokens = model_config["max_tokens"]
        self.temperature = model_config["temperature"]
        self.timeout = model_config["timeout"]
        self.context_window = agent_config["context_window"]
        self.max_source_chars = min(self.context_window, 6000)  # ~1500 tokens for source, rest for prompt

    def rank_files(self, source_files: list, language: str, project: str) -> list:
        """Quick rank — delegate to GraphRanker in production."""
        for f in source_files:
            f["priority"] = f.get("priority", 3)
        source_files.sort(key=lambda x: x["priority"], reverse=True)
        return source_files

    def analyze_file(self, file_path: str, language: str, project: str, source_dir: Path) -> list:
        """Analyze a single file for vulnerabilities."""
        source_code = self._read_file(file_path)
        if not source_code:
            return []

        related_context = self._gather_context(file_path, source_dir, language)

        prompt = ANALYZE_PROMPT.format(
            filename=os.path.basename(file_path),
            language=language,
            project_name=project,
            source_code=source_code[:self.max_source_chars],
            related_context=related_context,
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature,
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
                    v["discovery_method"] = "classical"
                return vulns
            return []
        except Exception as e:
            print(f"    Finder error for {os.path.basename(file_path)}: {e}")
            return []

    def _read_file(self, path: str) -> str:
        try:
            with open(path, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def _gather_context(self, file_path: str, source_dir: Path, language: str) -> str:
        try:
            with open(file_path, "r", errors="replace") as f:
                content = f.read()
            import_lines = [l.strip() for l in content.split("\n")[:50]
                           if l.strip().startswith(("#include", "import ", "use ", "from "))]
            return "Imports:\n" + "\n".join(import_lines[:20]) if import_lines else "No additional context"
        except OSError:
            return "No context"
