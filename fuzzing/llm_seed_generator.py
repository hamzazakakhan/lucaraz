"""LLM Seed Generator — generates structured fuzzing seeds using GLM-5.2"""

import json
from openai import OpenAI

SEED_PROMPT = """Generate fuzzing seed inputs for testing the following code.

Target file: {filename}
Language: {language}

Code preview:
```{language}
{code_preview}
```

Generate {count} diverse seed inputs that:
1. Cover different input paths and code branches
2. Include edge cases: empty, maximum size, boundary values
3. Include malformed inputs: truncated, extra data, wrong types
4. Include valid-looking inputs with subtle corruption
5. Target specific parsing functions with crafted fields

For each seed, provide:
- The raw input data (as a string or hex)
- A description of what it targets
- Expected code path it exercises

Respond with JSON array:
[
  {{
    "description": "<what this seed targets>",
    "target_path": "<code path exercised>",
    "data": "<raw input data>",
    "is_binary": false,
    "edge_case": "<what edge case this covers>"
  }}
]

{targeted_context}"""


class LLMSeedGenerator:
    """Generates structured fuzzing seeds using GLM-5.2."""

    def __init__(self, model_config: dict):
        self.client = OpenAI(base_url=model_config["api_base"], api_key="not-needed")
        self.model = model_config["model_name"]
        self.timeout = model_config["timeout"]

    def generate_seeds(self, source_dir, language: str, count: int = 40) -> list:
        """Generate diverse fuzzing seeds for the target codebase."""
        # Find input-parsing files
        parser_files = self._find_parsers(source_dir, language)
        if not parser_files:
            return [os.urandom(32) for _ in range(count)]

        seeds = []
        seeds_per_file = max(1, count // len(parser_files))

        for file_path in parser_files[:5]:  # Limit to 5 files
            try:
                with open(file_path, "r", errors="replace") as f:
                    code_preview = "\n".join(f.read().split("\n")[:100])
            except OSError:
                continue

            prompt = SEED_PROMPT.format(
                filename=str(file_path),
                language=language,
                code_preview=code_preview,
                count=seeds_per_file,
                targeted_context="",
            )

            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are a fuzzing expert. Generate diverse, targeted seed inputs."},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=2048,
                    temperature=0.6,
                    timeout=self.timeout,
                )

                content = response.choices[0].message.content
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]

                seed_list = json.loads(content.strip())
                for s in seed_list:
                    data = s.get("data", "")
                    if s.get("is_binary"):
                        try:
                            seeds.append(bytes.fromhex(data.replace(" ", "")))
                        except ValueError:
                            seeds.append(data.encode())
                    else:
                        seeds.append(data.encode())

            except Exception:
                # Fallback: random seeds
                import os as _os
                seeds.extend([_os.urandom(32) for _ in range(seeds_per_file)])

        return seeds[:count]

    def generate_targeted_seeds(self, uncovered_paths: list, language: str, count: int = 20) -> list:
        """Generate seeds targeting specific uncovered code paths."""
        if not uncovered_paths:
            return []

        targeted_context = f"Target these uncovered code paths:\n" + "\n".join(
            f"- {p}" for p in uncovered_paths[:10]
        )

        prompt = SEED_PROMPT.format(
            filename="targeted",
            language=language,
            code_preview="// See uncovered paths below",
            count=count,
            targeted_context=targeted_context,
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "Generate seeds targeting specific uncovered code paths."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=2048,
                temperature=0.5,
                timeout=self.timeout,
            )

            content = response.choices[0].message.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]

            seed_list = json.loads(content.strip())
            return [s.get("data", "").encode() for s in seed_list]

        except Exception:
            import os as _os
            return [_os.urandom(32) for _ in range(count)]

    def _find_parsers(self, source_dir, language: str) -> list:
        """Find files likely to contain input parsers."""
        parser_names = ["parse", "decode", "read", "input", "process", "handle",
                        "accept", "recv", "deserialize", "unpack"]
        results = []

        for path in source_dir.rglob("*"):
            if not path.is_file():
                continue
            name_lower = path.name.lower()
            if any(p in name_lower for p in parser_names):
                results.append(str(path))

        return results[:20]
