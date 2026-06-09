"""Primitive Extractor — converts validated bugs into exploit primitives

Bug → Primitive → Constraints → Exploitability

Primitive types:
- ARB_READ: Arbitrary Read
- ARB_WRITE: Arbitrary Write
- OOB_READ: Out-of-Bounds Read
- OOB_WRITE: Out-of-Bounds Write
- UAF: Use-After-Free
- TYPE_CONFUSION: Type Confusion
- INFO_LEAK: Information Leak
- RACE: Race Condition
"""

import json
from openai import OpenAI

EXTRACT_PROMPT = """Analyze the following validated vulnerability and extract its exploit primitive.

Vulnerability:
- Type: {bug_type}
- Location: {location}
- Description: {description}
- Trigger: {trigger}
- Impact: {impact}

Sanitizer output:
{sanitizer_output}

Crash details:
{crash_details}

Classify this bug into an exploit primitive and determine its constraints.

Primitive types:
- ARB_READ: Attacker can read arbitrary memory
- ARB_WRITE: Attacker can write arbitrary memory
- OOB_READ: Out-of-bounds read (limited range)
- OOB_WRITE: Out-of-bounds write (limited range)
- UAF: Use-after-free (dangling pointer access)
- TYPE_CONFUSION: Object type mismatch
- INFO_LEAK: Information disclosure (addresses, heap layout)
- RACE: Race condition (TOCTOU, data race)
- NULL_DEREF: NULL pointer dereference (DoS or limited info)
- INTEGER_OVERFLOW: Integer overflow leading to other primitives

For each primitive, assess:
- offset_control: Can the attacker control the offset? (full, partial, none)
- size_control: Can the attacker control the size? (full, partial, none)
- content_control: Can the attacker control the content? (full, partial, none)
- repeatability: Can this be triggered reliably? (always, mostly, sometimes, rare)
- constraints: What conditions must be met?

Respond with JSON:
{{
  "primitive_type": "<one of the types above>",
  "offset_control": "<full|partial|none>",
  "size_control": "<full|partial|none>",
  "content_control": "<full|partial|none>",
  "repeatability": "<always|mostly|sometimes|rare>",
  "constraints": ["<list of conditions>"],
  "exploitability_score": <0-10>,
  "chain_potential": "<what this primitive enables in a chain>",
  "notes": "<additional observations>"
}}"""


class PrimitiveExtractor:
    """Extracts exploit primitives from validated vulnerabilities."""

    def __init__(self, model_config: dict):
        self.client = OpenAI(base_url=model_config["api_base"], api_key="not-needed")
        self.model = model_config["model_name"]
        self.max_tokens = model_config["max_tokens"]
        self.timeout = model_config["timeout"]

    def extract(self, finding: dict, language: str) -> dict:
        """Extract an exploit primitive from a validated vulnerability."""
        validation = finding.get("validation", {})

        prompt = EXTRACT_PROMPT.format(
            bug_type=finding.get("bug_type", "unknown"),
            location=finding.get("location", "unknown"),
            description=finding.get("description", ""),
            trigger=finding.get("trigger", ""),
            impact=finding.get("impact", ""),
            sanitizer_output=validation.get("sanitizer", "None"),
            crash_details=f"Crashed: {validation.get('crashed', False)}, Exit: {validation.get('exit_code', 'N/A')}",
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an exploit developer specializing in primitive extraction and chain construction."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=self.max_tokens,
                temperature=0.2,
                timeout=self.timeout,
            )

            content = response.choices[0].message.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            primitive = json.loads(content.strip())
            primitive["source_finding"] = finding.get("bug_type", "unknown")
            primitive["source_location"] = finding.get("location", "unknown")
            return primitive

        except Exception as e:
            return {
                "primitive_type": "UNKNOWN",
                "offset_control": "none",
                "size_control": "none",
                "content_control": "none",
                "repeatability": "rare",
                "constraints": [],
                "exploitability_score": 0,
                "chain_potential": "none",
                "notes": f"Extraction failed: {e}",
            }
