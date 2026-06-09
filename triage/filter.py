"""False Positive Filter — heuristic + LLM-based filtering"""

import json
from openai import OpenAI

FP_PROMPT = """Is this vulnerability finding a FALSE POSITIVE?

Type: {bug_type}
Location: {location}
Description: {description}
PoC validated: {poc_validated}
Sanitizer hit: {sanitizer}

Common FP patterns: dead code, impossible preconditions, intentional behavior, test code, no PoC validation.
Respond JSON: {{"is_false_positive": true/false, "confidence": <0-100>, "reason": "<explanation>"}}"""


class FalsePositiveFilter:
    def __init__(self, model_config: dict):
        self.client = OpenAI(base_url=model_config["api_base"], api_key="not-needed")
        self.model = model_config["model_name"]
        self.timeout = model_config["timeout"]

    def is_fp(self, finding: dict) -> bool:
        validation = finding.get("validation", {})
        # Heuristic: no validated PoC → likely FP
        if not validation.get("success", False) and not validation.get("crashed"):
            return True
        # LLM check for ambiguous cases
        prompt = FP_PROMPT.format(
            bug_type=finding.get("bug_type", "unknown"),
            location=finding.get("location", "unknown"),
            description=finding.get("description", "")[:500],
            poc_validated=validation.get("success", False),
            sanitizer=bool(validation.get("sanitizer")),
        )
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=256, temperature=0.1, timeout=self.timeout,
            )
            content = response.choices[0].message.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            result = json.loads(content.strip())
            return result.get("is_false_positive", False) and result.get("confidence", 0) > 70
        except Exception:
            return False
