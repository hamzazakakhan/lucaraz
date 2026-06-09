"""Strategy Manager — selects and adapts PoC strategies using learning feedback"""

import json
from openai import OpenAI

FAILURE_ANALYSIS_PROMPT = """Analyze why this PoC attempt failed and derive a lesson.

Vulnerability:
- Type: {bug_type}
- Location: {location}
- Trigger: {trigger}

PoC Strategy Used: {strategy}

Execution Result:
- Success: {success}
- Sanitizer output: {sanitizer}
- Exit code: {exit_code}
- Stdout: {stdout}
- Stderr: {stderr}

Why did this PoC fail? Consider:
1. Was the input reaching the vulnerable function?
2. Were there input validation checks blocking the payload?
3. Was the memory layout different than expected?
4. Did the PoC trigger a different code path?
5. Was the timing wrong (for race conditions)?
6. Was the size/offset calculation incorrect?

Respond with JSON:
{{
  "reason": "<root cause of failure>",
  "lesson": "<what to do differently>",
  "suggested_strategy": "<next strategy to try>",
  "payload_modification": "<how to modify the payload>"
}}"""


class StrategyManager:
    """Manages PoC strategies with learning feedback."""

    STRATEGIES = [
        "direct",               # Direct input to vulnerable function
        "header_mutation",      # Mutate headers/metadata instead of payload
        "size_manipulation",    # Manipulate size fields to trigger overflow
        "race_condition",       # Exploit timing windows
        "integer_wrap",         # Use integer overflow/wraparound
        "type_confusion",       # Mismatch types across boundaries
        "state_desync",         # Desynchronize state between modules
        "path_traversal",       # Traverse outside expected paths
        "encoding_bypass",      # Use encoding tricks to bypass validation
        "boundary_violation",   # Violate assumed boundaries
        "chunk_manipulation",   # Manipulate heap chunk metadata
        "signal_injection",     # Inject signals at critical moments
        "resource_exhaustion",  # Exhaust resources to break assumptions
        "reorder_operations",   # Reorder operations to violate invariants
    ]

    def __init__(self, model_config: dict, pattern_index):
        self.client = OpenAI(base_url=model_config["api_base"], api_key="not-needed")
        self.model = model_config["model_name"]
        self.timeout = model_config["timeout"]
        self.pattern_index = pattern_index

    def get_strategies(self, bug_type: str) -> list:
        """Get recommended strategies for a bug type, informed by learning."""
        recommended = self.pattern_index.get_recommended_strategies(bug_type)

        # If no learned strategies, use defaults based on bug type
        if not recommended:
            recommended = self._default_strategies(bug_type)

        return recommended[:5]  # Top 5 strategies

    def analyze_failure(self, finding: dict, poc: dict, validation: dict) -> dict:
        """Analyze a PoC failure and derive a lesson."""
        prompt = FAILURE_ANALYSIS_PROMPT.format(
            bug_type=finding.get("bug_type", "unknown"),
            location=finding.get("location", "unknown"),
            trigger=finding.get("trigger", ""),
            strategy=poc.get("strategy", "unknown"),
            success=validation.get("success", False),
            sanitizer=validation.get("sanitizer", "None"),
            exit_code=validation.get("exit_code", "N/A"),
            stdout=validation.get("output", "")[:500],
            stderr=validation.get("errors", "")[:500],
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security researcher analyzing exploit failures. Be precise about root causes."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=512,
                temperature=0.2,
                timeout=self.timeout,
            )

            content = response.choices[0].message.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            return json.loads(content.strip())

        except Exception:
            return {
                "reason": "Analysis failed",
                "lesson": "Try a different approach",
                "suggested_strategy": "direct",
                "payload_modification": "none",
            }

    def _default_strategies(self, bug_type: str) -> list:
        """Default strategy ordering based on bug type."""
        type_strategies = {
            "heap-buffer-overflow": ["size_manipulation", "direct", "chunk_manipulation", "encoding_bypass"],
            "stack-buffer-overflow": ["direct", "size_manipulation", "encoding_bypass", "path_traversal"],
            "use-after-free": ["race_condition", "chunk_manipulation", "state_desync", "direct"],
            "integer-overflow": ["integer_wrap", "size_manipulation", "direct", "boundary_violation"],
            "race-condition": ["race_condition", "reorder_operations", "signal_injection", "state_desync"],
            "null-pointer-dereference": ["direct", "state_desync", "resource_exhaustion", "encoding_bypass"],
            "type-confusion": ["type_confusion", "state_desync", "encoding_bypass", "direct"],
            "info-leak": ["direct", "boundary_violation", "size_manipulation", "encoding_bypass"],
            "command-injection": ["direct", "encoding_bypass", "path_traversal", "header_mutation"],
        }
        return type_strategies.get(bug_type.lower(), self.STRATEGIES[:5])
