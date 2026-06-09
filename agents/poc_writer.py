"""PoC Writer — generates proof-of-concept exploits with strategy-awareness"""

import json
from openai import OpenAI

POC_PROMPT = """Write a minimal proof-of-concept exploit for the following vulnerability.

Vulnerability:
- Type: {bug_type}
- Location: {location}
- Description: {description}
- Trigger: {trigger}
- Impact: {impact}

Target Language: {language}
Iteration: {iteration}
Strategy: {strategy}

{failure_context}

Requirements:
1. The PoC must be standalone and trigger the bug
2. Use the simplest possible approach matching the strategy
3. For memory bugs: aim for crash detectable by ASan/UBSan
4. For logic bugs: demonstrate incorrect behavior
5. For race conditions: use threading/forking to trigger timing window
6. Include comments explaining the exploit strategy

Respond with JSON:
{{
  "poc_code": "<full source code>",
  "poc_type": "<c_program, python_script, shell_command, input_file>",
  "compile_cmd": "<how to compile>",
  "run_cmd": "<how to run>",
  "expected_result": "<what should happen>",
  "strategy": "<exploit strategy used>"
}}"""


class PoCWriter:
    """Generates proof-of-concept exploits with strategy-awareness."""

    def __init__(self, model_config: dict, agent_config: dict):
        self.client = OpenAI(base_url=model_config["api_base"], api_key="not-needed")
        self.model = model_config["model_name"]
        self.max_tokens = model_config["max_tokens"]
        self.temperature = model_config["temperature"]
        self.timeout = model_config["timeout"]

    def write_poc(self, vuln: dict, language: str, iteration: int = 0, strategy: str = "direct") -> dict:
        """Write a PoC for the given vulnerability using the specified strategy."""
        failure_context = ""
        if iteration > 0 and "last_failure" in vuln:
            last = vuln["last_failure"]
            lesson = vuln.get("last_lesson", {})
            failure_context = (
                f"Previous PoC FAILED (iteration {iteration}):\n"
                f"Expected: {last.get('expected', 'N/A')}\n"
                f"Actual: {last.get('output', 'N/A')}\n"
                f"Sanitizer: {last.get('sanitizer', 'None')}\n"
                f"Exit code: {last.get('exit_code', 'N/A')}\n"
            )
            if lesson:
                failure_context += f"Lesson learned: {lesson.get('lesson', 'N/A')}\n"
            failure_context += (
                "Analyze why the PoC failed and write an improved version.\n"
                "Consider: Is input reaching the vulnerable function? "
                "Are there validation checks blocking the payload? "
                "Is the memory layout different than expected?"
            )

        prompt = POC_PROMPT.format(
            bug_type=vuln.get("bug_type", "unknown"),
            location=vuln.get("location", "unknown"),
            description=vuln.get("description", ""),
            trigger=vuln.get("trigger", ""),
            impact=vuln.get("impact", ""),
            language=language,
            iteration=iteration + 1,
            strategy=strategy,
            failure_context=failure_context,
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an exploit developer. Write minimal, precise PoCs matching the given strategy."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=self.max_tokens,
                temperature=max(0.2, self.temperature - 0.1 * iteration),
                timeout=self.timeout,
            )

            content = response.choices[0].message.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            poc = json.loads(content.strip())
            poc["iteration"] = iteration + 1
            return poc

        except Exception as e:
            return {
                "poc_code": f"// PoC generation failed: {e}",
                "poc_type": "c_program",
                "compile_cmd": "",
                "run_cmd": "",
                "expected_result": "N/A",
                "strategy": strategy,
                "iteration": iteration + 1,
            }
