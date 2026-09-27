"""Shared LLM utilities."""

import json


def extract_json(content: str):
    """Strip markdown code fences and parse JSON from an LLM response."""
    if "```json" in content:
        content = content.split("```json")[1].split("```")[0]
    elif "```" in content:
        content = content.split("```")[1].split("```")[0]
    return json.loads(content.strip())
