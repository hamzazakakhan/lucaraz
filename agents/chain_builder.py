"""Chain Builder — constructs multi-stage exploit chains from primitives

Chain patterns:
- INFO_LEAK → ASLR bypass → ARB_WRITE → control hijack
- UAF → heap spray → ARB_WRITE → ROP chain
- RACE → TOCTOU → TYPE_CONFUSION → ARB_READ
- INTEGER_OVERFLOW → OOB_WRITE → code execution
"""

import json
from openai import OpenAI

CHAIN_PROMPT = """You are an exploit chain architect. Given a set of exploit primitives, \
construct multi-stage exploit chains.

Available primitives:
{primitives}

Existing primitive database (primitives from other findings):
{primitive_db}

Current exploit state:
{exploit_state}

Construct exploit chains by combining primitives. Each chain should:
1. Start with an information gathering step (if needed)
2. Bypass relevant protections (ASLR, DEP, canaries, etc.)
3. Achieve a meaningful goal (code execution, privilege escalation, etc.)

Common chain patterns:
- INFO_LEAK + ARB_WRITE = ASLR bypass + control flow hijack
- UAF + heap_spray + ARB_WRITE = use-after-free exploitation
- RACE + TYPE_CONFUSION = TOCTOU to type confusion
- OOB_READ + OOB_WRITE = relative read/write to absolute
- INTEGER_OVERFLOW + OOB_WRITE = size miscalculation to memory corruption

Respond with JSON array of chains:
[
  {{
    "chain_name": "<descriptive name>",
    "steps": ["<primitive1>", "<primitive2>", ...],
    "goal": "<what the chain achieves>",
    "aslr_bypass": true/false,
    "dep_bypass": true/false,
    "canary_bypass": true/false,
    "reliability": "<high|medium|low>",
    "requirements": ["<what must be true>"],
    "description": "<step-by-step explanation>"
  }}
]

If no viable chains can be constructed, return: []"""


class ChainBuilder:
    """Constructs multi-stage exploit chains from primitives."""

    def __init__(self, model_config: dict):
        self.client = OpenAI(base_url=model_config["api_base"], api_key="not-needed")
        self.model = model_config["model_name"]
        self.max_tokens = model_config["max_tokens"]
        self.timeout = model_config["timeout"]

    def build_chains(self, primitives: list, primitive_db, state_tracker) -> list:
        """Build exploit chains from available primitives."""
        if not primitives:
            return []

        # Format primitives for prompt
        prim_descriptions = []
        for p in primitives:
            prim_descriptions.append(
                f"- {p.get('primitive_type', 'UNKNOWN')}: "
                f"offset={p.get('offset_control', 'none')}, "
                f"size={p.get('size_control', 'none')}, "
                f"content={p.get('content_control', 'none')}, "
                f"repeat={p.get('repeatability', 'rare')}, "
                f"score={p.get('exploitability_score', 0)}, "
                f"from={p.get('source_location', 'unknown')}"
            )

        # Get all primitives from DB
        db_primitives = primitive_db.get_all() if primitive_db else []
        db_descriptions = []
        for p in db_primitives:
            db_descriptions.append(
                f"- {p.get('primitive_type', 'UNKNOWN')}: "
                f"offset={p.get('offset_control', 'none')}, "
                f"score={p.get('exploitability_score', 0)}"
            )

        # Get current exploit state
        exploit_state = state_tracker.get_state() if state_tracker else {}

        prompt = CHAIN_PROMPT.format(
            primitives="\n".join(prim_descriptions),
            primitive_db="\n".join(db_descriptions) if db_descriptions else "None",
            exploit_state=json.dumps(exploit_state, indent=2) if exploit_state else "{}",
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an exploit chain architect. Construct realistic, achievable chains."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=self.max_tokens,
                temperature=0.3,
                timeout=self.timeout,
            )

            content = response.choices[0].message.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            chains = json.loads(content.strip())
            if isinstance(chains, list):
                return chains
            return []

        except Exception as e:
            print(f"    Chain builder error: {e}")
            return []
