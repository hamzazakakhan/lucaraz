"""State Tracker — maintains evolving exploit context across attempts

Tracks:
- Heap layout knowledge
- Leaked addresses
- Derived offsets
- Mitigation status (ASLR, canaries, etc.)
- Accumulated primitive inventory
"""

import json
from pathlib import Path


class StateTracker:
    """Maintains evolving exploit context for stateful exploitation."""

    def __init__(self):
        self.state = {
            "heap_layout": "unknown",
            "leaked_addresses": [],
            "derived_offsets": {},
            "aslr_status": "unknown",
            "canary_known": False,
            "canary_value": None,
            "pie_base": None,
            "heap_base": None,
            "stack_base": None,
            "libc_base": None,
            "primitives_available": [],
            "active_chains": [],
            "attempt_history": [],
        }

    def get_state(self) -> dict:
        """Get current exploit state."""
        return dict(self.state)

    def update(self, key: str, value):
        """Update a state field."""
        self.state[key] = value

    def add_leaked_address(self, address: str, region: str = "unknown"):
        """Record a leaked address."""
        self.state["leaked_addresses"].append({
            "address": address,
            "region": region,
        })

        # Auto-derive base addresses
        if region == "heap":
            self.state["heap_base"] = address
            self.state["aslr_status"] = "bypassed"
        elif region == "stack":
            self.state["stack_base"] = address
            self.state["aslr_status"] = "bypassed"
        elif region == "libc":
            self.state["libc_base"] = address
            self.state["aslr_status"] = "bypassed"
        elif region == "pie_text":
            self.state["pie_base"] = address
            self.state["aslr_status"] = "bypassed"

    def add_offset(self, name: str, offset: int):
        """Record a derived offset."""
        self.state["derived_offsets"][name] = offset

    def set_canary(self, value: str):
        """Record known canary value."""
        self.state["canary_known"] = True
        self.state["canary_value"] = value

    def add_primitive(self, primitive: dict):
        """Record an available primitive."""
        self.state["primitives_available"].append({
            "type": primitive.get("primitive_type", "UNKNOWN"),
            "location": primitive.get("source_location", "unknown"),
            "score": primitive.get("exploitability_score", 0),
        })

    def record_attempt(self, attempt: dict):
        """Record an exploitation attempt."""
        self.state["attempt_history"].append(attempt)

    def is_aslr_bypassed(self) -> bool:
        """Check if ASLR has been bypassed."""
        return self.state["aslr_status"] == "bypassed"

    def has_write_primitive(self) -> bool:
        """Check if a write primitive is available."""
        write_types = {"ARB_WRITE", "OOB_WRITE", "UAF", "TYPE_CONFUSION"}
        return any(p["type"] in write_types for p in self.state["primitives_available"])

    def has_read_primitive(self) -> bool:
        """Check if a read primitive is available."""
        read_types = {"ARB_READ", "OOB_READ", "INFO_LEAK"}
        return any(p["type"] in read_types for p in self.state["primitives_available"])

    def can_build_chain(self) -> bool:
        """Check if enough primitives exist for chain construction."""
        return self.has_read_primitive() and self.has_write_primitive()

    def save(self, path: Path):
        """Save state to file."""
        with open(path, "w") as f:
            json.dump(self.state, f, indent=2)

    def load(self, path: Path):
        """Load state from file."""
        if path.exists():
            with open(path) as f:
                self.state = json.load(f)
