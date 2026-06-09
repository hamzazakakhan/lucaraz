"""Pattern Index — failure/success learning database with novelty detection

Stores lessons from failed and successful attempts, enabling:
- Failure-driven learning (avoid repeating failed strategies)
- Success pattern recognition (apply winning strategies)
- Novelty detection (flag findings unlike known patterns → zero-day signal)
"""

import json
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path


class PatternIndex:
    """Learning database for failure-driven improvement and novelty detection."""

    def __init__(self, failure_db_path: str, success_db_path: str):
        self.failure_db_path = failure_db_path
        self.success_db_path = success_db_path
        self.failures = self._load_db(failure_db_path)
        self.successes = self._load_db(success_db_path)
        self.pattern_cache = {}  # bug_type -> [strategies]

    def _load_db(self, path: str) -> list:
        """Load a JSON database."""
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def save(self):
        """Persist databases to disk."""
        for path, data in [(self.failure_db_path, self.failures),
                           (self.success_db_path, self.successes)]:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                json.dump(data, f, indent=2)

    def record_failure(self, lesson: dict):
        """Record a failed attempt and its lesson."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "bug_type": lesson.get("bug_type", "unknown"),
            "failure_reason": lesson.get("failure_reason", "unknown"),
            "attempted_strategy": lesson.get("attempted_strategy", ""),
            "lesson": lesson.get("lesson", ""),
        }
        self.failures.append(entry)
        self._invalidate_cache(lesson.get("bug_type", "unknown"))

    def record_success(self, result: dict):
        """Record a successful attempt."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "bug_type": result.get("bug_type", "unknown"),
            "strategy": result.get("strategy", ""),
            "iterations": result.get("iterations", 0),
            "primitive": result.get("primitive", {}),
        }
        self.successes.append(entry)
        self._invalidate_cache(result.get("bug_type", "unknown"))

    def get_failed_strategies(self, bug_type: str) -> list:
        """Get strategies that failed for this bug type."""
        return [f for f in self.failures if f["bug_type"] == bug_type]

    def get_successful_strategies(self, bug_type: str) -> list:
        """Get strategies that succeeded for this bug type."""
        return [s for s in self.successes if s["bug_type"] == bug_type]

    def get_lessons_for(self, bug_type: str) -> list:
        """Get learned lessons for a bug type."""
        lessons = []
        for f in self.failures:
            if f["bug_type"] == bug_type and f.get("lesson"):
                lessons.append(f["lesson"])
        return lessons

    def get_recommended_strategies(self, bug_type: str) -> list:
        """Get recommended strategies based on past successes and failures."""
        if bug_type in self.pattern_cache:
            return self.pattern_cache[bug_type]

        # Start with strategies that worked
        successful = [s["strategy"] for s in self.get_successful_strategies(bug_type) if s.get("strategy")]

        # Filter out strategies that consistently fail
        failed = [f["attempted_strategy"] for f in self.get_failed_strategies(bug_type) if f.get("attempted_strategy")]

        # Count failure frequency per strategy
        fail_counts = {}
        for s in failed:
            fail_counts[s] = fail_counts.get(s, 0) + 1

        # Recommend successful strategies first, then untried ones
        all_strategies = ["direct", "header_mutation", "size_manipulation", "race_condition",
                          "integer_wrap", "type_confusion", "state_desync", "path_traversal",
                          "encoding_bypass", "boundary_violation"]

        recommended = list(successful)
        for s in all_strategies:
            if s not in recommended and fail_counts.get(s, 0) < 3:
                recommended.append(s)

        self.pattern_cache[bug_type] = recommended
        return recommended

    def check_novelty(self, finding: dict) -> dict:
        """Check if a finding is novel (unlike known patterns) — zero-day signal."""
        bug_type = finding.get("bug_type", "unknown")
        description = finding.get("description", "")
        trigger = finding.get("trigger", "")
        combined = f"{bug_type} {description} {trigger}".lower()

        # Hash the finding for comparison
        finding_hash = hashlib.sha256(combined.encode()).hexdigest()[:16]

        # Check against known successes
        known_hashes = set()
        for s in self.successes:
            key = f"{s.get('bug_type', '')} {s.get('strategy', '')}".lower()
            known_hashes.add(hashlib.sha256(key.encode()).hexdigest()[:16])

        # Check against known CVE patterns
        known_cve_patterns = [
            "buffer overflow", "use-after-free", "double-free", "null pointer",
            "format string", "sql injection", "xss", "csrf", "directory traversal",
            "command injection", "heap overflow", "stack overflow", "integer overflow",
        ]

        is_known_pattern = any(p in combined for p in known_cve_patterns)

        # Novelty scoring
        novelty_score = 0.0
        reasons = []

        if not is_known_pattern:
            novelty_score += 0.4
            reasons.append("Does not match known vulnerability pattern")

        if finding.get("discovery_method") == "invariant_breaking":
            novelty_score += 0.3
            reasons.append("Found via assumption violation (not pattern matching)")

        if finding.get("cross_module"):
            novelty_score += 0.2
            reasons.append("Cross-module inconsistency")

        if "race" in combined or "concurrent" in combined or "atomic" in combined:
            novelty_score += 0.15
            reasons.append("Concurrency-related (often missed by static analysis)")

        if "state" in combined and ("inconsist" in combined or "desync" in combined):
            novelty_score += 0.15
            reasons.append("State inconsistency")

        return {
            "score": min(novelty_score, 1.0),
            "reason": "; ".join(reasons) if reasons else "Matches known patterns",
            "is_novel": novelty_score > 0.5,
        }

    def _invalidate_cache(self, bug_type: str):
        """Invalidate pattern cache for a bug type."""
        self.pattern_cache.pop(bug_type, None)
