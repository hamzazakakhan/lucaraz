"""Beam Search — explores PoC strategies with branching and scoring

Instead of linear retries, beam search explores multiple strategy variants:

  Attempt A ─┬─ A1 (direct)
             ├─ A2 (header mutation)
             └─ A3 (size manipulation)

Scoring: new_coverage → +score, partial_corruption → +score, crash → high score
Top candidates are retained for next depth level.
"""

from typing import Callable, Any


class BeamSearch:
    """Beam search over PoC strategies with scoring."""

    def __init__(self, width: int = 5, depth: int = 3):
        self.width = width  # Max branches per level
        self.depth = depth  # Max depth

    def search(self, initial_state: dict,
               expand_fn: Callable[[dict, int], list],
               score_fn: Callable[[dict], float]) -> list:
        """Run beam search.

        Args:
            initial_state: The initial finding to validate
            expand_fn: Function that takes (state, depth) and returns list of variants
            score_fn: Function that scores a variant (higher = better)

        Returns:
            List of all explored variants, sorted by score
        """
        all_results = []

        # Level 0: expand initial state
        current_beam = expand_fn(initial_state, 0)
        all_results.extend(current_beam)

        # Iterate through depth levels
        for depth in range(1, self.depth):
            if not current_beam:
                break

            # Score and select top candidates
            scored = [(score_fn(r), r) for r in current_beam]
            scored.sort(key=lambda x: x[0], reverse=True)
            top = scored[:self.width]

            # Expand each top candidate
            next_beam = []
            for score, state in top:
                if score >= 1.0:
                    # Already succeeded — no need to expand further
                    continue

                # Use the finding from this variant as the new state
                new_state = state.get("finding", initial_state)
                if state.get("failure_reason"):
                    new_state = dict(new_state)
                    new_state["last_failure"] = state.get("validation", {})
                    new_state["last_lesson"] = {"lesson": state.get("lesson", ""),
                                                 "reason": state.get("failure_reason", "")}

                variants = expand_fn(new_state, depth)
                next_beam.extend(variants)
                all_results.extend(variants)

            current_beam = next_beam

        # Final scoring and sorting
        all_results.sort(key=lambda r: score_fn(r), reverse=True)
        return all_results
