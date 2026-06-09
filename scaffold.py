#!/usr/bin/env python3
"""VULSCAN-X — GLM-5.2 Autonomous Zero-Day Discovery & Exploitation Scaffold

Closed-loop, self-improving vulnerability research system:
  Attempt → Fail → Analyze Failure → Learn → Explore Variants → Succeed

Usage:
    python scaffold.py --target <repo_url> [--mode zero-day] [--config config.yaml]
"""

import argparse
import json
import os
import sys
import yaml
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents.vuln_finder import VulnerabilityFinder
from agents.invariant_breaker import InvariantBreaker
from agents.poc_writer import PoCWriter
from agents.validator import PoCValidator
from agents.primitive_extractor import PrimitiveExtractor
from agents.chain_builder import ChainBuilder
from exploration.beam_search import BeamSearch
from exploration.strategy_manager import StrategyManager
from learning.pattern_index import PatternIndex
from fuzzing.feedback_loop import FuzzingFeedbackLoop
from fuzzing.llm_seed_generator import LLMSeedGenerator
from exploit.primitive_db import PrimitiveDB
from exploit.constraint_solver import ConstraintSolver
from sandbox.container import ContainerManager
from sandbox.builder import TargetBuilder
from sandbox.state_tracker import StateTracker
from triage.severity import SeverityClassifier
from triage.dedup import DedupChecker
from triage.filter import FalsePositiveFilter
from disclosure.commit import SHA3Committer
from ranker import GraphRanker


class VulscanX:
    """Main orchestrator — closed-loop zero-day discovery system."""

    def __init__(self, config_path: str = "config.yaml"):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)

        self.model_cfg = self.config["model"]
        self.agent_cfg = self.config["agent"]
        self.mode = self.config.get("mode", "standard")
        self.output_dir = Path(self.config["output"]["dir"])
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Core agents
        self.finder = VulnerabilityFinder(self.model_cfg, self.agent_cfg)
        self.invariant_breaker = InvariantBreaker(self.model_cfg, self.agent_cfg)
        self.poc_writer = PoCWriter(self.model_cfg, self.agent_cfg)
        self.validator = PoCValidator(self.config["sandbox"])
        self.primitive_extractor = PrimitiveExtractor(self.model_cfg)
        self.chain_builder = ChainBuilder(self.model_cfg)

        # Learning system
        self.pattern_index = PatternIndex(
            self.config["learning"]["failure_db"],
            self.config["learning"]["success_db"],
        )

        # Exploration
        self.beam = BeamSearch(
            width=self.agent_cfg["beam_width"],
            depth=self.agent_cfg["beam_depth"],
        )
        self.strategy_mgr = StrategyManager(self.model_cfg, self.pattern_index)

        # Fuzzing
        self.fuzz_loop = FuzzingFeedbackLoop(self.config["fuzzing"])
        self.seed_gen = LLMSeedGenerator(self.model_cfg)

        # Exploit construction
        self.primitive_db = PrimitiveDB()
        self.constraint_solver = ConstraintSolver(self.model_cfg)

        # Infrastructure
        self.container_mgr = ContainerManager(self.config["sandbox"])
        self.builder = TargetBuilder(self.config["sandbox"])
        self.state_tracker = StateTracker()

        # Triage
        self.classifier = SeverityClassifier()
        self.dedup = DedupChecker(self.config["triage"].get("nvd_api_key", ""))
        self.fp_filter = FalsePositiveFilter(self.model_cfg)
        self.committer = SHA3Committer()

        # Graph-based ranking
        self.ranker = GraphRanker(self.model_cfg)

        print(f"  VULSCAN-X initialized | Mode: {self.mode}")

    def run_target(self, target_cfg: dict):
        """Full closed-loop pipeline against a single target."""
        name = target_cfg["name"]
        url = target_cfg.get("url", "")
        language = target_cfg["language"]

        print(f"\n{'='*70}")
        print(f"  VULSCAN-X | Target: {name} ({language}) | Mode: {self.mode}")
        print(f"{'='*70}\n")

        workspace = self.output_dir / name
        workspace.mkdir(exist_ok=True)

        # Support local source_dir override
        if target_cfg.get("source_dir"):
            source_dir = Path(target_cfg["source_dir"])
        else:
            source_dir = workspace / "source"

        # Phase 1: Intelligent Codebase Mapping
        print("[Phase 1] Intelligent Codebase Mapping...")
        if not source_dir.exists():
            self._clone_repo(url, source_dir)

        build_dir = workspace / "build"
        build_result = self.builder.build(source_dir, build_dir, language, target_cfg.get("build_system", "make"))
        build_ok = build_result.get("success", False)
        if not build_ok:
            print(f"  BUILD FAILED: {build_result.get('error', 'unknown')} — continuing with source-only analysis")

        # Graph-based file ranking
        code_map = self.ranker.build_code_map(source_dir, language)
        ranked_files = self.ranker.rank_files(code_map, language, name)
        top_files = ranked_files[:self.agent_cfg["files_per_run"]]
        print(f"  Code map: {code_map['stats']} | Top {len(top_files)} files selected")

        # Phase 2: Parallel Vulnerability Exploration
        print("[Phase 2] Parallel Vulnerability Exploration...")
        raw_findings = []
        max_workers = self.agent_cfg["parallel_agents"]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for f in top_files:
                futures[executor.submit(self._explore_file, f, name, language, source_dir)] = f
            for future in as_completed(futures):
                try:
                    results = future.result()
                    raw_findings.extend(results)
                except Exception as e:
                    print(f"  Agent error: {e}")

        print(f"  Raw findings: {len(raw_findings)}")

        # Phase 3: Failure-Driven Learning Loop (beam search)
        print("[Phase 3] Failure-Driven Learning Loop...")
        validated = self._learning_loop(raw_findings, language, source_dir)

        # Phase 4: Primitive Extraction
        print("[Phase 4] Primitive Extraction...")
        primitives = []
        for finding in validated:
            prim = self.primitive_extractor.extract(finding, language)
            if prim:
                self.primitive_db.add(prim)
                primitives.append(prim)
                finding["primitive"] = prim
        print(f"  Extracted {len(primitives)} exploit primitives")

        # Phase 5: Exploit Chain Construction
        print("[Phase 5] Exploit Chain Construction...")
        chains = self.chain_builder.build_chains(primitives, self.primitive_db, self.state_tracker)
        for chain in chains:
            print(f"  Chain: {' -> '.join(chain['steps'])}")

        # Phase 6: Fuzzing Feedback Loop
        print("[Phase 6] Fuzzing Feedback Loop...")
        fuzz_results = self.fuzz_loop.run(source_dir, build_dir, language, self.seed_gen, self.pattern_index)
        for fr in fuzz_results:
            if fr.get("new_coverage") or fr.get("crash"):
                raw_findings.append(fr)

        # Phase 7: Triage & Report
        print("[Phase 7] Triage & Report...")
        triaged = self._triage_findings(validated + fuzz_results, name)

        # Save state
        self.state_tracker.save(workspace / "exploit_context.json")
        self.pattern_index.save()

        # Save results
        report_path = workspace / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, "w") as f:
            json.dump(triaged, f, indent=2, default=str)

        # SHA-3 commitments
        for finding in triaged:
            finding["commitment"] = self.committer.commit(finding)

        print(f"\n  RESULTS: {len(triaged)} validated | {len(primitives)} primitives | {len(chains)} chains")
        print(f"  Report: {report_path}")
        return triaged

    def _explore_file(self, file_info: dict, project: str, language: str, source_dir: Path) -> list:
        """Run multiple agents on a single file for diverse findings."""
        findings = []
        file_path = file_info["path"]

        # Agent 1: Classical vulnerability finder
        vulns = self.finder.analyze_file(file_path, language, project, source_dir)
        findings.extend(vulns)

        # Agent 2: Invariant breaker (zero-day mode emphasis)
        if self.mode == "zero-day":
            inv_violations = self.invariant_breaker.break_invariants(file_path, language, project, source_dir)
            findings.extend(inv_violations)

        return findings

    def _learning_loop(self, findings: list, language: str, source_dir: Path) -> list:
        """Closed-loop: attempt -> fail -> learn -> retry with beam search."""
        validated = []

        for finding in findings:
            # Beam search over PoC strategies
            beam_results = self.beam.search(
                initial_state=finding,
                expand_fn=lambda state, depth: self._expand_poc(state, language, depth),
                score_fn=self._score_attempt,
            )

            for result in beam_results:
                if result["score"] > 0.5:
                    validated.append(result["finding"])
                    self.pattern_index.record_success({
                        "bug_type": finding.get("bug_type"),
                        "strategy": result.get("strategy"),
                        "iterations": result.get("iterations", 0),
                        "primitive": result.get("primitive"),
                    })
                else:
                    self.pattern_index.record_failure({
                        "bug_type": finding.get("bug_type"),
                        "failure_reason": result.get("failure_reason", "unknown"),
                        "attempted_strategy": result.get("strategy"),
                        "lesson": result.get("lesson", ""),
                    })

        return validated

    def _expand_poc(self, state: dict, language: str, depth: int) -> list:
        """Expand a PoC attempt into variants (beam search children)."""
        variants = []
        strategies = self.strategy_mgr.get_strategies(state.get("bug_type", "unknown"))

        for strategy in strategies:
            poc = self.poc_writer.write_poc(state, language, depth, strategy=strategy)
            validation = self.validator.validate(poc, state, Path(state.get("source_dir", ".")), language)

            variant = {
                "finding": state,
                "poc": poc,
                "validation": validation,
                "strategy": strategy,
                "iterations": depth + 1,
                "score": self._score_attempt(validation),
            }

            if not validation.get("success"):
                lesson = self.strategy_mgr.analyze_failure(state, poc, validation)
                variant["failure_reason"] = lesson.get("reason", "unknown")
                variant["lesson"] = lesson.get("lesson", "")
                state["last_failure"] = validation
                state["last_lesson"] = lesson

            variants.append(variant)

        return variants

    def _score_attempt(self, result: dict) -> float:
        """Score a PoC attempt for beam search ranking."""
        if isinstance(result, dict) and "validation" in result:
            validation = result["validation"]
        elif isinstance(result, dict):
            validation = result
        else:
            return 0.0

        score = 0.0
        if validation.get("success"):
            score += 1.0
        if validation.get("sanitizer"):
            score += 0.5
        if validation.get("crashed"):
            score += 0.3
        if validation.get("expected_match"):
            score += 0.2
        if validation.get("partial_corruption"):
            score += 0.4
        if validation.get("new_coverage"):
            score += 0.3

        iterations = result.get("iterations", 1) if isinstance(result, dict) else 1
        score -= 0.05 * iterations
        return max(0.0, score)

    def _triage_findings(self, findings: list, project: str) -> list:
        """Filter, classify, score, and novelty-detect findings."""
        validated = []
        for finding in findings:
            severity = self.classifier.classify(finding)
            finding["severity"] = severity["level"]
            finding["cvss"] = severity["cvss"]

            min_sev = self.config["triage"].get("min_severity", "low")
            sev_order = ["low", "medium", "high", "critical"]
            if sev_order.index(finding["severity"]) < sev_order.index(min_sev):
                continue

            if self.config["triage"].get("dedup_check"):
                if self.dedup.check(finding, project):
                    continue

            if self.fp_filter.is_fp(finding):
                continue

            if self.config["triage"].get("novelty_detection"):
                novelty = self.pattern_index.check_novelty(finding)
                finding["novelty_score"] = novelty["score"]
                finding["novelty_reason"] = novelty.get("reason", "")

            validated.append(finding)

        return validated

    def _clone_repo(self, url: str, dest: Path):
        import subprocess
        subprocess.run(["git", "clone", "--depth", "1", url, str(dest)],
                       capture_output=True, text=True, timeout=600)


def main():
    parser = argparse.ArgumentParser(description="VULSCAN-X: Autonomous Zero-Day Discovery")
    parser.add_argument("--target", help="Target repository URL")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--name", help="Target name")
    parser.add_argument("--language", default="c")
    parser.add_argument("--mode", choices=["standard", "zero-day"], default=None)
    args = parser.parse_args()

    scaffold = VulscanX(args.config)
    if args.mode:
        scaffold.mode = args.mode

    if args.target:
        target = {
            "name": args.name or args.target.split("/")[-1].replace(".git", ""),
            "url": args.target, "language": args.language,
            "build_system": "make", "priority": 1,
        }
        scaffold.run_target(target)
    else:
        for target in scaffold.config["targets"]:
            scaffold.run_target(target)


if __name__ == "__main__":
    main()
