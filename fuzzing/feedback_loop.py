"""Fuzzing Feedback Loop — continuous LLM → fuzzer → coverage → LLM refinement

Hybrid loop: LLM generates structured seeds → AFL++/libFuzzer mutates →
coverage feedback → LLM refines seeds for uncovered paths
"""

import subprocess
import os
import json
import tempfile
from pathlib import Path


class FuzzingFeedbackLoop:
    """Continuous fuzzing with LLM-guided seed generation and coverage feedback."""

    def __init__(self, fuzz_config: dict):
        self.engine = fuzz_config.get("engine", "afl++")
        self.duration = fuzz_config.get("duration", 3600)
        self.seed_count = fuzz_config.get("seed_count", 100)
        self.coverage_level = fuzz_config.get("coverage_level", "edge")
        self.llm_seed_ratio = fuzz_config.get("llm_seed_ratio", 0.4)

    def run(self, source_dir: Path, build_dir: Path, language: str,
            seed_generator, pattern_index) -> list:
        """Run fuzzing feedback loop. Returns list of findings."""
        findings = []

        # Phase 1: Generate initial seeds
        llm_seed_count = int(self.seed_count * self.llm_seed_ratio)
        random_seed_count = self.seed_count - llm_seed_count

        seed_dir = build_dir / "seeds"
        seed_dir.mkdir(exist_ok=True)

        # Generate LLM seeds
        llm_seeds = seed_generator.generate_seeds(
            source_dir, language, count=llm_seed_count
        )
        for i, seed in enumerate(llm_seeds):
            seed_path = seed_dir / f"llm_seed_{i:04d}"
            with open(seed_path, "wb") as f:
                if isinstance(seed, bytes):
                    f.write(seed)
                else:
                    f.write(seed.encode())

        # Generate random seeds
        for i in range(random_seed_count):
            seed_path = seed_dir / f"rand_seed_{i:04d}"
            with open(seed_path, "wb") as f:
                f.write(os.urandom(32))

        # Phase 2: Run fuzzer
        fuzz_result = self._run_fuzzer(source_dir, build_dir, seed_dir, language)

        # Phase 3: Analyze crashes
        if fuzz_result.get("crash_dir"):
            crashes = self._analyze_crashes(fuzz_result["crash_dir"])
            findings.extend(crashes)

        # Phase 4: Check coverage and generate targeted seeds for uncovered paths
        if fuzz_result.get("coverage_data"):
            uncovered = self._find_uncovered(fuzz_result["coverage_data"])
            if uncovered:
                targeted_seeds = seed_generator.generate_targeted_seeds(
                    uncovered, language, count=20
                )
                for i, seed in enumerate(targeted_seeds):
                    seed_path = seed_dir / f"targeted_seed_{i:04d}"
                    with open(seed_path, "wb") as f:
                        if isinstance(seed, bytes):
                            f.write(seed)
                        else:
                            f.write(seed.encode())

                # Run fuzzer again with targeted seeds
                fuzz_result2 = self._run_fuzzer(source_dir, build_dir, seed_dir, language)
                if fuzz_result2.get("crash_dir"):
                    findings.extend(self._analyze_crashes(fuzz_result2["crash_dir"]))

        return findings

    def _run_fuzzer(self, source_dir: Path, build_dir: Path, seed_dir: Path, language: str) -> dict:
        """Run the configured fuzzer."""
        # Find the fuzzing harness
        harness = self._find_harness(source_dir, build_dir, language)
        if not harness:
            return {"error": "No fuzzing harness found"}

        if self.engine == "afl++":
            return self._run_afl(harness, seed_dir, build_dir)
        elif self.engine == "libfuzzer":
            return self._run_libfuzzer(harness, seed_dir, build_dir)
        else:
            return self._run_afl(harness, seed_dir, build_dir)

    def _run_afl(self, harness: str, seed_dir: Path, build_dir: Path) -> dict:
        """Run AFL++ fuzzer."""
        output_dir = build_dir / "afl_output"
        output_dir.mkdir(exist_ok=True)

        try:
            result = subprocess.run(
                ["afl-fuzz", "-i", str(seed_dir), "-o", str(output_dir),
                 "-t", "1000", "-m", "none", "--", harness],
                capture_output=True, text=True,
                timeout=self.duration,
            )
        except subprocess.TimeoutExpired:
            pass  # Expected — fuzzer runs until timeout
        except FileNotFoundError:
            return {"error": "AFL++ not installed"}

        crash_dir = output_dir / "default" / "crashes"
        return {
            "crash_dir": str(crash_dir) if crash_dir.exists() else None,
            "coverage_data": str(output_dir / "default" / "cov") if (output_dir / "default" / "cov").exists() else None,
        }

    def _run_libfuzzer(self, harness: str, seed_dir: Path, build_dir: Path) -> dict:
        """Run libFuzzer."""
        crash_dir = build_dir / "libfuzzer_crashes"
        crash_dir.mkdir(exist_ok=True)

        try:
            result = subprocess.run(
                [harness, f"-seed_inputs={seed_dir}",
                 f"-artifact_prefix={crash_dir}/",
                 f"-max_total_time={self.duration}",
                 f"-jobs=0"],
                capture_output=True, text=True,
                timeout=self.duration + 60,
                cwd=str(build_dir),
            )
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            return {"error": "libFuzzer harness not found"}

        return {
            "crash_dir": str(crash_dir),
            "coverage_data": None,
        }

    def _find_harness(self, source_dir: Path, build_dir: Path, language: str) -> str:
        """Find or identify a fuzzing harness."""
        # Check for existing harnesses
        harness_patterns = ["fuzz_", "fuzz", "harness", "target"]
        for pattern in harness_patterns:
            for path in build_dir.rglob(f"*{pattern}*"):
                if path.is_file() and os.access(path, os.X_OK):
                    return str(path)
        return ""

    def _analyze_crashes(self, crash_dir: str) -> list:
        """Analyze crash files from fuzzer output."""
        findings = []
        crash_path = Path(crash_dir)

        if not crash_path.exists():
            return findings

        for crash_file in crash_path.iterdir():
            if crash_file.is_file() and crash_file.stat().st_size < 10000:
                try:
                    with open(crash_file, "rb") as f:
                        crash_data = f.read()

                    findings.append({
                        "bug_type": "fuzzer_crash",
                        "location": "unknown",
                        "description": f"Fuzzer crash: {crash_file.name}",
                        "trigger": f"Input from {crash_file.name}",
                        "impact": "crash",
                        "poc_code": f"// Fuzzer crash input: {crash_file.name}\n// Size: {len(crash_data)} bytes",
                        "poc_type": "input_file",
                        "crash_data_path": str(crash_file),
                        "new_coverage": True,
                        "discovery_method": "fuzzing",
                    })
                except OSError:
                    continue

        return findings

    def _find_uncovered(self, coverage_data: str) -> list:
        """Find uncovered code paths from coverage data."""
        # Simplified — in production, parse LLVM source-based coverage
        return []
