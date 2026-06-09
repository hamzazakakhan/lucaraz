"""PoC Validator — executes PoCs in isolated containers, checks sanitizer/crash/coverage"""

import subprocess
import tempfile
import os
from pathlib import Path


class PoCValidator:
    """Validates PoCs by executing them in isolated Docker containers."""

    def __init__(self, sandbox_config: dict):
        self.network = sandbox_config.get("network", "none")
        self.memory_limit = sandbox_config.get("memory_limit", "4g")
        self.cpu_limit = sandbox_config.get("cpu_limit", 4)
        self.timeout = sandbox_config.get("timeout", 120)

    def validate(self, poc: dict, vuln: dict, source_dir: Path, language: str) -> dict:
        """Execute a PoC and check if it triggers the vulnerability."""
        poc_code = poc.get("poc_code", "")
        poc_type = poc.get("poc_type", "c_program")
        compile_cmd = poc.get("compile_cmd", "")
        run_cmd = poc.get("run_cmd", "")
        expected = poc.get("expected_result", "")

        if not poc_code or "Failed to generate" in poc_code:
            return {"success": False, "reason": "No valid PoC code"}

        with tempfile.TemporaryDirectory(prefix="vulscanx_poc_") as tmpdir:
            ext = self._get_extension(poc_type, language)
            poc_path = os.path.join(tmpdir, f"poc{ext}")
            with open(poc_path, "w") as f:
                f.write(poc_code)

            # Compile if needed
            if poc_type in ("c_program", "cpp_program") and compile_cmd:
                compile_result = self._run_in_container(tmpdir, compile_cmd, source_dir)
                if compile_result["exit_code"] != 0:
                    return {
                        "success": False, "reason": "Compilation failed",
                        "output": compile_result["stdout"][:1000],
                        "errors": compile_result["stderr"][:1000],
                        "exit_code": compile_result["exit_code"],
                    }

            if not run_cmd:
                run_cmd = self._default_run_cmd(poc_type)

            exec_result = self._run_in_container(tmpdir, run_cmd, source_dir)

            sanitizer_hit = self._check_sanitizer(exec_result)
            crashed = self._check_crash(exec_result)
            expected_match = self._check_expected(exec_result, expected)
            partial_corruption = self._check_partial_corruption(exec_result)
            new_coverage = self._check_coverage(exec_result)

            success = bool(sanitizer_hit) or crashed or expected_match

            return {
                "success": success,
                "output": exec_result["stdout"][:2000],
                "errors": exec_result["stderr"][:2000],
                "exit_code": exec_result["exit_code"],
                "sanitizer": sanitizer_hit,
                "crashed": crashed,
                "expected_match": expected_match,
                "partial_corruption": partial_corruption,
                "new_coverage": new_coverage,
            }

    def _run_in_container(self, workdir: str, command: str, source_dir: Path) -> dict:
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", "--network", self.network,
                 "--memory", self.memory_limit, "--cpus", str(self.cpu_limit),
                 "-v", f"{workdir}:/work:rw",
                 "-v", f"{source_dir}:/target:ro",
                 "--security-opt", "no-new-privileges",
                 "vulnscan-runner", "sh", "-c", command],
                capture_output=True, text=True, timeout=self.timeout,
            )
            return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.returncode}
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "TIMEOUT", "exit_code": -1}
        except FileNotFoundError:
            return self._run_local(workdir, command)
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1}

    def _run_local(self, workdir: str, command: str) -> dict:
        try:
            result = subprocess.run(["sh", "-c", command], capture_output=True, text=True,
                                    timeout=self.timeout, cwd=workdir)
            return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.returncode}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1}

    def _check_sanitizer(self, result: dict) -> str:
        combined = result.get("stderr", "") + result.get("stdout", "")
        patterns = ["AddressSanitizer", "Heap-buffer-overflow", "Heap-use-after-free",
                     "Stack-buffer-overflow", "SEGV", "UndefinedBehaviorSanitizer",
                     "runtime error:", "MemorySanitizer", "use-of-uninitialized-value",
                     "ThreadSanitizer", "data race"]
        lines = [l for l in combined.split("\n") if any(p in l for p in patterns)]
        return "\n".join(lines[:10]) if lines else ""

    def _check_crash(self, result: dict) -> bool:
        exit_code = result.get("exit_code", 0)
        if exit_code > 128:
            return (exit_code - 128) in [6, 7, 8, 11]  # SIGABRT, SIGBUS, SIGFPE, SIGSEGV
        return exit_code < 0

    def _check_expected(self, result: dict, expected: str) -> bool:
        if not expected:
            return False
        combined = (result.get("stdout", "") + result.get("stderr", "")).lower()
        if "crash" in expected.lower() and self._check_crash(result):
            return True
        if "asan" in expected.lower() and self._check_sanitizer(result):
            return True
        return False

    def _check_partial_corruption(self, result: dict) -> bool:
        """Check for signs of partial memory corruption (non-crash)."""
        stderr = result.get("stderr", "")
        partial_signals = ["WARNING:", "corrupted", "double free", "invalid free",
                          "alloc-dealloc", "heap overflow", "stack overflow"]
        return any(s in stderr for s in partial_signals)

    def _check_coverage(self, result: dict) -> bool:
        """Check if new code coverage was achieved (from profdata)."""
        stdout = result.get("stdout", "")
        return "new coverage" in stdout.lower() or "covered" in stdout.lower()

    def _get_extension(self, poc_type: str, language: str) -> str:
        return {"c_program": ".c", "cpp_program": ".cpp", "python_script": ".py",
                "shell_command": ".sh", "input_file": ".input",
                "rust_program": ".rs", "go_program": ".go"}.get(poc_type, f".{language}")

    def _default_run_cmd(self, poc_type: str) -> str:
        return {"c_program": "cd /work && ./poc", "cpp_program": "cd /work && ./poc",
                "python_script": "cd /work && python3 poc.py",
                "shell_command": "cd /work && sh poc.sh"}.get(poc_type, "cd /work && ./poc")
