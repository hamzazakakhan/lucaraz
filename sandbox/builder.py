"""Target Builder — builds targets with sanitizers and coverage instrumentation"""

import subprocess
import os
from pathlib import Path


class TargetBuilder:
    """Builds target projects with sanitizers and coverage instrumentation."""

    def __init__(self, sandbox_config: dict):
        self.sanitizers = sandbox_config.get("sanitizers", ["address", "undefined"])

    def build(self, source_dir: Path, build_dir: Path, language: str, build_system: str) -> dict:
        build_dir.mkdir(parents=True, exist_ok=True)
        if language in ("c", "cpp"):
            return self._build_c_cpp(source_dir, build_dir, build_system)
        elif language == "rust":
            return self._build_rust(source_dir, build_dir)
        elif language == "go":
            return self._build_go(source_dir, build_dir)
        return {"success": True, "build_dir": str(source_dir)}

    def _sanitizer_flags(self) -> str:
        flag_map = {"address": "-fsanitize=address", "undefined": "-fsanitize=undefined",
                     "memory": "-fsanitize=memory", "thread": "-fsanitize=thread"}
        flags = [flag_map.get(s, "") for s in self.sanitizers]
        if "address" in self.sanitizers and "memory" in self.sanitizers:
            flags = [f for f in flags if "memory" not in f]
        return " ".join(f for f in flags if f)

    def _build_c_cpp(self, source_dir: Path, build_dir: Path, build_system: str) -> dict:
        san_flags = self._sanitizer_flags()
        cov_flags = "-fprofile-instr-generate -fcoverage-mapping"
        env = {"CC": "clang", "CXX": "clang++",
               "CFLAGS": f"{san_flags} -g -O1 -fno-omit-frame-pointer {cov_flags}",
               "CXXFLAGS": f"{san_flags} -g -O1 -fno-omit-frame-pointer {cov_flags}",
               "LDFLAGS": san_flags}
        full_env = {**os.environ, **env}

        if build_system == "cmake":
            r = subprocess.run(["cmake", "-S", str(source_dir), "-B", str(build_dir),
                                f"-DCMAKE_C_FLAGS={env['CFLAGS']}", f"-DCMAKE_CXX_FLAGS={env['CXXFLAGS']}",
                                "-DCMAKE_BUILD_TYPE=Debug"],
                               capture_output=True, text=True, env=full_env, timeout=300)
            if r.returncode != 0:
                return {"success": False, "error": r.stderr[:500]}
            r = subprocess.run(["cmake", "--build", str(build_dir), "-j4"],
                               capture_output=True, text=True, env=full_env, timeout=600)
        elif build_system == "autotools":
            configure = source_dir / "configure"
            if not configure.exists():
                subprocess.run(["sh", "autoreconf", "-fi"], cwd=str(source_dir),
                               capture_output=True, text=True, timeout=120)
            r = subprocess.run([str(configure), f"--prefix={build_dir}/install"],
                               capture_output=True, text=True, env=full_env, cwd=str(build_dir), timeout=300)
            if r.returncode != 0:
                return {"success": False, "error": r.stderr[:500]}
            r = subprocess.run(["make", "-j4"], capture_output=True, text=True,
                               env=full_env, cwd=str(build_dir), timeout=600)
        else:
            r = subprocess.run(["make", "-j4", f"CFLAGS={env['CFLAGS']}", f"LDFLAGS={san_flags}"],
                               capture_output=True, text=True, env=full_env, cwd=str(source_dir), timeout=600)

        if r.returncode == 0:
            return {"success": True, "build_dir": str(build_dir)}
        return {"success": False, "error": r.stderr[:500]}

    def _build_rust(self, source_dir: Path, build_dir: Path) -> dict:
        env = {"RUSTFLAGS": "-Zsanitizer=address", "RUSTUP_TOOLCHAIN": "nightly"}
        full_env = {**os.environ, **env}
        r = subprocess.run(["cargo", "build"], capture_output=True, text=True,
                           env=full_env, cwd=str(source_dir), timeout=600)
        if r.returncode == 0:
            return {"success": True, "build_dir": str(source_dir / "target" / "debug")}
        return {"success": False, "error": r.stderr[:500]}

    def _build_go(self, source_dir: Path, build_dir: Path) -> dict:
        r = subprocess.run(["go", "build", "-race", "./..."], capture_output=True, text=True,
                           cwd=str(source_dir), timeout=600)
        if r.returncode == 0:
            return {"success": True, "build_dir": str(source_dir)}
        return {"success": False, "error": r.stderr[:500]}
