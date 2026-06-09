"""Container Manager — Docker container lifecycle for isolated execution"""

import subprocess
from pathlib import Path


class ContainerManager:
    """Manages Docker containers for isolated PoC execution."""

    def __init__(self, sandbox_config: dict):
        self.network = sandbox_config.get("network", "none")
        self.memory_limit = sandbox_config.get("memory_limit", "4g")
        self.cpu_limit = sandbox_config.get("cpu_limit", 4)
        self.image_prefix = sandbox_config.get("image_prefix", "vulnscan-")

    def build_base_images(self):
        """Build base Docker images for each language."""
        dockerfiles = {
            "c": """FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \\
    clang llvm gcc make autoconf automake libtool \\
    gdb valgrind afl++ && rm -rf /var/lib/apt/lists/*
ENV CC=clang CXX=clang++ CFLAGS="-fsanitize=address,undefined -g -O1"
""",
            "cpp": """FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \\
    clang llvm g++ make cmake autoconf automake libtool \\
    gdb valgrind libc++-dev afl++ && rm -rf /var/lib/apt/lists/*
""",
            "rust": """FROM rust:bookworm
RUN rustup toolchain install nightly && \\
    rustup default nightly && \\
    apt-get update && apt-get install -y gdb afl++ && rm -rf /var/lib/apt/lists/*
""",
            "go": """FROM golang:bookworm
RUN apt-get update && apt-get install -y gdb afl++ && rm -rf /var/lib/apt/lists/*
""",
        }
        for lang, dockerfile in dockerfiles.items():
            image_name = f"{self.image_prefix}{lang}"
            df_path = Path(f"/tmp/Dockerfile.{lang}")
            df_path.write_text(dockerfile)
            result = subprocess.run(
                ["docker", "build", "-t", image_name, "-f", str(df_path), "/tmp"],
                capture_output=True, text=True, timeout=600,
            )
            if result.returncode != 0:
                print(f"    Build FAILED for {image_name}: {result.stderr[:200]}")

    def exec_in_container(self, workdir: str, command: str, source_dir: str,
                          timeout: int = 120) -> dict:
        """Run a command in an isolated container."""
        try:
            result = subprocess.run(
                ["docker", "run", "--rm",
                 "--network", self.network,
                 "--memory", self.memory_limit,
                 "--cpus", str(self.cpu_limit),
                 "-v", f"{workdir}:/work:rw",
                 "-v", f"{source_dir}:/target:ro",
                 "--security-opt", "no-new-privileges",
                 "vulnscan-runner", "sh", "-c", command],
                capture_output=True, text=True, timeout=timeout,
            )
            return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.returncode}
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "TIMEOUT", "exit_code": -1}
        except FileNotFoundError:
            return self._run_local(workdir, command, timeout)
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1}

    def _run_local(self, workdir: str, command: str, timeout: int = 120) -> dict:
        try:
            result = subprocess.run(["sh", "-c", command], capture_output=True, text=True,
                                    timeout=timeout, cwd=workdir)
            return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.returncode}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1}
