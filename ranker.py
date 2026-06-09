"""Graph-based File Prioritization — call graph, data flow, trust boundary mapping"""

import os
import re
import subprocess
from pathlib import Path
from collections import defaultdict
from openai import OpenAI


class GraphRanker:
    """Ranks files using code graph analysis: call graph, data flow, trust boundaries."""

    def __init__(self, model_config: dict):
        self.client = OpenAI(base_url=model_config["api_base"], api_key="not-needed")
        self.model = model_config["model_name"]
        self.timeout = model_config["timeout"]

    def build_code_map(self, source_dir: Path, language: str) -> dict:
        """Build call graph, data flow graph, and trust boundary map."""
        source_files = self._collect_sources(source_dir, language)

        call_graph = defaultdict(list)       # caller -> [callees]
        reverse_calls = defaultdict(list)     # callee -> [callers]
        data_flow = defaultdict(list)         # source -> [sinks]
        trust_boundaries = []                 # [(file, boundary_type, direction)]
        file_metrics = {}

        for file_info in source_files:
            path = file_info["path"]
            try:
                with open(path, "r", errors="replace") as f:
                    content = f.read()
            except OSError:
                continue

            # Extract function calls
            calls = self._extract_calls(content, language)
            call_graph[path] = calls
            for callee in calls:
                reverse_calls[callee].append(path)

            # Identify data flow: input sources → processing → sinks
            inputs = self._find_input_sources(content, language)
            sinks = self._find_sinks(content, language)
            for inp in inputs:
                for sink in sinks:
                    data_flow[inp].append(sink)

            # Identify trust boundaries
            boundaries = self._find_trust_boundaries(content, language, path)
            trust_boundaries.extend(boundaries)

            # Compute file metrics
            file_metrics[path] = {
                "size": file_info["size"],
                "complexity": self._compute_complexity(content),
                "call_count": len(calls),
                "input_exposure": len(inputs),
                "sink_count": len(sinks),
                "boundary_count": len(boundaries),
                "memory_ops": self._count_memory_ops(content, language),
            }

        stats = {
            "files": len(source_files),
            "calls": sum(len(v) for v in call_graph.values()),
            "data_flows": sum(len(v) for v in data_flow.values()),
            "trust_boundaries": len(trust_boundaries),
        }

        return {
            "source_files": source_files,
            "call_graph": dict(call_graph),
            "reverse_calls": dict(reverse_calls),
            "data_flow": dict(data_flow),
            "trust_boundaries": trust_boundaries,
            "file_metrics": file_metrics,
            "stats": stats,
        }

    def rank_files(self, code_map: dict, language: str, project: str) -> list:
        """Rank files by vulnerability likelihood using graph metrics."""
        metrics = code_map["file_metrics"]
        reverse_calls = code_map["reverse_calls"]
        trust_boundaries = code_map["trust_boundaries"]
        data_flow = code_map["data_flow"]

        # Files on trust boundaries get bonus
        boundary_files = set()
        for b in trust_boundaries:
            boundary_files.add(b[0])

        # Files with many callers (high reachability) get bonus
        caller_counts = defaultdict(int)
        for callee, callers in reverse_calls.items():
            for caller in callers:
                caller_counts[caller] += 1

        # Files in data flow paths (input → sink) get bonus
        data_flow_files = set()
        for src, sinks in data_flow.items():
            data_flow_files.add(src)
            for s in sinks:
                data_flow_files.add(s)

        scored = []
        for path, m in metrics.items():
            score = 0.0

            # Complexity weight
            score += min(m["complexity"] / 50.0, 3.0)

            # Input exposure (network/file parsing)
            score += m["input_exposure"] * 2.0

            # Memory operations
            score += m["memory_ops"] * 1.5

            # Trust boundary bonus
            if path in boundary_files:
                score += 3.0

            # Reachability bonus
            score += min(caller_counts.get(path, 0) * 0.5, 3.0)

            # Data flow bonus
            if path in data_flow_files:
                score += 2.0

            # Sink count
            score += m["sink_count"] * 1.0

            scored.append({
                "path": path,
                "size": m["size"],
                "priority": min(int(score) + 1, 5),
                "score": round(score, 2),
                "metrics": m,
            })

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored

    def _collect_sources(self, source_dir: Path, language: str) -> list:
        """Collect source files."""
        exts = {"c": [".c", ".h"], "cpp": [".cpp", ".cc", ".cxx", ".hpp"],
                "rust": [".rs"], "go": [".go"], "java": [".java"]}
        extensions = exts.get(language, [".c", ".h"])
        files = []
        for ext in extensions:
            for path in source_dir.rglob(f"*{ext}"):
                rel = str(path.relative_to(source_dir))
                skip = ["test", "vendor", "third_party", "build", "node_modules", ".git", "fuzz"]
                if any(p in rel.lower() for p in skip):
                    continue
                try:
                    size = path.stat().st_size
                    if size < 500_000:
                        files.append({"path": str(path), "size": size})
                except OSError:
                    continue
        return files

    def _extract_calls(self, content: str, language: str) -> list:
        """Extract function calls from source."""
        if language in ("c", "cpp"):
            # Match function_name(
            pattern = r'\b([a-z_][a-z0-9_]*)\s*\('
        elif language == "rust":
            pattern = r'\b([a-z_][a-z0-9_]*)\s*\('
        elif language == "go":
            pattern = r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\('
        else:
            pattern = r'\b([a-z_][a-z0-9_]*)\s*\('

        # Filter out keywords
        keywords = {"if", "for", "while", "switch", "return", "sizeof", "typeof",
                     "case", "else", "struct", "union", "enum", "fn", "let", "mut",
                     "pub", "impl", "use", "mod", "func", "defer", "go", "select"}
        calls = re.findall(pattern, content)
        return list(set(c for c in calls if c not in keywords))

    def _find_input_sources(self, content: str, language: str) -> list:
        """Find input sources (network, file, CLI, env)."""
        input_patterns = {
            "c": [r"recv\b", r"read\b", r"fread\b", r"fgets\b", r"scanf\b",
                   r"getenv\b", r"argc\b", r"argv\b", r"accept\b", r"recvfrom\b",
                   r"SSL_read\b", r"BIO_read\b"],
            "cpp": [r"cin\b", r"getline\b", r"ifstream\b", r"recv\b", r"read\b"],
            "rust": [r"std::io::Read", r"std::net", r"std::env::args", r"std::fs::read"],
            "go": [r"io\.Read", r"net\.Conn", r"os\.Args", r"os\.Getenv"],
        }
        patterns = input_patterns.get(language, input_patterns["c"])
        sources = []
        for p in patterns:
            if re.search(p, content):
                sources.append(p.replace(r"\b", "").replace(r".", "_"))
        return sources

    def _find_sinks(self, content: str, language: str) -> list:
        """Find dangerous sinks (memory ops, exec, crypto)."""
        sink_patterns = {
            "c": [r"memcpy\b", r"strcpy\b", r"strcat\b", r"sprintf\b", r"malloc\b",
                   r"free\b", r"realloc\b", r"system\b", r"exec[lv]", r"popen\b",
                   r"write\b", r"send\b", r"mmap\b", r"mprotect\b"],
            "cpp": [r"new\b", r"delete\b", r"std::copy", r"std::memcpy", r"system\b"],
            "rust": [r"unsafe\b", r"std::ptr::copy", r"std::alloc", r"transmute\b"],
            "go": [r"copy\b", r"unsafe\b", r"syscall\b", r"os\.StartProcess"],
        }
        patterns = sink_patterns.get(language, sink_patterns["c"])
        sinks = []
        for p in patterns:
            if re.search(p, content):
                sinks.append(p.replace(r"\b", "").replace(r".", "_"))
        return sinks

    def _find_trust_boundaries(self, content: str, language: str, path: str) -> list:
        """Identify trust boundary crossings."""
        boundaries = []
        boundary_signals = {
            "kernel": [r"copy_from_user\b", r"copy_to_user\b", r"put_user\b",
                        r"get_user\b", r"ioctl\b", r"setuid\b", r"capable\b"],
            "network": [r"recv\b", r"recvfrom\b", r"accept\b", r"SSL_read\b",
                         r"parse_request\b", r"handle_connection\b"],
            "file": [r"fopen\b", r"open\b", r"mmap\b", r"read\b", r"fread\b"],
            "privilege": [r"setuid\b", r"setgid\b", r"chroot\b", r"prctl\b",
                           r"seteuid\b", r"capset\b"],
            "sandbox": [r"seccomp\b", r"chroot\b", r"pivot_root\b", r"namespace\b",
                         r"cgroup\b", r"unshare\b"],
        }

        for btype, patterns in boundary_signals.items():
            for p in patterns:
                if re.search(p, content):
                    boundaries.append((path, btype, "inbound"))
                    break  # One boundary per type per file

        return boundaries

    def _compute_complexity(self, content: str) -> int:
        """Compute cyclomatic complexity estimate."""
        branches = len(re.findall(r'\bif\b', content))
        branches += len(re.findall(r'\bfor\b', content))
        branches += len(re.findall(r'\bwhile\b', content))
        branches += len(re.findall(r'\bcase\b', content))
        branches += len(re.findall(r'\b&&\b', content))
        branches += len(re.findall(r'\|\|\b', content))
        return branches + 1

    def _count_memory_ops(self, content: str, language: str) -> int:
        """Count memory operations."""
        if language in ("c", "cpp"):
            patterns = [r"malloc\b", r"calloc\b", r"realloc\b", r"free\b",
                        r"memcpy\b", r"memmove\b", r"memset\b", r"strcpy\b",
                        r"strncpy\b", r"strcat\b", r"strncat\b", r"sprintf\b",
                        r"snprintf\b", r"new\b", r"delete\b"]
        elif language == "rust":
            patterns = [r"unsafe\b", r"std::ptr::", r"std::alloc", r"transmute\b",
                        r"copy_nonoverlapping\b", r"copy\b"]
        else:
            patterns = [r"malloc\b", r"free\b", r"memcpy\b", r"copy\b"]

        count = 0
        for p in patterns:
            count += len(re.findall(p, content))
        return count
