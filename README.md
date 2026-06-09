# VULSCAN-X

**GLM-5.1 Autonomous Zero-Day Discovery & Exploitation System**

A closed-loop, self-improving vulnerability research framework that autonomously discovers, validates, and exploits zero-day vulnerabilities in complex software systems.

---

## 🎯 Overview

VULSCAN-X is an advanced cybersecurity research tool that leverages Large Language Models (LLMs) and automated fuzzing to discover vulnerabilities in production software. The system employs a failure-driven learning loop where each unsuccessful attempt is analyzed, lessons are extracted, and strategies are adapted for subsequent exploration.

### Key Features

- **Autonomous Discovery**: Parallel agents analyze codebases using graph-based ranking
- **Zero-Day Focus**: Specialized invariant-breaking for novel vulnerability patterns
- **Closed-Loop Learning**: Beam search-driven strategy adaptation from failures
- **Exploit Construction**: Automatic primitive extraction and chain building
- **Sandboxed Execution**: Docker-based isolation with sanitizers
- **Responsible Disclosure**: SHA-3 commitment schemes for timestamped findings

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           VULSCAN-X Architecture                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                 │
│  │   Target     │    │   Graph      │    │   Beam       │                 │
│  │  Repository  │───▶│   Ranker     │───▶│   Search     │                 │
│  └──────────────┘    └──────────────┘    └──────────────┘                 │
│         │                   │                   │                          │
│         ▼                   ▼                   ▼                          │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                        Parallel Agents                               │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │ │
│  │  │ Vuln Finder  │  │Invariant     │  │  PoC Writer  │               │ │
│  │  │              │  │  Breaker     │  │              │               │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                   │                                        │
│                                   ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                    Learning & Adaptation                             │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │ │
│  │  │ Pattern      │  │ Strategy     │  │ Failure      │               │ │
│  │  │ Index        │  │ Manager      │  │ Analysis     │               │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                   │                                        │
│                                   ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                   Exploit Construction                                │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │ │
│  │  │ Primitive    │  │ Chain        │  │ Constraint   │               │ │
│  │  │ Extractor    │  │ Builder      │  │ Solver       │               │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                   │                                        │
│                                   ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                      Validation & Triage                             │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │ │
│  │  │ Sandbox      │  │ Severity     │  │ Dedup & FP   │               │ │
│  │  │ Validator    │  │ Classifier   │  │ Filter       │               │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                   │                                        │
│                                   ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                      Fuzzing Feedback Loop                           │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │ │
│  │  │ AFL++/       │  │ LLM Seed     │  │ Coverage     │               │ │
│  │  │ LibFuzzer    │  │ Generator    │  │ Analysis     │               │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                   │                                        │
│                                   ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                      Disclosure & Reporting                          │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │ │
│  │  │ SHA-3        │  │ CVSS         │  │ Novelty      │               │ │
│  │  │ Commitment   │  │ Scoring      │  │ Detection    │               │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Workflow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        VULSCAN-X Execution Pipeline                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  START                                                                       │
│   │                                                                          │
│   ▼                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Phase 1: Intelligent Codebase Mapping                               │   │
│  │ • Clone target repository                                           │   │
│  │ • Build with sanitizers (ASan, UBSan)                               │   │
│  │ • Build dependency graph                                             │   │
│  │ • Rank files by vulnerability likelihood                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│   │                                                                          │
│   ▼                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Phase 2: Parallel Vulnerability Exploration                           │   │
│  │ • Deploy multiple agents on top-ranked files                         │   │
│  │ • Classical vulnerability detection                                  │   │
│  │ • Invariant breaking (zero-day mode)                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│   │                                                                          │
│   ▼                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Phase 3: Failure-Driven Learning Loop                                 │   │
│  │ • Beam search over PoC strategies                                     │   │
│  │ • Generate proof-of-concept attempts                                  │   │
│  │ • Validate in sandbox                                                │   │
│  │ • Record failures → Extract lessons → Retry                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│   │                                                                          │
│   ▼                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Phase 4: Primitive Extraction                                        │   │
│  │ • Extract reusable exploit primitives                                 │   │
│  │ • Store in primitive database                                         │   │
│  │ • Categorize by type (memory corruption, logic, etc.)                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│   │                                                                          │
│   ▼                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Phase 5: Exploit Chain Construction                                   │   │
│  │ • Combine primitives into exploit chains                              │   │
│  │ • Solve constraints with constraint solver                           │   │
│  │ • Track exploit state across attempts                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│   │                                                                          │
│   ▼                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Phase 6: Fuzzing Feedback Loop                                       │   │
│  │ • Run AFL++/LibFuzzer on target functions                            │   │
│  │ • Generate seeds using LLM                                            │   │
│  │ • Analyze coverage and crashes                                        │   │
│  │ • Feed new findings back to learning system                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│   │                                                                          │
│   ▼                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Phase 7: Triage & Reporting                                          │   │
│  │ • Classify severity (CVSS)                                           │   │
│  │ • Deduplicate against NVD database                                   │   │
│  │ • Filter false positives                                             │   │
│  │ • Detect novelty (zero-day potential)                                │   │
│  │ • Generate SHA-3 commitments                                         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│   │                                                                          │
│   ▼                                                                          │
│  END → Report saved to output/                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

### Prerequisites

- Python 3.9+
- Docker (for sandboxed execution)
- Git
- Clang/LLVM (for building with sanitizers)

### Setup

```bash
# Clone the repository
git clone https://github.com/hamzazakakhan/lucaraz.git
cd lucaraz

# Install Python dependencies
pip install -r requirements.txt

# Ensure Docker is running
docker --version

# Configure your LLM endpoint (edit config.yaml)
# Set model.api_base to your GLM-5.1 endpoint
```

### Configuration

Edit `config.yaml` to customize:

```yaml
model:
  api_base: "http://localhost:8000/v1"  # Your LLM endpoint
  model_name: "GLM-5.1"
  max_tokens: 8192
  temperature: 0.3

agent:
  max_iterations: 8
  parallel_agents: 8
  files_per_run: 50

mode: "zero-day"  # or "standard"

sandbox:
  runtime: "docker"
  memory_limit: "4g"
  cpu_limit: 4
```

---

## 🚀 Usage

### Basic Usage

```bash
# Analyze a single target
python scaffold.py --target https://github.com/FFmpeg/FFmpeg --name FFmpeg --language c

# Run in zero-day mode
python scaffold.py --target https://github.com/FFmpeg/FFmpeg --name FFmpeg --language c --mode zero-day

# Use custom config
python scaffold.py --target https://github.com/FFmpeg/FFmpeg --config config_cbmpc.yaml
```

### Batch Processing

Edit `config.yaml` to add targets, then run:

```bash
# Process all configured targets
python scaffold.py
```

### Example Targets

The system comes pre-configured with high-value targets:

- **FFmpeg** - Multimedia framework
- **OpenSSH** - Secure shell protocol
- **SQLite** - Embedded database
- **Linux Kernel** - Operating system kernel
- **Chromium** - Web browser engine
- **OpenSSL** - Cryptography library
- **Firecracker** - MicroVM

---

## 🧩 Components

### Agents (`agents/`)

| Component | Description |
|-----------|-------------|
| `vuln_finder.py` | Classical vulnerability detection using pattern matching |
| `invariant_breaker.py` | Zero-day focused invariant violation detection |
| `poc_writer.py` | Proof-of-concept code generation |
| `validator.py` | Sandbox-based PoC validation |
| `primitive_extractor.py` | Extract reusable exploit primitives |
| `chain_builder.py` | Construct exploit chains from primitives |

### Exploration (`exploration/`)

| Component | Description |
|-----------|-------------|
| `beam_search.py` | Beam search algorithm for strategy exploration |
| `strategy_manager.py` | Manage and adapt exploitation strategies |

### Learning (`learning/`)

| Component | Description |
|-----------|-------------|
| `pattern_index.py` | Index success/failure patterns for learning |
| `failure_db.json` | Database of failed attempts and lessons |
| `success_db.json` | Database of successful strategies |

### Fuzzing (`fuzzing/`)

| Component | Description |
|-----------|-------------|
| `feedback_loop.py` | Integrate fuzzing with learning system |
| `llm_seed_generator.py` | Generate fuzzing seeds using LLM |

### Exploit (`exploit/`)

| Component | Description |
|-----------|-------------|
| `primitive_db.py` | Database of exploit primitives |
| `constraint_solver.py` | Solve constraints for exploit chains |

### Sandbox (`sandbox/`)

| Component | Description |
|-----------|-------------|
| `container.py` | Docker container management |
| `builder.py` | Target build system integration |
| `state_tracker.py` | Track exploit state across attempts |

### Triage (`triage/`)

| Component | Description |
|-----------|-------------|
| `severity.py` | CVSS severity classification |
| `dedup.py` | Deduplication against NVD database |
| `filter.py` | False positive filtering |

### Disclosure (`disclosure/`)

| Component | Description |
|-----------|-------------|
| `commit.py` | SHA-3 commitment scheme for timestamping |

---

## 🔬 Learning System

The learning system uses a failure-driven approach:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Learning Loop Architecture                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Attempt PoC ──▶ Validate ──▶ Success?                                      │
│       │              │          │                                           │
│       │              │          ├─ Yes → Record Success Pattern            │
│       │              │          │        - Strategy used                   │
│       │              │          │        - Bug type                        │
│       │              │          │        - Iterations                      │
│       │              │          │        - Primitive extracted             │
│       │              │          │                                           │
│       │              │          └─ No → Analyze Failure                     │
│       │              │                 - Extract failure reason             │
│       │              │                 - Generate lesson                   │
│       │              │                 - Update strategy weights           │
│       │              │                 - Record in failure DB              │
│       │              │                                                     │
│       │              └─▶ Update Pattern Index                              │
│       │                     - Decay old lessons (rate: 0.95)               │
│       │                     - Reinforce successful patterns                │
│       │                     - Apply lessons after threshold (5)             │
│       │                                                                   │
│       └─▶ Generate New Strategy (Beam Search)                              │
│              - Select from pattern index                                    │
│              - Adapt based on lessons                                       │
│              - Retry with variant                                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Output Format

Findings are saved as JSON in the `output/` directory:

```json
{
  "target": "FFmpeg",
  "file": "libavcodec/h264dec.c",
  "line": 1234,
  "bug_type": "buffer_overflow",
  "severity": "high",
  "cvss": 7.5,
  "poc": "/* Proof of concept code */",
  "validation": {
    "success": true,
    "sanitizer": "address",
    "crashed": true
  },
  "primitive": {
    "type": "overflow",
    "description": "Integer overflow leading to buffer overflow"
  },
  "novelty_score": 0.85,
  "novelty_reason": "Pattern not found in NVD database",
  "commitment": "sha3_256_hash_here"
}
```

---

## 🛡️ Safety & Ethics

VULSCAN-X is designed for **responsible vulnerability research**:

- **Sandboxed Execution**: All code runs in isolated Docker containers
- **Responsible Disclosure**: SHA-3 commitments provide timestamped proof
- **90-Day Timeline**: Configured disclosure timeline for vendors
- **Human Review**: Findings require manual verification before disclosure

### Usage Guidelines

1. Only test on software you have permission to analyze
2. Follow responsible disclosure practices
3. Do not use for malicious purposes
4. Report findings to vendors through proper channels

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Additional fuzzing engine integrations
- More vulnerability detection patterns
- Enhanced learning algorithms
- Additional language support (Go, Java, etc.)
- Improved visualization tools

### Development Setup

```bash
# Run tests (if available)
python -m pytest tests/

# Format code
black .
flake8 .
```

---

## 📝 License

This project is for research and educational purposes. Use responsibly and in accordance with applicable laws and regulations.

---

## 🙏 Acknowledgments

- GLM-5.1 language model for code analysis
- AFL++, LibFuzzer, and Honggfuzz communities
- NVD database for vulnerability deduplication
- Docker for sandboxing infrastructure

---

## 📧 Contact

For questions or responsible disclosure coordination:
- GitHub: https://github.com/hamzazakakhan/lucaraz
- Issues: https://github.com/hamzazakakhan/lucaraz/issues

---

**⚠️ Disclaimer**: This tool is for authorized security research only. Users are responsible for ensuring compliance with all applicable laws and regulations.
