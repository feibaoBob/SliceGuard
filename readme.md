# SliceGuard

**Taming Long Code for LLMs via Cryptography-Aware Program Slicing for Precise Cryptographic API Misuse Detection**

> 📄 This repository contains the implementation and evaluation data for our paper submitted to NDSS 2026.

------

## Overview

SliceGuard is a multi-granularity analysis framework that combines **static code filtering**, **cryptography-aware program slicing**, and **slice-informed LLM detection** to precisely detect cryptographic API misuses in Python code.

**Key insight:** Cryptographic API misuses are inherently localized. By extracting only the cryptography API-relevant code context through domain-specific program slicing—with original line numbers preserved—we transform the intractable long-code detection problem into a tractable short-snippet analysis task where LLMs excel.

### Three-Phase Pipeline

| Phase       | Component                          | Scope Reduction                  | Output                                           |
| ----------- | ---------------------------------- | -------------------------------- | ------------------------------------------------ |
| **Phase 1** | Static Code Filtering              | Project → Candidate files        | Files importing/using crypto APIs                |
| **Phase 2** | Cryptography-Aware Program Slicing | File → Line-level code fragments | Sliced code with original line numbers preserved |
| **Phase 3** | Slice-Informed LLM Detection       | Sliced snippets → Misuse reports | Precise misuse locations with line numbers       |

------

## Key Features

- **Line-Number-Preserving Slicing:** The slicing algorithm outputs code fragments annotated with their original file line numbers. When the LLM reports a misuse line number, it directly maps to the source code—no post-processing needed.
- **Bidirectional Slicing:** Forward + backward slicing captures complete data/control dependencies around crypto API usage points.
- **Comprehensive Crypto API Knowledge Base:** Covers 30+ Python crypto libraries including `hashlib`, `ssl`, `cryptography`, `PyCryptodome`, `paramiko`, `jwt`, `requests`, etc.
- **Multi-pattern Import Resolution:** Handles `import X`, `from X import Y`, aliases, wildcard imports, dynamic imports (`__import__`, `importlib`), and inter-procedural data flows.
- **CoT-Enhanced LLM Detection:** Chain-of-thought prompting with structured rule descriptions for accurate, explainable detection.

------

## Repository Structure

```
SliceGuard/
├── SliceGuard_Implement.py       # Main entry: 3-phase pipeline execution
├── Filter_Algorithm.py           # Phase 1: Static crypto API filtering
├── Slice_Algorithm.py            # Phase 2: Cryptography-aware program slicing
├── LLM_Detection_Algorithm.py   # Phase 3: Slice-informed LLM detection
├── LLM_Detection_Algorithm_FL.py # LLM-Filter baseline (Filter + LLM, no slicing)
├── Filter_LLM_Implement.py      # LLM-Filter baseline implementation
├── LLM_Cost_Statistics.py       # Token/cost statistics calculator
├── calculate_lhr.py              # Line Hit Rate (LHR) evaluation metric
├── count_lines.py                # Code line counter utility
├── rule_source_py.py             # 18 crypto misuse rule definitions
├── build_pycryptobench_llm.py    # Build PyCryptoBench-LLM from PyCryptoBench
├── requirements.txt              # Python dependencies
│
├── PyCryptoBench/                # Original PyCryptoBench benchmark
│   ├── misuse_cases/             # True misuse cases (19 rules × variants)
│   ├── safe_cases/               # Safe/trap usage cases
│   └── trap_cases/               # Trap cases (imported but not insecurely used)
│
└── SATs_Implement/               # Static analysis tool wrappers (Cryptolation/Bandit/Dlint)
    └── src/
        ├── SATs_Implement.py     # SATs runner
        ├── bandit_json2csv.py    # Bandit output converter
        ├── dlint_json2csv.py     # Dlint output converter
        ├── cryptolation.py       # Cryptolation Tool
        └── ...
```

------

## Quick Start

### 1. Installation

```bash
pip install -r requirements.txt
```

### 2. Prepare Your Project

Place the Python project you want to analyze in a directory (e.g., `./real-world-project`).

### 3. Run SliceGuard

```python
# Edit SliceGuard_Implement.py to set your paths and API credentials
python SliceGuard_Implement.py
```

Key parameters to configure:

- `source_directory`: Path to the target Python project
- `filtered_directory`: Output path for Phase 1 filtered files
- `sliced_directory`: Output path for Phase 2 sliced files
- `model_name`: LLM model (e.g., `Pro/zai-org/GLM-5.1`)
- `API_Key`: Your LLM API key
- `API_Url`: LLM API endpoint
- `cot`: Enable/disable Chain-of-Thought prompting (`True`/`False`)

### 4. Run LLM-Filter Baseline

```python
# Edit Filter_LLM_Implement.py similarly
python Filter_LLM_Implement.py
```

### 5. Run SATs Baseline

```python
# Edit SATs_Implement.py to set your paths
python SATs_Implement.py
```
Key parameters to configure:

- `target_folder`: Path to the target Python project
  
------

## PyCryptoBench-LLM Benchmark

We refine the existing PyCryptoBench into **PyCryptoBench-LLM**, a five-category benchmark better suited for evaluating LLM-based detectors:

| Category         | Description                                            |
| ---------------- | ------------------------------------------------------ |
| **misuse_cases** | Imported AND insecurely used (true misuses only)       |
| **trap_type1**   | Imported only, not used at all                         |
| **trap_type2**   | Imported AND used, but NOT in a security-sensitive way |
| **safe_type1**   | Imported AND safely used                               |
| **safe_type2**   | No crypto API import or usage                          |

### Key Refinements over PyCryptoBench

- **FP reclassification:** rule_05 (random for non-crypto), rule_16 (yaml.dump vs yaml.load), rule_18 (static regex vs dynamic input) reclassified from misuse to trap/safe
- **Import variant generation:** alias, wildcard, dynamic import variants for all misuse rules
- **New misuse cases:** rule_16 and rule_18 true misuses added back

### Build the Benchmark

```bash
python build_pycryptobench_llm.py
```

------

## Detection Rules

SliceGuard detects 18 categories of cryptographic API misuse (defined in `rule_source_py.py`):

| Rule | Category                                             |
| ---- | ---------------------------------------------------- |
| R01  | Insecure SSL/TLS protocol versions                   |
| R02  | Unvalidated SSL certificates                         |
| R03  | Disabled certificate verification                    |
| R04  | Insecure HTTP connections (cleartext)                |
| R05  | Use of non-cryptographic random in security contexts |
| R06  | Insufficient PBKDF2 iterations                       |
| R07  | Hardcoded/short encryption keys                      |
| R08  | Use of broken hash algorithms (MD5/SHA1)             |
| R09  | Insecure cipher modes (ECB) / fixed IVs              |
| R10  | Insufficient RSA key length                          |
| R11  | Broken hash algorithms in signatures/HMAC            |
| R12  | JWT algorithm confusion / none algorithm             |
| R13  | Insecure SSL/TLS configuration                       |
| R14  | Insecure network protocols (FTP/Telnet/LDAP)         |
| R15  | XML external entity (XXE) injection                  |
| R16  | Insecure YAML deserialization                        |
| R17  | Insecure pickle deserialization                      |
| R18  | ReDoS (Regular Expression DoS)                       |


------

## License

This project is for research purposes. Please refer to the license file for details.
