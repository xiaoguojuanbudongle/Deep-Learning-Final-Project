# LLM Security Evaluation Framework

A comprehensive framework for evaluating the robustness of Large Language Models (LLMs) against prompt injection and leaking attacks, and testing the effectiveness of various defense strategies.

## Overview

This project provides a modular environment to simulate, execute, and evaluate adversarial attacks on LLM systems. It focuses on two primary threat vectors:
- **Goal Hijacking**: Manipulating the model to ignore its original instructions and execute malicious commands.
- **Prompt Leaking**: Coercing the model to reveal its system prompt or confidential configuration data.

To mitigate these threats, the framework implements and evaluates three distinct defense mechanisms:
- **Input Filtering**: A keyword and regex-based filter to block known malicious patterns.
- **Sandwich Defense**: Wraps user input between defensive prompts to reinforce system instructions.
- **Perplexity Detection**: Uses a secondary language model to detect anomalous, high-perplexity inputs often associated with attacks.

## Project Structure

```
├── src/                  # Core source code
│   ├── attacks.py        # Attack execution and success evaluation logic
│   ├── defenses.py       # Implementation of defense mechanisms (Filter, Sandwich, Perplexity)
│   ├── evaluator.py      # Main evaluation engine for calculating metrics (ASR, Utility, etc.)
│   ├── target_system.py  # Interface for Target LLMs (Real API or Mock)
│   └── utils.py          # Helper functions
├── experiments/          # Evaluation scripts
│   ├── run_evaluation.py # Main entry point for running benchmarks
│   └── analyze_results.py# Tools for analyzing output data
├── data/                 # Dataset containing attack prompts and benign queries
├── results/              # Output directory for evaluation logs and figures
└── config.py             # Configuration for API keys and experiment settings
```

## Features

- **Automated Attack Execution**: Automatically runs a battery of prompt injection and leaking attacks.
- **Defense Evaluation**: Compare the effectiveness of different defense layers individually or in combination.
- **Comprehensive Metrics**:
  - **Attack Success Rate (ASR)**: The percentage of successful attacks.
  - **Utility Preservation**: Measures if the defense negatively impacts performance on benign user queries.
  - **False Positive Rate**: The rate at which legitimate queries are incorrectly blocked.
- **Mock System**: Includes a simulated LLM environment for cost-free testing and development.

## Experimental Results

The following results were obtained from an evaluation run using a **Real LLM API** (not Mock), illustrating the system's performance in a production-like environment.

### Summary Table

| Defense Strategy | ASR (Lower is Better) | ASR Reduction | Utility (Higher is Better) | FPR (False Positive Rate) |
| :--- | :---: | :---: | :---: | :---: |
| **None (Baseline)** | 60.00% | - | 100.00% | 0.00% |
| **Input Filter** | 12.50% | 47.50% | 100.00% | 0.00% |
| **Sandwich Defense** | 57.50% | 2.50% | 100.00% | 0.00% |
| **Perplexity Detector** | **2.50%** | **57.50%** | 20.00% | 80.00% |
| **Combined Defense** | 17.50% | 42.50% | 100.00% | 0.00% |

### Key Findings

1.  **Best Balance (Winner)**: The **Input Filter** proved to be the most practical defense. It significantly reduced the Attack Success Rate (from 60% to 12.5%) while maintaining a perfect **100% Utility** score, meaning it did not accidentally block any legitimate user queries.
2.  **Aggressive Defense**: The **Perplexity Detector** offered the strongest security (lowest ASR of 2.5%), but at a severe cost to usability. With a **False Positive Rate of 80%**, it blocked the vast majority of benign requests, making it unsuitable for direct deployment without threshold tuning.
3.  **Ineffective Strategies**: In this specific test, the **Sandwich Defense** provided minimal protection (only reducing ASR by 2.5%), suggesting that sophisticated models can easily bypass simple prompt wrapping instructions.
4.  **Combined Defense**: The Combined Defense (configured to use Filter + Sandwich) achieved solid results (17.5% ASR, 100% Utility), performing similarly to the Input Filter alone.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/gavinn212/Deep-Learning-Final-Project.git
   cd Deep-Learning-Final-Project
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
## Configuration

This project supports two primary modes of operation: using a **Real LLM API** (recommended for accurate results) or a **Mock System** (for zero-cost testing).

### 1. Real LLM API Configuration

To evaluate against real models, you need to configure `config.py`.

1.  Open `config.py` in the root directory.
2.  Select your API provider by setting the `USE_API` variable to either `"openai"` or `"qwen"`.
3.  Fill in the corresponding API key and model details.

**Example for OpenAI:**
```python
# config.py
USE_API = "openai"
OPENAI_API_KEY = "sk-..."  # Replace with your actual key
OPENAI_MODEL = "gpt-3.5-turbo"
```

**Example for Qwen (Aliyun):**
```python
# config.py
USE_API = "qwen"
QWEN_API_KEY = "sk-..."    # Replace with your actual key
QWEN_API_BASE = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
QWEN_MODEL = "qwen-flash"
```

### 2. Mock System Configuration

The Mock System simulates an LLM using rule-based logic. It is useful for debugging the pipeline without incurring API costs.

- No `config.py` changes are strictly required, but you can adjust `vulnerability` via command-line arguments (see Usage below).
- The mock system has a built-in "vulnerability level" that determines how likely it is to fall for a specific attack pattern.

## Usage

### Method A: Running with Real API (Recommended)

Once you have configured `config.py` with your API keys:

```bash
python experiments/run_evaluation.py
```
*This will connect to the configured endpoint (OpenAI or Qwen), run all attacks, and generate results.*

### Method B: Running with Mock System

To run the evaluation using the simulated local system (bypassing `config.py` API settings):

```bash
python experiments/run_evaluation.py --use-mock
```

You can also adjust how "vulnerable" the mock system is (0.0 = secure, 1.0 = always accepts attacks):

```bash
# Simulate a highly vulnerable model (default is usually 0.5-0.7)
python experiments/run_evaluation.py --use-mock --vulnerability 0.9
```

### Other Options

- **Specify Output Directory**:
  ```bash
  python experiments/run_evaluation.py --output-dir my_custom_results
  ```
- **Set Random Seed**:
  ```bash
  python experiments/run_evaluation.py --seed 123
  ```

## License

This project is licensed under the MIT License.

