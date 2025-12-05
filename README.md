# LLM Security: Prompt Injection/Leaking Evaluation and Defense

## Project Structure
```
llm_security_project/
├── README.md
├── requirements.txt
├── config.py                 # API配置
├── data/
│   └── attack_prompts.json   # 攻击prompt数据集
├── src/
│   ├── __init__.py
│   ├── target_system.py      # 目标LLM系统
│   ├── attacks.py            # 攻击实现
│   ├── defenses.py           # 防御实现
│   ├── evaluator.py          # 评测器
│   └── utils.py              # 工具函数
├── experiments/
│   ├── run_evaluation.py     # 主评测脚本
│   └── analyze_results.py    # 结果分析和可视化
└── results/                  # 实验结果输出
```

## Setup
```bash
pip install -r requirements.txt
```

## Configuration
Edit `config.py` to set your API key and model settings.

## Run Experiments
```bash
python experiments/run_evaluation.py
python experiments/analyze_results.py
```

## Attack Types
1. Goal Hijacking - 劫持模型执行非预期任务
2. Prompt Leaking - 泄露系统prompt

## Defense Methods
1. Input Filtering - 输入过滤（关键词+模式匹配）
2. Sandwich Defense - 分层提示（三明治防御）
3. Perplexity Detection - 困惑度检测

## Metrics
- Attack Success Rate (ASR)
- Utility Drop (正常任务准确率下降)
- Robustness Curve
