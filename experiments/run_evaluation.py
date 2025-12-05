"""
Main Evaluation Script - Run comprehensive security evaluation
"""
import os
import sys
import argparse

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.target_system import get_llm_system, MockLLMSystem
from src.attacks import AttackExecutor
from src.defenses import InputFilter, SandwichDefense, PerplexityDetector, CombinedDefense, create_defense
from src.evaluator import SecurityEvaluator
from src.utils import set_seed, ensure_dir, get_timestamp, save_json


def parse_args():
    parser = argparse.ArgumentParser(description="LLM Security Evaluation")
    
    parser.add_argument("--use-mock", action="store_true", default=True,
                        help="Use mock LLM system (no API needed)")
    parser.add_argument("--vulnerability", type=float, default=0.7,
                        help="Mock system vulnerability level (0-1)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed")
    parser.add_argument("--output-dir", type=str, default="results",
                        help="Output directory for results")
    parser.add_argument("--verbose", action="store_true", default=True,
                        help="Verbose output")
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    # 设置随机种子
    set_seed(args.seed)
    
    # 确保输出目录存在
    output_dir = os.path.join(PROJECT_ROOT, args.output_dir)
    ensure_dir(output_dir)
    
    print("="*70)
    print("LLM SECURITY EVALUATION - Prompt Injection/Leaking Benchmark")
    print("="*70)
    
    # 1. 初始化目标系统
    print("\n[1] Initializing target system...")
    if args.use_mock:
        print(f"    Using Mock LLM System (vulnerability={args.vulnerability})")
        target_system = MockLLMSystem(vulnerability_level=args.vulnerability)
    else:
        print("    Using real LLM API")
        target_system = get_llm_system(use_mock=False)
    
    # 2. 初始化攻击执行器
    print("\n[2] Loading attack prompts...")
    attack_executor = AttackExecutor()
    
    gh_count = len(attack_executor.get_attack_prompts("goal_hijacking"))
    pl_count = len(attack_executor.get_attack_prompts("prompt_leaking"))
    bq_count = len(attack_executor.get_attack_prompts("benign_queries"))
    
    print(f"    Goal Hijacking attacks: {gh_count}")
    print(f"    Prompt Leaking attacks: {pl_count}")
    print(f"    Benign queries: {bq_count}")
    
    # 3. 初始化防御方法
    print("\n[3] Setting up defenses...")
    
    defenses = [
        ("Input Filter", InputFilter()),
        ("Sandwich Defense", SandwichDefense()),
        ("Perplexity Detector", PerplexityDetector(threshold=30.0)),
        ("Combined Defense", CombinedDefense([
            ("filter", InputFilter()),
            ("sandwich", SandwichDefense()),
        ])),
    ]
    
    for name, _ in defenses:
        print(f"    - {name}")
    
    # 4. 运行评估
    print("\n[4] Running evaluation...")
    evaluator = SecurityEvaluator(target_system, attack_executor)
    
    full_results = evaluator.full_evaluation(defenses, verbose=args.verbose)
    
    # 5. 打印摘要
    evaluator.print_summary(full_results)
    
    # 6. 保存结果
    timestamp = get_timestamp()
    results_file = os.path.join(output_dir, f"evaluation_{timestamp}.json")
    save_json(full_results, results_file)
    print(f"\nResults saved to: {results_file}")
    
    # 7. 保存简化的摘要
    summary = {
        "timestamp": timestamp,
        "config": {
            "use_mock": args.use_mock,
            "vulnerability": args.vulnerability if args.use_mock else None,
            "seed": args.seed
        },
        "comparison": full_results["comparison"]
    }
    summary_file = os.path.join(output_dir, f"summary_{timestamp}.json")
    save_json(summary, summary_file)
    
    print("\nEvaluation complete!")
    
    return full_results


if __name__ == "__main__":
    results = main()
