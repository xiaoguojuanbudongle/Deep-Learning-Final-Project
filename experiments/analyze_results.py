"""
Analyze Results and Generate Visualizations
"""
import os
import sys
import json
import argparse
from glob import glob

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.ticker import PercentFormatter

# 设置绘图风格
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 12


def load_latest_results(results_dir: str) -> dict:
    """加载最新的评估结果"""
    pattern = os.path.join(results_dir, "evaluation_*.json")
    files = sorted(glob(pattern))
    
    if not files:
        raise FileNotFoundError(f"No result files found in {results_dir}")
    
    latest_file = files[-1]
    print(f"Loading results from: {latest_file}")
    
    with open(latest_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def plot_asr_comparison(results: dict, save_path: str = None):
    """绘制攻击成功率对比图"""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    defenses = ["Baseline"]
    asr_gh = [results["baseline"]["attacks"]["metrics"]["asr_by_type"].get("goal_hijacking", 0)]
    asr_pl = [results["baseline"]["attacks"]["metrics"]["asr_by_type"].get("prompt_leaking", 0)]
    
    for defense_name, defense_results in results["defenses"].items():
        defenses.append(defense_name)
        asr_gh.append(defense_results["attacks"]["metrics"]["asr_by_type"].get("goal_hijacking", 0))
        asr_pl.append(defense_results["attacks"]["metrics"]["asr_by_type"].get("prompt_leaking", 0))
    
    x = np.arange(len(defenses))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, asr_gh, width, label='Goal Hijacking', color='#e74c3c', alpha=0.8)
    bars2 = ax.bar(x + width/2, asr_pl, width, label='Prompt Leaking', color='#3498db', alpha=0.8)
    
    ax.set_xlabel('Defense Method', fontsize=14)
    ax.set_ylabel('Attack Success Rate (ASR)', fontsize=14)
    ax.set_title('Attack Success Rate by Defense Method', fontsize=16, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(defenses, rotation=15, ha='right')
    ax.legend(loc='upper right')
    ax.yaxis.set_major_formatter(PercentFormatter(1))
    ax.set_ylim(0, 1)
    
    for bar in bars1:
        height = bar.get_height()
        ax.annotate(f'{height:.1%}', xy=(bar.get_x() + bar.get_width() / 2, height),
                   xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=9)
    
    for bar in bars2:
        height = bar.get_height()
        ax.annotate(f'{height:.1%}', xy=(bar.get_x() + bar.get_width() / 2, height),
                   xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"Saved: {save_path}")
    plt.close()


def plot_utility_vs_security(results: dict, save_path: str = None):
    """绘制安全性 vs 可用性权衡图"""
    fig, ax = plt.subplots(figsize=(10, 8))
    
    points = []
    labels = []
    
    baseline_asr = results["baseline"]["attacks"]["metrics"]["attack_success_rate"]
    baseline_utility = results["baseline"]["utility"]["metrics"]["utility_rate"]
    points.append((baseline_asr, baseline_utility))
    labels.append("Baseline")
    
    for defense_name, defense_results in results["defenses"].items():
        asr = defense_results["attacks"]["metrics"]["attack_success_rate"]
        utility = defense_results["utility"]["metrics"]["utility_rate"]
        points.append((asr, utility))
        labels.append(defense_name)
    
    colors = plt.cm.viridis(np.linspace(0, 1, len(points)))
    
    for i, ((asr, utility), label) in enumerate(zip(points, labels)):
        ax.scatter(asr, utility, s=200, c=[colors[i]], label=label, 
                  edgecolors='black', linewidth=1.5, zorder=5)
        ax.annotate(label, (asr, utility), xytext=(10, 10),
                   textcoords='offset points', fontsize=10,
                   bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.7))
    
    ax.scatter(0, 1, s=300, c='gold', marker='*', edgecolors='black',
              linewidth=1.5, zorder=10, label='Ideal (ASR=0, Utility=1)')
    
    ax.set_xlabel('Attack Success Rate (lower is better)', fontsize=14)
    ax.set_ylabel('Utility Preservation (higher is better)', fontsize=14)
    ax.set_title('Security-Utility Trade-off', fontsize=16, fontweight='bold')
    
    ax.xaxis.set_major_formatter(PercentFormatter(1))
    ax.yaxis.set_major_formatter(PercentFormatter(1))
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)
    
    ax.axhspan(0.8, 1.0, alpha=0.1, color='green')
    ax.axvspan(0, 0.2, alpha=0.1, color='blue')
    
    ax.legend(loc='lower left', fontsize=9)
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"Saved: {save_path}")
    plt.close()


def plot_category_heatmap(results: dict, save_path: str = None):
    """绘制攻击类别热力图"""
    defenses = ["Baseline"] + list(results["defenses"].keys())
    categories = list(results["baseline"]["attacks"]["metrics"]["asr_by_category"].keys())
    
    data = []
    for defense in defenses:
        if defense == "Baseline":
            asr_by_cat = results["baseline"]["attacks"]["metrics"]["asr_by_category"]
        else:
            asr_by_cat = results["defenses"][defense]["attacks"]["metrics"]["asr_by_category"]
        row = [asr_by_cat.get(cat, 0) for cat in categories]
        data.append(row)
    
    data = np.array(data)
    
    fig, ax = plt.subplots(figsize=(14, 8))
    sns.heatmap(data, annot=True, fmt='.0%', cmap='RdYlGn_r',
                xticklabels=categories, yticklabels=defenses,
                cbar_kws={'label': 'Attack Success Rate'},
                ax=ax, vmin=0, vmax=1)
    
    ax.set_xlabel('Attack Category', fontsize=12)
    ax.set_ylabel('Defense Method', fontsize=12)
    ax.set_title('Attack Success Rate by Category and Defense', fontsize=14, fontweight='bold')
    
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"Saved: {save_path}")
    plt.close()


def plot_robustness_curve(results: dict, save_path: str = None):
    """绘制鲁棒性曲线"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    
    defenses = ["Baseline"]
    overall_asr = [results["baseline"]["attacks"]["metrics"]["attack_success_rate"]]
    blocked_rate = [0]
    utility = [results["baseline"]["utility"]["metrics"]["utility_rate"]]
    fpr = [0]
    
    for defense_name, defense_results in results["defenses"].items():
        defenses.append(defense_name)
        overall_asr.append(defense_results["attacks"]["metrics"]["attack_success_rate"])
        blocked_rate.append(defense_results["attacks"]["metrics"]["blocked_rate"])
        utility.append(defense_results["utility"]["metrics"]["utility_rate"])
        fpr.append(defense_results["utility"]["metrics"]["false_positive_rate"])
    
    x = np.arange(len(defenses))
    width = 0.35
    
    ax1.bar(x - width/2, overall_asr, width, label='ASR', color='#e74c3c', alpha=0.8)
    ax1.bar(x + width/2, blocked_rate, width, label='Blocked Rate', color='#27ae60', alpha=0.8)
    ax1.set_xlabel('Defense Method')
    ax1.set_ylabel('Rate')
    ax1.set_title('Attack Success Rate vs Block Rate')
    ax1.set_xticks(x)
    ax1.set_xticklabels(defenses, rotation=15, ha='right')
    ax1.legend()
    ax1.yaxis.set_major_formatter(PercentFormatter(1))
    ax1.set_ylim(0, 1)
    
    ax2.bar(x - width/2, utility, width, label='Utility', color='#3498db', alpha=0.8)
    ax2.bar(x + width/2, fpr, width, label='False Positive Rate', color='#f39c12', alpha=0.8)
    ax2.set_xlabel('Defense Method')
    ax2.set_ylabel('Rate')
    ax2.set_title('Utility Preservation vs False Positive Rate')
    ax2.set_xticks(x)
    ax2.set_xticklabels(defenses, rotation=15, ha='right')
    ax2.legend()
    ax2.yaxis.set_major_formatter(PercentFormatter(1))
    ax2.set_ylim(0, 1)
    
    plt.tight_layout()
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"Saved: {save_path}")
    plt.close()


def generate_latex_table(results: dict) -> str:
    """生成LaTeX表格"""
    latex = r"""\begin{table}[h]
\centering
\caption{Evaluation Results: Attack Success Rate and Utility}
\label{tab:results}
\begin{tabular}{lcccc}
\toprule
\textbf{Defense} & \textbf{ASR (\%)} & \textbf{ASR Reduction} & \textbf{Utility (\%)} & \textbf{FPR (\%)} \\
\midrule
"""
    for row in results["comparison"]["summary_table"]:
        latex += f"{row['defense']} & {row['ASR']*100:.1f} & {row['ASR_reduction']*100:.1f} & {row['utility']*100:.1f} & {row['FPR']*100:.1f} \\\\\n"
    
    latex += r"""\bottomrule
\end{tabular}
\end{table}
"""
    return latex


def main():
    parser = argparse.ArgumentParser(description="Analyze evaluation results")
    parser.add_argument("--results-dir", type=str, default="results",
                        help="Directory containing result files")
    parser.add_argument("--output-dir", type=str, default="results/figures",
                        help="Directory for output figures")
    args = parser.parse_args()
    
    results_dir = os.path.join(PROJECT_ROOT, args.results_dir)
    output_dir = os.path.join(PROJECT_ROOT, args.output_dir)
    os.makedirs(output_dir, exist_ok=True)
    
    results = load_latest_results(results_dir)
    
    print("\nGenerating visualizations...")
    
    plot_asr_comparison(results, os.path.join(output_dir, "asr_comparison.png"))
    plot_utility_vs_security(results, os.path.join(output_dir, "utility_vs_security.png"))
    plot_category_heatmap(results, os.path.join(output_dir, "category_heatmap.png"))
    plot_robustness_curve(results, os.path.join(output_dir, "robustness_curve.png"))
    
    latex_table = generate_latex_table(results)
    latex_file = os.path.join(output_dir, "results_table.tex")
    with open(latex_file, 'w') as f:
        f.write(latex_table)
    print(f"Saved: {latex_file}")
    
    print("\nAnalysis complete!")
    print(f"Figures saved to: {output_dir}")


if __name__ == "__main__":
    main()
