"""
Utility Functions
"""
import os
import json
import random
import numpy as np
from datetime import datetime


def set_seed(seed: int = 42):
    """Set random seed"""
    random.seed(seed)
    np.random.seed(seed)
    try:
        import torch
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except ImportError:
        pass


def ensure_dir(path: str):
    """Ensure directory exists"""
    os.makedirs(path, exist_ok=True)


def get_timestamp():
    """Get timestamp string"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def load_json(filepath: str) -> dict:
    """Load JSON file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json(data: dict, filepath: str):
    """Save JSON file"""
    ensure_dir(os.path.dirname(filepath))
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def format_percentage(value: float) -> str:
    """Format percentage"""
    return f"{value * 100:.1f}%"


def calculate_metrics(results: list) -> dict:
    """
    Calculate statistics from results list
    
    Args:
        results: List of results containing 'success' field
        
    Returns:
        Statistics dictionary
    """
    total = len(results)
    if total == 0:
        return {"total": 0, "success": 0, "rate": 0.0}
    
    success = sum(1 for r in results if r.get("success", False))
    
    return {
        "total": total,
        "success": success,
        "rate": success / total
    }


def print_attack_result(result: dict, verbose: bool = False):
    """Print single attack result"""
    status = "✓ SUCCESS" if result.get("success") else "✗ FAILED"
    blocked = " [BLOCKED]" if result.get("was_blocked") else ""
    
    print(f"[{result.get('attack_id', 'N/A')}] {status}{blocked}")
    
    if verbose:
        print(f"  Prompt: {result.get('prompt', '')[:50]}...")
        print(f"  Response: {result.get('response', '')[:100]}...")
        if result.get("indicators"):
            print(f"  Indicators: {result.get('indicators')}")
        print()


def create_robustness_curve_data(results_by_threshold: dict) -> dict:
    """
    Prepare data for robustness curve
    
    Args:
        results_by_threshold: {threshold: metrics_dict} dictionary
        
    Returns:
        Data for plotting
    """
    thresholds = sorted(results_by_threshold.keys())
    asr_values = [results_by_threshold[t]["attack_success_rate"] for t in thresholds]
    utility_values = [results_by_threshold[t]["utility_rate"] for t in thresholds]
    fpr_values = [results_by_threshold[t]["false_positive_rate"] for t in thresholds]
    
    return {
        "thresholds": thresholds,
        "asr": asr_values,
        "utility": utility_values,
        "fpr": fpr_values
    }
