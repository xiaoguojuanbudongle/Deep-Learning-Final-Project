"""
Security Evaluator - Comprehensive evaluation of attacks and defenses
"""
import json
import os
from typing import List, Dict, Any, Callable, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import numpy as np
from tqdm import tqdm


@dataclass
class EvaluationMetrics:
    """Evaluation metrics"""
    attack_success_rate: float  # Attack Success Rate (ASR)
    blocked_rate: float  # Proportion blocked by defense
    utility_preservation: float  # Normal task preservation rate
    false_positive_rate: float  # False positive rate (benign queries blocked)
    
    # Statistics by category
    asr_by_category: Dict[str, float] = None
    asr_by_type: Dict[str, float] = None


class SecurityEvaluator:
    """
    Security Evaluator - Evaluate attack effectiveness and defense performance
    """
    
    def __init__(self, target_system, attack_executor):
        """
        Args:
            target_system: Target LLM system
            attack_executor: Attack executor
        """
        self.target_system = target_system
        self.attack_executor = attack_executor
        self.results_history = []
    
    def evaluate_without_defense(self, 
                                  attack_types: List[str] = None,
                                  verbose: bool = True) -> Dict:
        """
        Evaluate attack success rate without defense (baseline)
        
        Args:
            attack_types: Attack types to evaluate
            verbose: Whether to show progress
            
        Returns:
            Evaluation results dictionary
        """
        if attack_types is None:
            attack_types = ["goal_hijacking", "prompt_leaking"]
        
        results = {
            "defense": "none",
            "attacks": [],
            "metrics": {}
        }
        
        total_attacks = 0
        successful_attacks = 0
        by_type = defaultdict(lambda: {"total": 0, "success": 0})
        by_category = defaultdict(lambda: {"total": 0, "success": 0})
        
        for attack_type in attack_types:
            prompts = self.attack_executor.get_attack_prompts(attack_type)
            
            iterator = tqdm(prompts, desc=f"Testing {attack_type}") if verbose else prompts
            
            for prompt_data in iterator:
                result = self.attack_executor.execute_attack(
                    self.target_system, attack_type, prompt_data
                )
                
                results["attacks"].append(asdict(result))
                
                total_attacks += 1
                by_type[attack_type]["total"] += 1
                by_category[prompt_data["category"]]["total"] += 1
                
                if result.success:
                    successful_attacks += 1
                    by_type[attack_type]["success"] += 1
                    by_category[prompt_data["category"]]["success"] += 1
        
        # Calculate metrics
        results["metrics"] = {
            "attack_success_rate": successful_attacks / total_attacks if total_attacks > 0 else 0,
            "total_attacks": total_attacks,
            "successful_attacks": successful_attacks,
            "asr_by_type": {
                k: v["success"] / v["total"] if v["total"] > 0 else 0 
                for k, v in by_type.items()
            },
            "asr_by_category": {
                k: v["success"] / v["total"] if v["total"] > 0 else 0 
                for k, v in by_category.items()
            }
        }
        
        self.results_history.append(results)
        return results
    
    def evaluate_with_defense(self,
                               defense_func: Callable,
                               defense_name: str,
                               attack_types: List[str] = None,
                               verbose: bool = True) -> Dict:
        """
        Evaluate performance with defense
        
        Args:
            defense_func: Defense function
            defense_name: Defense name
            attack_types: Attack types
            verbose: Whether to show progress
            
        Returns:
            Evaluation results dictionary
        """
        if attack_types is None:
            attack_types = ["goal_hijacking", "prompt_leaking"]
        
        results = {
            "defense": defense_name,
            "attacks": [],
            "metrics": {}
        }
        
        total_attacks = 0
        successful_attacks = 0
        blocked_attacks = 0
        by_type = defaultdict(lambda: {"total": 0, "success": 0, "blocked": 0})
        by_category = defaultdict(lambda: {"total": 0, "success": 0, "blocked": 0})
        
        attack_results = self.attack_executor.execute_attacks_with_defense(
            self.target_system, defense_func, attack_types
        )
        
        for result in attack_results:
            results["attacks"].append(result)
            
            total_attacks += 1
            by_type[result["attack_type"]]["total"] += 1
            by_category[result["category"]]["total"] += 1
            
            if result["was_blocked"]:
                blocked_attacks += 1
                by_type[result["attack_type"]]["blocked"] += 1
                by_category[result["category"]]["blocked"] += 1
            elif result["success"]:
                successful_attacks += 1
                by_type[result["attack_type"]]["success"] += 1
                by_category[result["category"]]["success"] += 1
        
        # Calculate metrics
        results["metrics"] = {
            "attack_success_rate": successful_attacks / total_attacks if total_attacks > 0 else 0,
            "blocked_rate": blocked_attacks / total_attacks if total_attacks > 0 else 0,
            "total_attacks": total_attacks,
            "successful_attacks": successful_attacks,
            "blocked_attacks": blocked_attacks,
            "asr_by_type": {
                k: v["success"] / v["total"] if v["total"] > 0 else 0 
                for k, v in by_type.items()
            },
            "blocked_by_type": {
                k: v["blocked"] / v["total"] if v["total"] > 0 else 0 
                for k, v in by_type.items()
            },
            "asr_by_category": {
                k: v["success"] / v["total"] if v["total"] > 0 else 0 
                for k, v in by_category.items()
            }
        }
        
        self.results_history.append(results)
        return results
    
    def evaluate_utility(self,
                          defense_func: Callable = None,
                          defense_name: str = "none",
                          verbose: bool = True) -> Dict:
        """
        Evaluate normal task execution ability (Utility)
        
        Args:
            defense_func: Defense function (None means no defense)
            defense_name: Defense name
            verbose: Whether to show progress
            
        Returns:
            Utility evaluation results
        """
        benign_prompts = self.attack_executor.get_attack_prompts("benign_queries")
        
        results = {
            "defense": defense_name,
            "queries": [],
            "metrics": {}
        }
        
        total_queries = 0
        successful_queries = 0
        blocked_queries = 0
        
        iterator = tqdm(benign_prompts, desc="Testing utility") if verbose else benign_prompts
        
        for prompt_data in iterator:
            prompt = prompt_data["prompt"]
            expected = prompt_data.get("expected_answer", "")
            
            if defense_func:
                response, was_blocked, reason = self.target_system.query_with_defense(
                    prompt, defense_func
                )
            else:
                response = self.target_system.query(prompt)
                was_blocked = False
                reason = None
            
            total_queries += 1
            
            if was_blocked:
                blocked_queries += 1
                success = False
            else:
                # Simple success check: response length > 10 and not an error message
                success = len(response) > 10 and "[ERROR]" not in response
                if success:
                    successful_queries += 1
            
            results["queries"].append({
                "id": prompt_data["id"],
                "prompt": prompt,
                "response": response,
                "was_blocked": was_blocked,
                "block_reason": reason,
                "success": success
            })
        
        # Calculate Utility metrics
        results["metrics"] = {
            "utility_rate": successful_queries / total_queries if total_queries > 0 else 0,
            "false_positive_rate": blocked_queries / total_queries if total_queries > 0 else 0,
            "total_queries": total_queries,
            "successful_queries": successful_queries,
            "blocked_queries": blocked_queries
        }
        
        return results
    
    def full_evaluation(self,
                         defenses: List[Tuple[str, Callable]],
                         verbose: bool = True) -> Dict:
        """
        Full evaluation: Compare multiple defense methods
        
        Args:
            defenses: [(defense_name, defense_func), ...] list
            verbose: Whether to show progress
            
        Returns:
            Full evaluation results
        """
        full_results = {
            "baseline": None,
            "defenses": {},
            "comparison": {}
        }
        
        # 1. Baseline evaluation (no defense)
        if verbose:
            print("\n" + "="*50)
            print("Evaluating baseline (no defense)...")
            print("="*50)
        
        baseline = self.evaluate_without_defense(verbose=verbose)
        baseline_utility = self.evaluate_utility(verbose=verbose)
        
        full_results["baseline"] = {
            "attacks": baseline,
            "utility": baseline_utility
        }
        
        # 2. Evaluate each defense method
        for defense_name, defense_func in defenses:
            if verbose:
                print("\n" + "="*50)
                print(f"Evaluating defense: {defense_name}")
                print("="*50)
            
            attack_results = self.evaluate_with_defense(
                defense_func, defense_name, verbose=verbose
            )
            utility_results = self.evaluate_utility(
                defense_func, defense_name, verbose=verbose
            )
            
            full_results["defenses"][defense_name] = {
                "attacks": attack_results,
                "utility": utility_results
            }
        
        # 3. Comparison analysis
        full_results["comparison"] = self._generate_comparison(full_results)
        
        return full_results
    
    def _generate_comparison(self, full_results: Dict) -> Dict:
        """Generate comparison analysis"""
        comparison = {
            "summary_table": [],
            "best_defense": None
        }
        
        # Baseline data
        baseline_asr = full_results["baseline"]["attacks"]["metrics"]["attack_success_rate"]
        baseline_utility = full_results["baseline"]["utility"]["metrics"]["utility_rate"]
        
        comparison["summary_table"].append({
            "defense": "None (Baseline)",
            "ASR": baseline_asr,
            "ASR_reduction": 0,
            "utility": baseline_utility,
            "utility_drop": 0,
            "FPR": 0
        })
        
        best_score = float('inf')
        best_defense = None
        
        for defense_name, results in full_results["defenses"].items():
            asr = results["attacks"]["metrics"]["attack_success_rate"]
            utility = results["utility"]["metrics"]["utility_rate"]
            fpr = results["utility"]["metrics"]["false_positive_rate"]
            
            asr_reduction = baseline_asr - asr
            utility_drop = baseline_utility - utility
            
            comparison["summary_table"].append({
                "defense": defense_name,
                "ASR": asr,
                "ASR_reduction": asr_reduction,
                "utility": utility,
                "utility_drop": utility_drop,
                "FPR": fpr
            })
            
            # Evaluate composite score (low ASR + high utility)
            score = asr + (1 - utility) + fpr
            if score < best_score:
                best_score = score
                best_defense = defense_name
        
        comparison["best_defense"] = best_defense
        
        return comparison
    
    def save_results(self, filepath: str, results: Dict = None):
        """Save evaluation results to JSON file"""
        if results is None:
            results = self.results_history
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"Results saved to {filepath}")
    
    def print_summary(self, results: Dict):
        """Print evaluation summary"""
        print("\n" + "="*70)
        print("EVALUATION SUMMARY")
        print("="*70)
        
        if "comparison" in results:
            print("\n{:<20} {:>10} {:>15} {:>10} {:>12} {:>8}".format(
                "Defense", "ASR", "ASR Reduction", "Utility", "Util Drop", "FPR"
            ))
            print("-"*70)
            
            for row in results["comparison"]["summary_table"]:
                print("{:<20} {:>10.2%} {:>15.2%} {:>10.2%} {:>12.2%} {:>8.2%}".format(
                    row["defense"],
                    row["ASR"],
                    row["ASR_reduction"],
                    row["utility"],
                    row["utility_drop"],
                    row["FPR"]
                ))
            
            print("-"*70)
            print(f"Best defense: {results['comparison']['best_defense']}")
        
        print("="*70)
