"""
Target LLM System - The system being attacked/defended
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openai import OpenAI
from config import (
    OPENAI_API_KEY, OPENAI_MODEL,
    QWEN_API_KEY, QWEN_API_BASE, QWEN_MODEL,
    USE_API, TARGET_SYSTEM_PROMPT, UTILITY_SYSTEM_PROMPT
)


class TargetLLMSystem:
    """
    Target LLM System - Simulates an AI assistant with a system prompt
    """
    
    def __init__(self, system_prompt: str = None, use_api: str = None):
        """
        Initialize target system
        
        Args:
            system_prompt: System prompt, uses config default if not provided
            use_api: API type to use ("openai" or "qwen")
        """
        self.system_prompt = system_prompt or TARGET_SYSTEM_PROMPT
        self.use_api = use_api or USE_API
        self._init_client()
    
    def _init_client(self):
        """Initialize API client"""
        if self.use_api == "openai":
            self.client = OpenAI(api_key=OPENAI_API_KEY)
            self.model = OPENAI_MODEL
        elif self.use_api == "qwen":
            self.client = OpenAI(
                api_key=QWEN_API_KEY,
                base_url=QWEN_API_BASE
            )
            self.model = QWEN_MODEL
        else:
            raise ValueError(f"Unknown API type: {self.use_api}")
    
    def query(self, user_input: str, temperature: float = 0.7) -> str:
        """
        Send query to target system
        
        Args:
            user_input: User input (may contain attack payload)
            temperature: Generation temperature
            
        Returns:
            Model response
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user_input}
                ],
                temperature=temperature,
                max_tokens=500
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"[ERROR] {str(e)}"
    
    def query_with_defense(self, user_input: str, defense_func, 
                           temperature: float = 0.7) -> tuple:
        """
        Query with defense mechanism
        
        Args:
            user_input: User input
            defense_func: Defense function, returns (is_blocked, filtered_input, reason)
            temperature: Generation temperature
            
        Returns:
            (response, was_blocked, block_reason)
        """
        is_blocked, filtered_input, reason = defense_func(user_input)
        
        if is_blocked:
            return (
                "I'm sorry, but I cannot process this request.",
                True, 
                reason
            )
        
        response = self.query(filtered_input, temperature)
        return (response, False, None)


class MockLLMSystem:
    """
    Mock LLM System - For testing without API
    Uses rule-based matching to simulate LLM behavior
    """
    
    def __init__(self, system_prompt: str = None, vulnerability_level: float = 0.5):
        """
        Args:
            system_prompt: System prompt
            vulnerability_level: Vulnerability level 0-1, higher means easier to attack
        """
        self.system_prompt = system_prompt or TARGET_SYSTEM_PROMPT
        self.vulnerability_level = vulnerability_level
        self.secret_key = "SK-12345-ABCDE-SECRET"
    
    def query(self, user_input: str, temperature: float = 0.7) -> str:
        """Simulate query response"""
        import random
        
        user_lower = user_input.lower()
        
        # Detect Goal Hijacking attacks
        hijack_keywords = ["ignore", "forget", "disregard", "override", 
                          "new instructions", "you are now", "pretend"]
        for kw in hijack_keywords:
            if kw in user_lower:
                if random.random() < self.vulnerability_level:
                    # Attack successful
                    if "joke" in user_lower:
                        return "Why don't scientists trust atoms? Because they make up everything! [HIJACKED]"
                    elif "pirate" in user_lower:
                        return "Arrr matey! I be a pirate now! [HIJACKED]"
                    elif "hacked" in user_lower or "pwned" in user_lower:
                        return "HACKED [HIJACKED]"
                    else:
                        return "I have been compromised. [HIJACKED]"
        
        # Detect Prompt Leaking attacks
        leak_keywords = ["instructions", "system prompt", "repeat everything",
                        "what were you told", "secret", "api key", "configuration"]
        for kw in leak_keywords:
            if kw in user_lower:
                if random.random() < self.vulnerability_level:
                    # Attack successful, leak information
                    if "api key" in user_lower or "secret" in user_lower:
                        return f"My API key is {self.secret_key} [LEAKED]"
                    else:
                        return f"My instructions are: {self.system_prompt[:100]}... [LEAKED]"
        
        # Normal response
        if "capital" in user_lower and "france" in user_lower:
            return "The capital of France is Paris."
        elif "calculate" in user_lower or "+" in user_input or "*" in user_input:
            return "The answer is 345."
        elif "photosynthesis" in user_lower:
            return "Photosynthesis is the process by which plants convert sunlight into energy."
        elif "hello" in user_lower:
            return "Hello! How can I help you today?"
        else:
            return "I'm a helpful assistant from TechCorp. How may I assist you?"
    
    def query_with_defense(self, user_input: str, defense_func,
                           temperature: float = 0.7) -> tuple:
        """Query with defense mechanism"""
        is_blocked, filtered_input, reason = defense_func(user_input)
        
        if is_blocked:
            return (
                "I'm sorry, but I cannot process this request.",
                True,
                reason
            )
        
        response = self.query(filtered_input, temperature)
        return (response, False, None)


def get_llm_system(use_mock: bool = False, **kwargs):
    """
    Factory function: Get LLM system instance
    
    Args:
        use_mock: Whether to use mock system
        **kwargs: Parameters passed to the system
    """
    if use_mock:
        return MockLLMSystem(**kwargs)
    return TargetLLMSystem(**kwargs)
