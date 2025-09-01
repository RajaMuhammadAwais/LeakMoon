"""
Secret Detection Module for LeakMon
Detects various types of secrets, credentials, and PII in text content.
"""

import re
import math
from typing import List, Dict, Tuple
from dataclasses import dataclass
from enum import Enum


class SeverityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Detection:
    """Represents a detected secret or PII"""
    type: str
    value: str
    line_number: int
    column_start: int
    column_end: int
    severity: SeverityLevel
    confidence: float
    context: str


class SecretDetector:
    """Main class for detecting secrets and PII in text content"""
    
    def __init__(self):
        self.patterns = self._load_patterns()
        self.entropy_threshold = 4.5
        
    def _load_patterns(self) -> Dict[str, Dict]:
        """Load regex patterns for different types of secrets"""
        return {
            # High severity - Private keys and high-value secrets
            'aws_access_key': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'severity': SeverityLevel.HIGH,
                'description': 'AWS Access Key ID'
            },
            'aws_secret_key': {
                'pattern': r'[A-Za-z0-9/+=]{40}',
                'severity': SeverityLevel.HIGH,
                'description': 'AWS Secret Access Key',
                'context_required': ['aws', 'secret', 'key']
            },
            'private_key': {
                'pattern': r'-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----',
                'severity': SeverityLevel.HIGH,
                'description': 'Private Key'
            },
            'jwt_token': {
                'pattern': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
                'severity': SeverityLevel.HIGH,
                'description': 'JWT Token'
            },
            
            # Medium severity - API keys and tokens
            'github_token': {
                'pattern': r'ghp_[A-Za-z0-9]{36}',
                'severity': SeverityLevel.MEDIUM,
                'description': 'GitHub Personal Access Token'
            },
            'openai_api_key': {
                'pattern': r'sk-[A-Za-z0-9]{48}',
                'severity': SeverityLevel.MEDIUM,
                'description': 'OpenAI API Key'
            },
            'stripe_key': {
                'pattern': r'sk_live_[A-Za-z0-9]{24}',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Stripe Live Secret Key'
            },
            'slack_token': {
                'pattern': r'xox[baprs]-[A-Za-z0-9-]+',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Slack Token'
            },
            'database_url': {
                'pattern': r'(mysql|postgresql|mongodb)://[^:]+:[^@]+@[^/]+',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Database Connection String'
            },
            
            # Low severity - PII and other sensitive data
            'email': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'severity': SeverityLevel.LOW,
                'description': 'Email Address'
            },
            'phone_number': {
                'pattern': r'\b\d{3}-\d{3}-\d{4}\b|\b\(\d{3}\)\s*\d{3}-\d{4}\b',
                'severity': SeverityLevel.LOW,
                'description': 'Phone Number'
            },
            'credit_card': {
                'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Credit Card Number'
            },
            'ssn': {
                'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Social Security Number'
            }
        }
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def detect_high_entropy_strings(self, text: str, line_number: int) -> List[Detection]:
        """Detect strings with high entropy that might be secrets"""
        detections = []
        
        # Look for base64-like strings
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.finditer(base64_pattern, text)
        
        for match in matches:
            value = match.group()
            entropy = self.calculate_entropy(value)
            
            if entropy > self.entropy_threshold and len(value) > 20:
                detection = Detection(
                    type='high_entropy_string',
                    value=value,
                    line_number=line_number,
                    column_start=match.start(),
                    column_end=match.end(),
                    severity=SeverityLevel.MEDIUM,
                    confidence=min(entropy / 6.0, 1.0),  # Normalize to 0-1
                    context=text.strip()
                )
                detections.append(detection)
        
        return detections
    
    def scan_text(self, text: str, filename: str = None) -> List[Detection]:
        """Scan text content for secrets and PII"""
        detections = []
        lines = text.split('\n')
        
        for line_number, line in enumerate(lines, 1):
            # Skip comments and obvious test data
            if self._should_skip_line(line):
                continue
            
            # Check against known patterns
            for pattern_name, pattern_info in self.patterns.items():
                pattern = pattern_info['pattern']
                matches = re.finditer(pattern, line, re.IGNORECASE)
                
                for match in matches:
                    # Check context requirements if specified
                    if 'context_required' in pattern_info:
                        if not self._check_context(line.lower(), pattern_info['context_required']):
                            continue
                    
                    # Calculate confidence based on pattern specificity
                    confidence = self._calculate_confidence(pattern_name, match.group(), line)
                    
                    if confidence > 0.3:  # Minimum confidence threshold
                        detection = Detection(
                            type=pattern_name,
                            value=match.group(),
                            line_number=line_number,
                            column_start=match.start(),
                            column_end=match.end(),
                            severity=pattern_info['severity'],
                            confidence=confidence,
                            context=line.strip()
                        )
                        detections.append(detection)
            
            # Check for high entropy strings
            entropy_detections = self.detect_high_entropy_strings(line, line_number)
            detections.extend(entropy_detections)
        
        return detections
    
    def _should_skip_line(self, line: str) -> bool:
        """Check if a line should be skipped during scanning"""
        line = line.strip().lower()
        
        # Skip empty lines
        if not line:
            return True
        
        # Skip comments
        if line.startswith('#') or line.startswith('//') or line.startswith('/*'):
            return True
        
        # Skip obvious test/example data
        skip_keywords = ['example', 'test', 'dummy', 'fake', 'sample', 'placeholder']
        if any(keyword in line for keyword in skip_keywords):
            return True
        
        return False
    
    def _check_context(self, line: str, required_keywords: List[str]) -> bool:
        """Check if line contains required context keywords"""
        return any(keyword in line for keyword in required_keywords)
    
    def _calculate_confidence(self, pattern_name: str, value: str, context: str) -> float:
        """Calculate confidence score for a detection"""
        base_confidence = 0.7
        
        # Adjust based on pattern type
        if pattern_name in ['aws_access_key', 'github_token', 'openai_api_key']:
            base_confidence = 0.9  # Very specific patterns
        elif pattern_name in ['email', 'phone_number']:
            base_confidence = 0.6  # Common patterns, might have false positives
        
        # Reduce confidence for test/example contexts
        context_lower = context.lower()
        if any(word in context_lower for word in ['test', 'example', 'dummy', 'fake']):
            base_confidence *= 0.3
        
        # Increase confidence for production-like contexts
        if any(word in context_lower for word in ['prod', 'production', 'live', 'api_key']):
            base_confidence = min(base_confidence * 1.2, 1.0)
        
        return base_confidence
    
    def scan_file(self, filepath: str) -> List[Detection]:
        """Scan a file for secrets and PII"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return self.scan_text(content, filepath)
        except Exception as e:
            print(f"Error scanning file {filepath}: {e}")
            return []

