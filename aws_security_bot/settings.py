"""Configuration and security settings for AWS Security Chatbot"""

import os
import logging
from dataclasses import dataclass
from typing import Optional
from enum import Enum

class SecurityLevel(Enum):
    """Security risk levels"""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"


class LogLevel(Enum):
    """Logging levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass
class Config:
    """Centralized application settings"""
    
    # Claude Configuration
    anthropic_api_key: str = os.getenv('ANTHROPIC_API', '')
    anthropic_model: str = os.getenv('ANTHROPIC_MODEL', 'claude-3-5-sonnet-latest')
    anthropic_temperature: float = float(os.getenv('ANTHROPIC_TEMPERATURE', '0.1'))
    
    # OpenAI Configuration
    openai_api_key: str = os.getenv('OPENAI_API', '')
    openai_model: str = os.getenv('OPENAI_MODEL', 'gpt-3.5-turbo')
    openai_temperature: float = float(os.getenv('OPENAI_TEMPERATURE', '0.1'))
    
    # AWS Configuration
    aws_profile: Optional[str] = os.getenv('AWS_PROFILE')
    aws_region: str = os.getenv('AWS_REGION', 'us-east-1')
    
    # Security Settings
    max_api_calls_per_minute: int = int(os.getenv('MAX_API_CALLS', '10'))
    audit_sensitive_operations: bool = os.getenv('AUDIT_OPERATIONS', 'true').lower() == 'true'
    
    # Agent Configuration
    max_agent_iterations: int = int(os.getenv('MAX_ITERATIONS', '3'))
    agent_verbose: bool = os.getenv('AGENT_VERBOSE', 'true').lower() == 'true'
    
    # Logging Configuration
    log_level: str = os.getenv('LOG_LEVEL', 'INFO')
    log_to_file: bool = os.getenv('LOG_TO_FILE', 'false').lower() == 'true'
    log_file_path: str = os.getenv('LOG_FILE_PATH', 'security_audit.log')
    
    def validate(self) -> None:
        """Validate configuration settings"""
        if not self.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is required")

        # if not self.openai_api_key:
        #     raise ValueError("OPENAI_API_KEY environment variable is required")
        
        # if self.openai_temperature < 0 or self.openai_temperature > 1:
        #     raise ValueError("OPENAI_TEMPERATURE must be between 0 and 1")
        
        # if self.max_api_calls_per_minute <= 0:
        #     raise ValueError("MAX_API_CALLS must be positive")
        
        if self.log_level not in [level.value for level in LogLevel]:
            raise ValueError(f"LOG_LEVEL must be one of: {[l.value for l in LogLevel]}")
    
    @classmethod
    def from_env_file(cls, env_file: str = '.env') -> 'Config':
        """Load settings from .env file"""
        try:
            from dotenv import load_dotenv
            load_dotenv(env_file)
        except ImportError:
            pass  # dotenv is optional
        
        return cls()

# global Vars

# Collect all tools for easy import
# ALL_TOOLS = [
#     analyze_s3_buckets,
#     check_public_s3_buckets,
#     get_s3_security_recommendations,
#     analyze_user_permissions,
#     get_iam_security_recommendations
# ]

# __all__ = [
#     'analyze_s3_buckets',
#     'check_public_s3_buckets', 
#     'get_s3_security_recommendations',
#     'analyze_user_permissions',
#     'get_iam_security_recommendations',
#     'ALL_TOOLS'
# ] 

# Security configuration constants
SENSITIVE_FILE_EXTENSIONS = [
    'key', 'pem', 'p12', 'pfx', 'env', 'sql', 'db', 
    'backup', 'bak', 'config', 'conf', 'ini'
]

HIGH_RISK_IAM_POLICIES = [
    'AdministratorAccess',
    'PowerUserAccess', 
    'IAMFullAccess',
    'AmazonS3FullAccess',
    'AmazonEC2FullAccess',
    'SecurityAudit'
]


# Global settings instance
config = Config()

# def get_all_tools():
#     """Lazy import to avoid circular dependency"""
#     from tools.s3_tools import (
#         analyze_s3_buckets,
#         check_public_s3_buckets,
#         get_s3_security_recommendations
#     )
# """LangChain tools package for AWS Account analysis"""

    
# ALL_TOOLS = None

# def get_tools():
#     """Get tools, initializing if needed"""
#     global ALL_TOOLS
#     if ALL_TOOLS is None:
#         ALL_TOOLS = get_all_tools()
#     return ALL_TOOLS
    