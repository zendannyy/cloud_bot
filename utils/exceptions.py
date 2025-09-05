"""Custom exceptions for AWS Security Chatbot"""

"""
1. DEFINE exceptions (utils/exceptions.py)
   - Just class definitions with 'pass'

2. RAISE exceptions (in analysis code)
   - Use 'raise ExceptionName("message")'
   - When something goes wrong

3. CATCH exceptions (in main.py, tools, etc.)
   - Use try/except blocks
   - Handle errors gracefully
   - Provide helpful error messages
   """

class SecurityChatbotError(Exception):
    """Base exception for all chatbot errors"""
    pass


class ConfigurationError(SecurityChatbotError):
    """Raised when configuration is invalid"""
    pass


class AWSCredentialsError(SecurityChatbotError):
    """Raised when AWS credentials are invalid or missing"""
    pass


class RateLimitError(SecurityChatbotError):
    """Raised when API rate limits are exceeded"""
    pass


class SecurityAuditError(SecurityChatbotError):
    """Raised when security audit operations fail"""
    pass


class AnalysisError(SecurityChatbotError):
    """Raised when AWS resource analysis fails"""
    pass


class ToolExecutionError(SecurityChatbotError):
    """Raised when LangChain tool execution fails"""
    pass
