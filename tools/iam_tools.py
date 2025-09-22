from langchain_core.tools import tool
import json
import os 


from utils.logger import Logger, get_logger

from utils.exceptions import ToolExecutionError
from tools.schemas import IAMUserAnalysisInput, IAMRoleAnalysisInput
from aws_security_bot.aws_analyzers import iam_analyzer

@tool
def iam_policy():
    """ fetch results for an iam policy"""
    pass

"""LangChain tools for IAM security analysis"""

logger = get_logger(__name__)


@tool("analyze_role_permissions", args_schema=IAMRoleAnalysisInput)
def analyze_role_permissions(
    role: str,
    include_policy_details: bool = False,
    check_last_activity: bool = True
) -> str:
    """
    Comprehensive IAM Role name permissions and security analysis.
    
    Analyzes IAM Role permissions, policy attachments, and assesses security risks.
    
    Args:
        role: Name of IAM role to analyze
        include_policy_details: Include detailed policy document analysis
        check_last_activity: Check role's last activity/login time
    Returns:
        JSON string with permissions analysis and security recommendations
    """
    try:
        logger.info(f"Starting IAM Role analysis for: {role}")
        # Get basic permissions analysis
        result = iam_analyzer.analyze_role_permissions(role)
        
        # Add enhanced analysis if requested by prompter
        if include_policy_details:
            # This is placeholder
            result['policy_analysis'] = {
                'note': 'Detailed policy analysis requires additional implementation'
            }
        
        if check_last_activity:
            result['activity_analysis'] = {
                'note': 'Activity analysis requires additional implementation'
            }
        
        # Add compliance assessment
        risk_level = result.get('risk_assessment', {}).get('risk_level', 'unknown')
        result['compliance_status'] = {
            'least_privilege_compliance': 'FAIL' if risk_level == 'high' else 'PASS',
            'mfa_required': True,
            'access_review_required': True
        }
        
        logger.info(f"IAM analysis completed for role: {role}")
        return json.dumps(result, indent=2, default=str)
        
    except Exception as e:
        logger.error(f"IAM role analysis failed for {role}: {str(e)}")
        raise ToolExecutionError(f"IAM analysis failed for role {role}: {str(e)}")

@tool("analyze_user_permissions", args_schema=IAMUserAnalysisInput)
def analyze_user_permissions(
    username: str,
    include_policy_details: bool = False,
    check_last_activity: bool = True
) -> str:
    """
    Comprehensive IAM user permissions and security analysis.
    
    Analyzes IAM user permissions, policy attachments, and assesses security risks.
    
    Args:
        username: IAM username to analyze
        include_policy_details: Include detailed policy document analysis
        check_last_activity: Check user's last activity/login time
    Returns:
        Initial logger message returns basic permissions analysis
        JSON string with detailed permissions analysis and security recommendations
    """
    try:
        logger.info(f"Starting IAM user analysis for: {username}")
        result = iam_analyzer.analyze_user_permissions(username)
        
        # Add enhanced analysis if requested
        if include_policy_details:
            # This would require additional implementation in iam_analyzer
            result['policy_analysis'] = {
                'note': 'Detailed policy analysis requires additional implementation'
            }
        
        if check_last_activity:
            # This would require additional AWS API calls
            result['activity_analysis'] = {
                'note': 'Activity analysis requires additional implementation'
            }
        
        # Add compliance assessment
        risk_level = result.get('risk_assessment', {}).get('risk_level', 'unknown')
        result['compliance_status'] = {
            'least_privilege_compliance': 'FAIL' if risk_level == 'high' else 'PASS',
            'mfa_required': True,
            'access_review_required': True
        }
        
        logger.info(f"IAM analysis completed for user: {username}")
        return json.dumps(result, indent=2, default=str)
        
    except Exception as e:
        logger.error(f"IAM user analysis failed for {username}: {str(e)}")
        raise ToolExecutionError(f"IAM analysis failed for user {username}: {str(e)}")


@tool("get_iam_security_recommendations")
def get_iam_security_recommendations() -> str:
    """
    Get comprehensive IAM security recommendations and best practices.
    Provides actionable IAM security recommendations based on AWS security
    best practices and compliance requirements.
    
    Returns:
        JSON string with categorized IAM security recommendations
    """
    try:
        recommendations = {
            'critical_actions': [
                "🚨 Enable MFA for all IAM users",
                "🔑 Rotate access keys regularly (90 days max)",
                "👥 Remove unused IAM users and roles",
                "🔒 Review and remove excessive permissions"
            ],
            'access_management': [
                "📋 Implement least privilege principle",
                "🏷️ Use IAM roles instead of users for applications",
                "👥 Organize users into groups for easier management",
                "🔄 Regular access reviews (quarterly)"
            ],
            'monitoring_and_auditing': [
                "📊 Enable CloudTrail for all API activity",
                "🔍 Monitor failed login attempts",
                "⚠️ Set up alerts for privilege escalation",
                "📝 Regular audit of IAM policies and permissions"
            ],
            'compliance_best_practices': [
                "📊 Document all IAM roles and their purposes",
                "🔒 Implement break-glass procedures for emergency access",
                "👥 Separate duties for critical operations",
                "📝 Maintain audit trails for all permission changes"
            ]
        }
        
        return json.dumps(recommendations, indent=2)
        
    except Exception as e:
        logger.error(f"Failed to generate IAM recommendations: {str(e)}")
        raise ToolExecutionError(f"Failed to generate IAM recommendations: {str(e)}")

# Test success Log message
logger_obj = Logger(log_level='DEBUG')
logger = logger_obj.setup_logging()
logger.info(f"Successful {os.path.abspath(__file__)} Run")
