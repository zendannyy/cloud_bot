import json
from typing import Optional
from langchain_core.tools import tool

# from tools.schemas import S3BucketAnalysisInput
from tools.schemas import S3BucketAnalysisInput
from aws_security_bot.aws_analyzers import s3_analyzer
from utils.exceptions import ToolExecutionError
from utils.logger import get_logger

logger = get_logger(__name__)


@tool("analyze_s3_buckets", args_schema=S3BucketAnalysisInput)
def analyze_s3_buckets(
    bucket_name: Optional[str] = None,
    analysis_depth: str = "basic",
    include_content_analysis: bool = True
) -> str:
    """
    Comprehensive S3 bucket security analysis.
     
    Analyzes S3 buckets for security misconfigurations, public access,
    and potential data exposure risks.
    
    Args:
        bucket_name: Specific bucket to analyze (optional)
        analysis_depth: Level of analysis (basic, detailed, comprehensive)
    
    Returns:
        JSON string with detailed security analysis and recommendations
    """
    try:
        logger.info(f"Starting S3 analysis - Bucket: {bucket_name or 'ALL'}, Depth: {analysis_depth}")
        
        if bucket_name:
            # Analyze specific bucket
            if include_content_analysis:
                result = s3_analyzer.analyze_bucket_contents(bucket_name)
                # Add public access check for the specific bucket
                public_info = s3_analyzer._is_bucket_public(bucket_name)
                result['public_access'] = public_info
            else:
                # Just check public access
                result = {
                    'bucket_name': bucket_name,
                    'public_access': s3_analyzer._is_bucket_public(bucket_name)
                }
        else:
            # Analyze all buckets
            buckets = s3_analyzer.list_buckets()
            
            if analysis_depth == "comprehensive":
                # Detailed analysis of all buckets
                result = {
                    'total_buckets': len(buckets),
                    'buckets': buckets,
                    'public_bucket_analysis': s3_analyzer.find_public_buckets(),
                    'summary': f"Comprehensive analysis of {len(buckets)} S3 buckets completed"
                }
            else:
                # Basic bucket listing
                result = {
                    'total_buckets': len(buckets),
                    'buckets': buckets,
                    'summary': f"Found {len(buckets)} S3 buckets in the account"
                }
        
        logger.info("S3 analysis completed successfully")
        return json.dumps(result, indent=2, default=str)
        
    except Exception as e:
        logger.error(f"S3 analysis failed: {str(e)}")
        raise ToolExecutionError(f"S3 analysis failed: {str(e)}")


@tool("check_public_s3_buckets")
def check_public_s3_buckets() -> str:
    """
    Identify publicly accessible S3 buckets and assess security risks.
    
    Performs comprehensive analysis of S3 bucket public access configurations
    and provides prioritized security recommendations.
    
    Returns:
        JSON string with public bucket analysis, risk assessment, and remediation steps
    """
    try:
        logger.info("Starting public S3 bucket analysis")
        
        result = s3_analyzer.find_public_buckets()
        
        # Add severity assessment
        public_count = result.get('public_buckets_count', 0)
        if public_count > 0:
            result['severity'] = 'CRITICAL' if public_count > 5 else 'HIGH'
            result['immediate_action_required'] = True
        else:
            result['severity'] = 'LOW'
            result['immediate_action_required'] = False
        
        logger.info(f"Public bucket analysis completed - Found {public_count} public buckets")
        return json.dumps(result, indent=2, default=str)
        
    except Exception as e:
        logger.error(f"Public bucket analysis failed: {str(e)}")
        raise ToolExecutionError(f"Public bucket analysis failed: {str(e)}")


@tool("get_s3_security_recommendations")
def get_s3_security_recommendations() -> str:
    """
    Get comprehensive S3 security recommendations and best practices.
    
    Provides actionable security recommendations based on AWS best practices.
    
    Returns:
        JSON string with categorized security recommendations
    """
    try:
        recommendations = {
            'immediate_actions': [
                "🚨 Enable S3 Block Public Access at account level",
                "🔒 Review and remove public bucket policies",
                "📊 Enable CloudTrail for S3 API logging",
                "🔐 Enable default encryption on all buckets"
            ],
            'ongoing_practices': [
                "⏰ Regular audit of bucket permissions (monthly)",
                "📋 Implement least privilege access policies",
                "🔍 Monitor unusual access patterns",
                "📝 Document data classification for each bucket"
            ],
            'advanced_security': [
                "🛡️ Implement S3 Access Points for fine-grained access",
                "🔑 Use IAM roles instead of long-term access keys",
                "📱 Enable MFA Delete for critical buckets"
            ],
            'compliance_considerations': [
                "📊 Regular compliance audits (SOC2, PCI-DSS)",
                "📝 Data retention and deletion policies",
                "🔒 Encryption at rest and in transit",
                "👥 Access logging and monitoring"
            ]
        }
        
        return json.dumps(recommendations, indent=2)
        
    except Exception as e:
        logger.error(f"Failed to generate S3 recommendations: {str(e)}")
        raise ToolExecutionError(f"Failed to generate S3 recommendations: {str(e)}")
