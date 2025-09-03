"""LangChain tools package for AWS Account analysis"""

from tools.ec2_tools import (
    create_tags,
    describe_instances
)

from tools.s3_tools import (
    analyze_s3_buckets,
    check_public_s3_buckets,
    get_s3_security_recommendations
)
from tools.iam_tools import (
    analyze_user_permissions,
    get_iam_security_recommendations,
    analyze_role_permissions
)

# Collect all tools for easy import
ALL_TOOLS = [
    analyze_s3_buckets,
    check_public_s3_buckets,
    create_tags,
    describe_instances,
    get_s3_security_recommendations,
    analyze_user_permissions,
    analyze_role_permissions,
    get_iam_security_recommendations
]

__all__ = [
    'analyze_s3_buckets',
    'check_public_s3_buckets', 
    'create_tags',
    'describe_instances',
    'get_s3_security_recommendations',
    'analyze_role_permissions',
    'analyze_user_permissions',
    'get_iam_security_recommendations',
    'ALL_TOOLS'
]