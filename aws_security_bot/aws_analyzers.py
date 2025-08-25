#!/usr/bin/env python3

import boto3
import json
import logging
from datetime import datetime
from functools import wraps
from typing import Dict, Any, List, Optional

# from aws_security_bot.settings import SecurityLevel
from aws_security_bot.settings import config, SecurityLevel

"""AWS security analyzers with built-in decorators"""

# Simple decorators
def rate_limit(max_calls: int = 10):
    """Rate limiting decorator"""
    def decorator(func):
        func.call_count = 0
        func.last_reset = datetime.now()
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = datetime.now()
            if (now - func.last_reset).seconds > 60:
                func.call_count = 0
                func.last_reset = now
            
            if func.call_count >= max_calls:
                raise Exception(f"Rate limit exceeded for {func.__name__}")
            
            func.call_count += 1
            return func(*args, **kwargs)
        return wrapper
    return decorator


def audit_log(operation: str):
    """Security audit logging decorator"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = logging.getLogger(__name__)
            logger.info(f"Security operation: {operation}")
            try:
                result = func(*args, **kwargs)
                logger.info(f"Security operation {operation} completed successfully")
                return result
            except Exception as e:
                logger.error(f"Security operation {operation} failed: {str(e)}")
                raise
        return wrapper
    return decorator


class AWSSession:
    """Simple AWS session manager with context manager"""
    
    def __init__(self):
        self.session = boto3.Session(
            profile_name=config.aws_profile,
            region_name=config.aws_region
        )
        # client caching
        self._clients = {}

    def __enter__(self):
        """Context manager entry point"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit point - cleanup resources"""
        # Close any open clients
        for client in self._clients.values():
            if hasattr(client, '_endpoint'):
                client._endpoint.http_session.close()
        
        # Clear references
        self._clients.clear()
        
        # Log any exceptions
        if exc_type:
            logger = logging.getLogger(__name__)
            logger.error(f"AWS session error: {exc_type.__name__}: {exc_val}")
    
    def get_client(self, service: str):
        """Get AWS service client"""
        return self.session.client(service)
    
    def validate_credentials(self) -> bool:
        """Validate AWS credentials"""
        try:
            sts = self.get_client('sts')
            sts.get_caller_identity()
            return True
        except Exception:
            return False

class S3Analyzer:
    """S3 security analysis"""
    
    def __init__(self):
        # self.aws = AWSSession()
        # self.s3 = self.aws.get_client('s3')
        self.logger = logging.getLogger(__name__)
    
    @audit_log("LIST_S3_BUCKETS")
    @rate_limit(5)
    def list_buckets(self) -> List[Dict[str, Any]]:
        """List all S3 buckets"""
        with AWSSession() as aws:
            s3 = aws.get_client('s3')
        try:
            response = self.s3.list_buckets()
            return [
                {
                    'name': bucket['Name'],
                    'creation_date': bucket['CreationDate'].isoformat(),
                    'region': self._get_bucket_region(bucket['Name'])
                }
                for bucket in response['Buckets']
            ]
        except Exception as e:
            self.logger.error(f"Error listing buckets: {e}")
            return []
    
    @audit_log("ANALYZE_PUBLIC_BUCKETS")
    @rate_limit(10)
    def find_public_buckets(self) -> Dict[str, Any]:
        """Find publicly accessible S3 buckets
        Return buckets
        Using context manager"""
        with AWSSession() as aws:
            s3 = aws.get_client('s3')
        buckets = self.list_buckets()
        public_buckets = []
        
        for bucket in buckets:
            bucket_name = bucket['name']
            if self._is_bucket_public(s3, bucket_name):
                public_buckets.append({
                    'name': bucket_name,
                    'risk_level': SecurityLevel.HIGH.value,
                    'details': self._get_public_details(bucket_name)
                })
        
        return {
            'total_buckets': len(buckets),
            'public_buckets_count': len(public_buckets),
            'public_buckets': public_buckets,
            'risk_level': SecurityLevel.HIGH.value if public_buckets else SecurityLevel.LOW.value,
            'recommendations': self._get_recommendations(public_buckets)
        }
    
    @audit_log("ANALYZE_BUCKET_CONTENTS")
    @rate_limit(15)
    def analyze_bucket_contents(self, bucket_name: str) -> Dict[str, Any]:
        """Analyze specific bucket contents"""
        with AWSSession() as aws:
            s3 = aws.get_client('s3')
            try:
                # Get objects (limited to first 100 for demo)
                response = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=100)
                objects = response.get('Contents', [])
                
                # Analyze data types
                data_types = {}
                total_size = 0
                
                for obj in objects:
                    key = obj['Key']
                    size = obj['Size']
                    total_size += size
                    
                    # Get file extension
                    if '.' in key:
                        ext = key.split('.')[-1].lower()
                        data_types[ext] = data_types.get(ext, 0) + 1
                    else:
                        data_types['no_extension'] = data_types.get('no_extension', 0) + 1
                
                return {
                    'bucket_name': bucket_name,
                    'total_objects': len(objects),
                    'total_size_bytes': total_size,
                    'data_types': data_types,
                    'security_assessment': self._assess_content_security(data_types),
                    'sample_objects': [obj['Key'] for obj in objects[:5]]
                }
                
            except Exception as e:
                return {'error': f"Error analyzing bucket {bucket_name}: {str(e)}"}
    
    def _get_bucket_region(self, s3_client, bucket_name: str) -> str:
        """Get bucket region"""
        try:
            response = self.s3.get_bucket_location(Bucket=bucket_name)
            return response.get('LocationConstraint') or 'us-east-1'
        except:
            return 'unknown'
    
    def _is_bucket_public(self, s3_client, bucket_name: str) -> bool:
        """Check if bucket is publicly accessible"""
        try:
            # Check public access block
            try:
                pab = self.s3.get_public_access_block(Bucket=bucket_name)
                if not all(pab['PublicAccessBlockConfiguration'].values()):
                    return True
            except:
                return True  # No PAB = potentially public
            
            # Check bucket policy
            try:
                policy = self.s3.get_bucket_policy(Bucket=bucket_name)
                if '"Principal": "*"' in policy['Policy']:
                    return True
            except:
                pass
            
            return False
        except:
            return False
    
    def _get_public_details(self, s3_client, bucket_name: str) -> Dict[str, Any]:
        """Get public access details"""
        details = {}
        try:
            # Public access block status
            try:
                pab = self.s3.get_public_access_block(Bucket=bucket_name)
                details['public_access_block'] = pab['PublicAccessBlockConfiguration']
            except:
                details['public_access_block'] = 'Not configured'
            
            # Policy check
            try:
                self.s3.get_bucket_policy(Bucket=bucket_name)
                details['has_bucket_policy'] = True
            except:
                details['has_bucket_policy'] = False
                
        except Exception as e:
            details['error'] = str(e)
        
        return details
    
    def _assess_content_security(self, data_types: Dict[str, int]) -> Dict[str, Any]:
        """Assess security of bucket contents"""
        sensitive_extensions = ['sql', 'db', 'key', 'pem', 'p12', 'pfx', 'env']
        
        sensitive_count = sum(
            count for ext, count in data_types.items() 
            if ext in sensitive_extensions
        )
        
        return {
            'has_sensitive_files': sensitive_count > 0,
            'sensitive_file_count': sensitive_count,
            'risk_level': SecurityLevel.HIGH.value if sensitive_count > 0 else SecurityLevel.LOW.value
        }
    
    def _get_recommendations(self, public_buckets: List[Dict]) -> List[str]:
        """Generate security recommendations"""
        if not public_buckets:
            return ["No public buckets found - good security posture!"]
        
        return [
            "🚨 IMMEDIATE ACTION: Enable S3 Public Access Block on all public buckets",
            "📋 Review bucket policies and remove public access where not needed",
            "🔒 Enable server-side encryption on all buckets",
            "📊 Set up CloudTrail logging for S3 API calls",
            "⏰ Schedule regular security audits of S3 permissions"
        ]


class IAMAnalyzer:
    """IAM permissions analysis"""
    
    def __init__(self):
        # self.aws = AWSSession()
        # self.iam = self.aws.get_client('iam')
        self.logger = logging.getLogger(__name__)
    
    @audit_log("ANALYZE_USER_PERMISSIONS")
    @rate_limit(5)
    def analyze_user_permissions(self, username: str) -> Dict[str, Any]:
        """Analyze IAM user permissions
        Using Context Manager"""
        with AWSSession() as aws:
            iam_analyzer = aws.get_client('iam')
            try:
                # Get user info
                user = self.iam.get_user(UserName=username)
            
                # Get policies
                attached_policies = self.iam.list_attached_user_policies(UserName=username)
                inline_policies = self.iam.list_user_policies(UserName=username)
                groups = self.iam.get_groups_for_user(UserName=username)
            
                # Risk assessment
                risk_info = self._assess_user_risk(
                        attached_policies['AttachedPolicies'],
                        inline_policies['PolicyNames'],
                        groups['Groups']
                    )
            
                return {
                    'username': username,
                    'user_arn': user['User']['Arn'],
                    'attached_policies': [p['PolicyName'] for p in attached_policies['AttachedPolicies']],
                    'inline_policies': inline_policies['PolicyNames'],
                    'groups': [g['GroupName'] for g in groups['Groups']],
                    'total_permission_sources': (
                        len(attached_policies['AttachedPolicies']) + 
                        len(inline_policies['PolicyNames']) + 
                        len(groups['Groups'])
                    ),
                    'risk_assessment': risk_info
                }
                
            except Exception as e:
                return {'error': f"Error analyzing user {username}: {str(e)}"}
    
    def _assess_user_risk(self, attached_policies, inline_policies, groups) -> Dict[str, Any]:
        """Assess user permission risks"""
        high_risk_policies = [
            'AdministratorAccess', 'PowerUserAccess', 'IAMFullAccess',
            'AmazonS3FullAccess', 'AmazonEC2FullAccess'
        ]
        
        has_admin = any(
            policy['PolicyName'] in high_risk_policies 
            for policy in attached_policies
        )
        
        total_sources = len(attached_policies) + len(inline_policies) + len(groups)
        
        if has_admin:
            risk_level = SecurityLevel.HIGH
        elif total_sources > 3:
            risk_level = SecurityLevel.MEDIUM
        else:
            risk_level = SecurityLevel.LOW
        
        # recommendations list
        recommendations = []
        if has_admin:
            recommendations.append("🚨 User has admin access - consider reducing privileges")
        if total_sources > 5:
            recommendations.append("📋 Too many permission sources - consolidate policies")
        
        recommendations.extend([
            "🔐 Ensure MFA is enabled for this user",
            "⏰ Review permissions quarterly",
            "📊 Monitor user activity with CloudTrail"
        ])
        
        return {
            'risk_level': risk_level.value,
            'has_admin_access': has_admin,
            'total_permission_sources': total_sources,
            'recommendations': recommendations
        }
    
    @audit_log("ANALYZE_ROLE_PERMISSIONS")
    @rate_limit(5)
    def analyze_role_permissions(self, role_name: str) -> Dict[str, Any]:
        """Analyze IAM role permissions."""
        with AWSSession() as aws:
            iam = aws.get_client('iam')
            try:
                # Get role info
                role = iam.get_role(RoleName=role_name)
                
                # Get policies
                attached_policies = iam.list_attached_role_policies(RoleName=role_name)
                inline_policies = iam.list_role_policies(RoleName=role_name)
            
                # Risk assessment (reuse user risk logic or create a new one for roles)
                risk_info = self._assess_role_risk(
                    attached_policies['AttachedPolicies'],
                    inline_policies['PolicyNames']
                )
            
                return {
                    'role_name': role_name,
                    'role_arn': role['Role']['Arn'],
                    'attached_policies': [p['PolicyName'] for p in attached_policies['AttachedPolicies']],
                    'inline_policies': inline_policies['PolicyNames'],
                    'total_permission_sources': (
                        len(attached_policies['AttachedPolicies']) + 
                        len(inline_policies['PolicyNames'])
                    ),
                    'risk_assessment': risk_info
                }
            except Exception as e:
                return {'error': f"Error analyzing role {role_name}: {str(e)}"}

    def _assess_role_risk(self, attached_policies, inline_policies) -> Dict[str, Any]:
        """Assess role permission risks."""
        high_risk_policies = [
            'AdministratorAccess', 'PowerUserAccess', 'IAMFullAccess',
            'AmazonS3FullAccess', 'AmazonEC2FullAccess'
        ]
        
        has_admin = any(
            policy['PolicyName'] in high_risk_policies 
            for policy in attached_policies
        )
        
        total_sources = len(attached_policies) + len(inline_policies)
        
        if has_admin:
            risk_level = SecurityLevel.HIGH
        elif total_sources > 3:
            risk_level = SecurityLevel.MEDIUM
        else:
            risk_level = SecurityLevel.LOW
        
        recommendations = []

        recommendations.extend([
            "⏰ Review role permissions quarterly",
                "📊 Monitor role usage with CloudTrail"
                ])
    
        return {
            'risk_level': risk_level.value,
            'has_admin_access': has_admin,
            'total_permission_sources': total_sources,
            'recommendations': recommendations
        }

# Global analyzer instances
s3_analyzer = S3Analyzer()
iam_analyzer = IAMAnalyzer()