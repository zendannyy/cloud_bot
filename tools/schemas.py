"""Pydantic schemas for LangChain tool inputs"""

import string
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from enum import Enum

# alphanumeric characters allowed by IAM 
iam_characters = string.ascii_letters + '+=,.@-_'

class AnalysisDepth(str, Enum):
    """Analysis depth levels"""
    BASIC = "basic"
    DETAILED = "detailed"
    COMPREHENSIVE = "comprehensive"


class S3BucketAnalysisInput(BaseModel):
    """Input schema for S3 bucket analysis"""
    bucket_name: Optional[str] = Field(
        default=None,
        description="Specific S3 bucket name to analyze. If not provided, analyzes all buckets.",
        min_length=3,
        max_length=63
    )
    
    analysis_depth: AnalysisDepth = Field(
        default=AnalysisDepth.BASIC,
        description="Depth of analysis to perform: basic, detailed, or comprehensive"
    )
    
    include_content_analysis: bool = Field(
        default=True,
        description="Whether to analyze bucket contents and file types"
    )
    
    @field_validator('bucket_name')
    def validate_bucket_name(cls, v):
        if v is not None:
            # Basic S3 bucket name validation
            if not v.replace('-', '').replace('.', '').isalnum():
                raise ValueError("Bucket name contains invalid characters")
            if v.startswith('-') or v.endswith('-'):
                raise ValueError("Bucket name cannot start or end with hyphen")
        return v


class IAMRoleAnalysisInput(BaseModel):
    """Input schema for IAM Role permissions analysis"""
    role: str = Field(
        description="IAM Role to analyze permissions for",
        min_length=1,
        max_length=64
    )
    
    include_policy_details: bool = Field(
        default=False,
        description="Whether to include detailed policy document analysis"
    )
    
    check_last_activity: bool = Field(
        default=True,
        description="Whether to check Role's last activity/login time"
    )
    
    @field_validator('role')
    def validate_role(cls, v):
        # Basic IAM Role validation
        allowed_chars = set(iam_characters)
        # allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+=,.@-_')
        if not set(v).issubset(allowed_chars):
            raise ValueError("Role contains invalid characters")
        return v


class IAMUserAnalysisInput(BaseModel):
    """Input schema for IAM user permissions analysis"""
    username: str = Field(
        description="IAM username to analyze permissions for",
        min_length=1,
        max_length=64
    )
    
    include_policy_details: bool = Field(
        default=False,
        description="Whether to include detailed policy document analysis"
    )
    
    check_last_activity: bool = Field(
        default=True,
        description="Whether to check user's last activity/login time"
    )
    
    @field_validator('username')
    def validate_username(cls, v):
        # Basic IAM username validation
        allowed_chars = set(iam_characters)
        if not set(v).issubset(allowed_chars):
            raise ValueError("Username contains invalid characters")
        return v


class SecurityScanInput(BaseModel):
    """Input schema for comprehensive security scanning"""
    services: List[str] = Field(
        default=["s3", "iam"],
        description="List of AWS services to scan: s3, iam, ec2, etc."
    )
    
    scan_depth: AnalysisDepth = Field(
        default=AnalysisDepth.BASIC,
        description="Depth of security scan to perform"
    )
    
    include_recommendations: bool = Field(
        default=True,
        description="Whether to include security recommendations"
    )
    
    max_resources_per_service: int = Field(
        default=50,
        description="Maximum number of resources to analyze per service",
        ge=1,
        le=1000
    )
    
    @field_validator('services')
    def validate_services(cls, v):
        supported_services = {'s3', 'iam', 'ec2', 'rds', 'lambda', 'cloudformation'}
        invalid_services = set(v) - supported_services
        if invalid_services:
            raise ValueError(f"Unsupported services: {invalid_services}")
        return v


class ComplianceCheckInput(BaseModel):
    """Input schema for compliance checking"""
    framework: str = Field(
        description="Compliance framework to check against: SOC2, PCI-DSS, HIPAA, etc.",
        pattern="^(SOC2|PCI-DSS|CIS|NIST)$"
    )
    
    services_scope: List[str] = Field(
        default=["s3", "iam"],
        description="AWS services to include in compliance check"
    )
    
    generate_report: bool = Field(
        default=False,
        description="Whether to generate a detailed compliance report"
    )

class EC2InstanceAnalysisInput(BaseModel):
    """Input schema for EC2 instance analysis"""
    instance_ids: Optional[List[str]] = Field(
        default=None,
        description="List of specific EC2 instance IDs to analyze. If not provided, analyzes all instances.",
        max_length=100
    )
    
    include_volumes: bool = Field(
        default=True,
        description="Whether to include detailed volume information in the analysis"
    )
    
    include_network: bool = Field(
        default=True,
        description="Whether to include network interface details in the analysis"
    )
    
    analysis_depth: AnalysisDepth = Field(
        default=AnalysisDepth.BASIC,
        description="Depth of analysis to perform: basic, detailed, or comprehensive"
    )
    
    include_security_analysis: bool = Field(
        default=True,
        description="Whether to include security assessment and recommendations"
    )
    
    region: Optional[str] = Field(
        default=None,
        description="AWS region to query (e.g., us-east-1, eu-west-1). If not specified, uses default region.",
        pattern="^[a-z]{2}-[a-z]+-[0-9]+$"
    )

    @field_validator('instance_ids')
    def validate_instance_ids(cls, v):
        if v is not None:
            # EC2 instance ID validation pattern: i-xxxxxxxxxxxxxxxxx
            import re
            instance_id_pattern = r'^i-[a-f0-9]{8,17}$'
            for instance_id in v:
                if not re.match(instance_id_pattern, instance_id):
                    raise ValueError(f"Invalid EC2 instance ID format: {instance_id}")
        return v
    
    @field_validator('region')
    def validate_region(cls, v):
        if v is not None:
            # Basic AWS region validation
            import re
            region_pattern = r'^[a-z]{2}-[a-z]+-[0-9]+$'
            if not re.match(region_pattern, v):
                raise ValueError(f"Invalid AWS region format: {v}")
        return v
    
class EC2VolumeAnalysisInput(BaseModel):
    """Input schema for EC2 volume analysis"""
    volume_ids: Optional[List[str]] = Field(
        default=None,
        description="List of specific volume IDs to analyze. If not provided, analyzes all volumes.",
        max_length=100
    )
    
    include_encryption_analysis: bool = Field(
        default=True,
        description="Whether to analyze encryption status and compliance"
    )
    
    check_unused_volumes: bool = Field(
        default=True,
        description="Whether to identify unused or orphaned volumes"
    )
    
    @field_validator('volume_ids')
    def validate_volume_ids(cls, v):
        if v is not None:
            # Volume ID validation pattern: vol-xxxxxxxxx
            import re
            volume_pattern = r'^vol-[a-f0-9]{8,17}$'
            for volume_id in v:
                if not re.match(volume_pattern, volume_id):
                    raise ValueError(f"Invalid volume ID format: {volume_id}")
        return v
