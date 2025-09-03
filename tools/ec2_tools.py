from langchain_core.tools import tool
import json 
import boto3
from typing import Dict, Any, List, Optional
from aws_security_bot.aws_analyzers import AWSSession
from tools.schemas import EC2InstanceAnalysisInput, EC2VolumeAnalysisInput
from utils.logger import get_logger


@tool
def describe_tags(event_name, class_attributes, **kwargs):
    """This utilizes a custom describe_tags method on the ec2 service resource

    This is from
    https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-tags.html
    """
    class_attributes['describe_tags'] = describe_tags

@tool("create_tags")
def create_tags(self, **kwargs):
    """Returns tags for the ec2 resources given at the prompt
    Args:
        ec2_instance: Instance to analyze (optional)
        analysis_depth: Level of analysis (basic, detailed, comprehensive)
    
    Returns:
        JSON with detailed security analysis and recommendations
    Call the client method"""
    self.meta.client.describe_tags(**kwargs)
    resources = kwargs.get('Resources', [])
    tags = kwargs.get('Tags', [])
    tag_resources = []

    # Generate all of the tag resources that just were called with the
    # preceding client call.
    for resource in resources:
        for tag in tags:
            # Add each tag from the tag set for each resource to the list
            tag_resource = self.Tag(resource, tag['Key'], tag['Value'])
            tag_resources.append(tag_resource)
    return tag_resources

@tool("describe_instances")
def describe_instances(
    instance_ids: List[str] = None,
    include_volumes: bool = True,
    include_network: bool = True,
    region: Optional[str] = None
) -> str:
    """
    Describe EC2 instances with detailed information including size, volume state, and network details.
    
    Args:
        instance_ids: List of specific instance IDs to describe (optional - describes all if not provided)
        include_volumes: Include detailed volume information
        include_network: Include network interface details
    
    Returns:
        JSON string with detailed instance information
    """
    try:
        get_logger.info(f"Starting EC2 instance analysis. Region: {region}, Instance IDs: {instance_ids}")
        
        # Use AWSSession for proper AWS client management
        with AWSSession() as aws:
            # Create EC2 client with specified region if provided
            if region:
                ec2_client = boto3.client('ec2', region_name=region)
            else:
                ec2_client = aws.get_client('ec2')

        # Prepare filters for describe_instances
        filters = []
        if instance_ids:
            filters.append({'Name': 'instance-id', 'Values': instance_ids})
        
        # Get instance information
        response = ec2_client.describe_instances(Filters=filters)
        
        instances_info = []
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_data = {
                    'instance_id': instance['InstanceId'],
                    'instance_type': instance['InstanceType'],
                    'state': instance['State']['Name'],
                    'launch_time': instance['LaunchTime'].isoformat(),
                    'platform': instance.get('Platform', 'linux'),
                    'architecture': instance['Architecture'],
                    'vpc_id': instance.get('VpcId'),
                    'subnet_id': instance.get('SubnetId'),
                    'availability_zone': instance['Placement']['AvailabilityZone'],
                    'key_name': instance.get('KeyName'),
                    'security_groups': [
                        {
                            'group_id': sg['GroupId'],
                            'group_name': sg['GroupName']
                        } for sg in instance.get('SecurityGroups', [])
                    ],
                    'tags': {
                        tag['Key']: tag['Value'] 
                        for tag in instance.get('Tags', [])
                    }
                }
                
                # Add volume information if requested
                if include_volumes:
                    volume_ids = [
                        block_device['Ebs']['VolumeId'] 
                        for block_device in instance.get('BlockDeviceMappings', [])
                        if 'Ebs' in block_device
                    ]
                    
                    if volume_ids:
                        try:
                            volumes_response = ec2_client.describe_volumes(VolumeIds=volume_ids)
                            instance_data['volumes'] = [
                                {
                                    'volume_id': volume['VolumeId'],
                                    'size_gb': volume['Size'],
                                    'volume_type': volume['VolumeType'],
                                    'state': volume['State'],
                                    'encrypted': volume['Encrypted'],
                                    'iops': volume.get('Iops'),
                                    'throughput': volume.get('Throughput'),
                                    'attachments': [
                                        {
                                            'device': attachment['Device'],
                                            'state': attachment['State'],
                                            'delete_on_termination': attachment['DeleteOnTermination']
                                        } for attachment in volume.get('Attachments', [])
                                    ]
                                } for volume in volumes_response['Volumes']
                            ]
                        except Exception as e:
                            instance_data['volumes'] = {'error': f"Failed to get volume details: {str(e)}"}
                    else:
                        instance_data['volumes'] = []
                
                # Add network interface information if requested
                if include_network:
                    instance_data['network_interfaces'] = [
                        {
                            'interface_id': ni['NetworkInterfaceId'],
                            'subnet_id': ni['SubnetId'],
                            'vpc_id': ni['VpcId'],
                            'private_ip': ni.get('PrivateIpAddress'),
                            'public_ip': ni.get('Association', {}).get('PublicIp'),
                            'status': ni['Status'],
                            'description': ni.get('Description', ''),
                            'groups': [
                                {
                                    'group_id': group['GroupId'],
                                    'group_name': group['GroupName']
                                } for group in ni.get('Groups', [])
                            ]
                        } for ni in instance.get('NetworkInterfaces', [])
                    ]
                
                # Add monitoring and metadata information
                instance_data['monitoring'] = instance['Monitoring']['State']
                instance_data['metadata_options'] = {
                    'http_tokens': instance.get('MetadataOptions', {}).get('HttpTokens', 'optional'),
                    'http_endpoint': instance.get('MetadataOptions', {}).get('HttpEndpoint', 'enabled'),
                    'http_put_response_hop_limit': instance.get('MetadataOptions', {}).get('HttpPutResponseHopLimit', 1)
                }
                
                # Add security analysis if requested
                # if include_security_analysis:
                #     instance_data['security_assessment'] = _assess_instance_security(instance_data)
                
                instances_info.append(instance_data)

        result = {
            'total_instances': len(instances_info),
            'instances': instances_info
        }
        
        return json.dumps(result, indent=2, default=str)
        
    except Exception as e:
        error_result = {
            'error': f"Failed to describe instances: {str(e)}",
            'total_instances': 0,
            'instances': []
        }
        return json.dumps(error_result, indent=2)
