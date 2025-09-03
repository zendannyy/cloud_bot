import boto3
from aws_security_bot.aws_analyzers import AWSSession


def test_aws_credentials():
    """Test AWS credential setup"""
    try:
        session = AWSSession()
        
        # Test credential validation
        is_valid = session.validate_credentials()
        
        if is_valid:
            print("✅ AWS credentials are valid")
            
            # Test getting a client
            s3_client = session.get_client('s3')
            print("✅ S3 client created successfully")
            
            # Test a simple API call
            response = s3_client.list_buckets()
            bucket_count = len(response.get('Buckets', []))
            print(f"✅ Found {bucket_count} S3 buckets")
            
        else:
            print("❌ AWS credentials are invalid")
            print("Run: aws configure")
            
    except Exception as e:
        print(f"❌ AWS connection failed: {e}")
        print("Solutions:")
        print("1. Run: aws configure")
        print("2. Set AWS_PROFILE environment variable")
        print("3. Check AWS credentials file")

