# 3.1 Test S3 analyzer in isolation
# File: test_s3_analyzer.py
from aws_security_bot.aws_analyzers import S3Analyzer


def test_s3_list_buckets():
    """Test S3 bucket listing"""
    try:
        analyzer = S3Analyzer()
        buckets = analyzer.list_buckets()
        
        print(f"✅ Listed {len(buckets)} S3 buckets")
        
        if buckets:
            print("Sample bucket:", buckets[0])
        
        return buckets
        
    except Exception as e:
        print(f"❌ S3 listing failed: {e}")
        return []


def test_s3_public_check():
    """Test public bucket detection"""
    try:
        analyzer = S3Analyzer()
        result = analyzer.find_public_buckets()
        
        public_count = result.get('public_buckets_count', 0)
        print(f"✅ Found {public_count} public buckets")
        
        if public_count > 0:
            print("⚠️  WARNING: Public buckets detected!")
            for bucket in result.get('public_buckets', []):
                print(f"  - {bucket['name']}")
        else:
            print("✅ No public buckets found")
        
        return result
        
    except Exception as e:
        print(f"❌ Public bucket check failed: {e}")
        return {}


def test_s3_content_analysis():
    """Test bucket content analysis, if buckets exist"""
    try:
        buckets = test_s3_list_buckets()
        
        if not buckets:
            print("⚠️  No buckets to analyze content")
            return
        
        # Test with first bucket
        bucket_name = buckets[0]['name']
        print(f"Analyzing bucket: {bucket_name}")
        
        analyzer = S3Analyzer()
        result = analyzer.analyze_bucket_contents(bucket_name)
        
        if 'error' in result:
            print(f"❌ Content analysis failed: {result['error']}")
        else:
            print(f"✅ Analyzed {result.get('total_objects', 0)} objects")
            print(f"   Data types: {result.get('data_types', {})}")
        
    except Exception as e:
        print(f"❌ Content analysis failed: {e}")


# Run S3 tests:
# python -c "from test_s3_analyzer import *; test_s3_list_buckets(); test_s3_public_check()"