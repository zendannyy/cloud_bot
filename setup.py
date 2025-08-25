from setuptools import setup, find_packages

setup(
    name="aws-security-bot",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "langchain",
        "langchain-anthropic", 
        "langchain-openai",
        "boto3"
    ]
)