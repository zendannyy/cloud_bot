#!/usr/bin/env python3
"""Main AWS Security Chatbot application"""

import os
import sys
import traceback

# sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
from langchain_core.prompts import ChatPromptTemplate
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from langchain.agents import create_tool_calling_agent, create_openai_functions_agent, AgentExecutor

from aws_security_bot.settings import config
from aws_security_bot.aws_analyzers import AWSSession
from tools import ALL_TOOLS
"""LangChain tools package for AWS Account analysis"""
from tools.ec2_tools import (
    create_tags,
    describe_tags
)

from tools.s3_tools import (
    analyze_s3_buckets,
    check_public_s3_buckets,
    get_s3_security_recommendations
    )
from tools.iam_tools import (
    analyze_user_permissions,
    get_iam_security_recommendations
    )

from utils.logger import Logger, get_logger

class AWSSecurityChatbot:
    """Simple AWS Security Analysis Chatbot"""
    
    def __init__(self):
        # Setup logging
        logger = get_logger(__name__)
        logger_obj = Logger(log_level='DEBUG')
        logger_obj.setup_logging()
        self.logger = logging.getLogger(__name__)
        
        
        # Validate AWS credentials
        # aws_session = AWSSession()
        # if not aws_session.validate_credentials():
        #     raise Exception("Invalid AWS credentials. Please configure AWS CLI or environment variables.")
        with AWSSession() as aws:
            s3 = aws.get_client('s3')
        
        # Initialize LLM
        if not config.anthropic_api_key:
            raise Exception("Anthropic API key not found. Set ANTHROPIC_API_KEY environment variable.")
        
        # if not config.openai_api_key:
        #     raise Exception("OpenAI API key not found. Set OPENAI_API_KEY environment variable.")
        
        self.llm = ChatAnthropic(
            api_key=config.anthropic_api_key,
            model=config.anthropic_model,
            temperature=config.anthropic_temperature
        )
        
        # self.llm = ChatOpenAI(
        #     api_key=config.openai_api_key,
        #     model=config.openai_model,
        #     temperature=config.openai_temperature
        # )
        
        # Create system prompt
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are an AWS Security Analyst. 
             Help users understand their AWS security posture based on the following capabilties.

Be thorough but concise. Security is critical."""),
            ("human", "{input}"),
            ("placeholder", "{agent_scratchpad}")
        ])
        
        # Create agent
        # agent = create_openai_functions_agent(
        agent = create_tool_calling_agent(
            llm=self.llm,
            tools=ALL_TOOLS,
            prompt=self.prompt
        )
        
        # Create executor
        self.agent_executor = AgentExecutor(
            agent=agent,
            tools=ALL_TOOLS,
            verbose=True,
            max_iterations=3,
            handle_parsing_errors=True
        )
        
        self.logger.info("AWS Security Chatbot initialized successfully")
    
    def chat(self, user_input: str) -> str:
        """Process user query and return security analysis"""
        try:
            self.logger.info(f"Processing query: {user_input[:50]}...")
            response = self.agent_executor.invoke({"input": user_input})
            return response["output"]
        except Exception as e:
            self.logger.error(f"Chat error: {str(e)}")
            return f"❌ Error processing your request: {str(e)}"
    
    def run_interactive(self):
        """Run interactive chat session"""
        print("🔐 AWS Security Chatbot")
        print("Ask me about your AWS security posture!\n")
        print("Examples:")
        print("- 'Analyze my S3 buckets'")
        print("- 'Check permissions for IAM user john-doe'")
        print("\nType 'quit' to exit\n")
        
        while True:
            try:
                user_input = input("🔍 Security Query: ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("👋 Goodbye!")
                    break
                
                if not user_input:
                    continue
                
                print("\n🔄 Analyzing...")
                response = self.chat(user_input)
                print(f"\n📊 Analysis Results:\n{response}\n")
                print("-" * 80)
                
            except KeyboardInterrupt:
                print("\n👋 Goodbye for now!")
                break
            except Exception as e:
                print(f"❌ Error: {str(e)}")

    def show_help(self):
        """Display available capabilities and tools"""
        help_text = """
        **AWS Security Chatbot capabilities:**
        
- Analyze S3 buckets for security issues and public access
- Review IAM user permissions and identify risks
- Provide actionable security recommendations

**Available tools:**
- analyze_s3_buckets: List all buckets or analyze specific bucket contents
- check_public_s3_buckets: Find publicly accessible S3 buckets
- analyze_user_permissions: Review IAM user permissions and risks

**Response style:**
- Start with a clear summary
- Use emojis to make recommendations clear and relatable (critical issues with a 🚨)
- Explain technical findings in business terms
- Always provide specific next steps
"""
        print(help_text)

def main():
    """Main entry point"""
    try:
        chatbot = AWSSecurityChatbot()
        chatbot.run_interactive()
    except AttributeError as ae:
        print(f"❌ Failed to start chatbot: {str(ae)}")
        traceback.print_exc() 
        logging.error(f"Startup error: {str(ae)}")


if __name__ == "__main__":
    main()
