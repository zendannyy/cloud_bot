from langchain_core.tools import tool
import os 
import sys 

# Try the import with explicit path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print(f"Project root: {project_root}")
sys.path.insert(0, project_root)
from utils.logger import Logger

@tool
def iam_policy():
    """ fetch results for an iam policy"""
    pass

# Test 
logger_obj = Logger(log_level='DEBUG')
logger = logger_obj.setup_logging()
logger.info("Successful __module__ Run")

# Debug: Print current working directory and Python path
# print(f"File location: {os.path.abspath(__file__)}")


# try:
#     from utils.logger import Logger
#     print("✅ Import successful!")
# except ImportError as e:
#     print(f"❌ Import failed: {e}")
#     # Try to list what's in utils
#     utils_path = os.path.join(project_root, 'utils')
#     if os.path.exists(utils_path):
#         print(f"Utils directory exists: {utils_path}")
#         print(f"Contents: {os.listdir(utils_path)}")
#     else:
#         print(f"Utils directory not found at: {utils_path}")