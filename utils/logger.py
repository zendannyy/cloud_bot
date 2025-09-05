#!/usr/bin/env python3
import os
import logging
import uuid
from dataclasses import dataclass
from enum import Enum, IntEnum


UUID = str(uuid.uuid4())

class LoggingLevel(IntEnum):
    """Security levels for operations"""
    DEBUG = logging.DEBUG
    LOW = logging.INFO
    MEDIUM = logging.WARNING
    HIGH = logging.ERROR
    CRITICAL = logging.CRITICAL


@dataclass
class Logger:
    """Centralized logging"""
    log_level: str = os.getenv('LOG_LEVEL', 'INFO')
    
    def setup_logging(self):
        """Setup logging configuration"""

        default_time_format = "%Y-%m-%dT%H:%M:%S"
        logger = logging.getLogger(__name__)        # uses the module name
        extra = {'script': self, 'uuid': UUID}

        logging.basicConfig(
            level=getattr(logging, self.log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(lineno)d - %(message)s'
        )
    #     if IS_DEV:
	# 		LOGGER.info(f"{config_object.name} would have been updated")
	# 	else:
	# 		LOGGER.info(f"{config_object.name} was successfully updated")
	# else:
	# 	LOGGER.debug(f"{config_object.name} does not need updating")

        logger = logging.LoggerAdapter(logger, extra)

        # Security-specific logger
        # security_logger = logging.getLogger('security')
        # security_logger.setLevel(logging.INFO)
        return logger
    
def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with consistent configuration"""
    return logging.getLogger(name)

class SecurityAuditLogger:
    """Specialized logger for security audit events"""
    
    def __init__(self):
        self.logger = get_logger('security.audit')
    
    def log_operation(self, operation: str, username: str = None, resource: str = None, status: str = "SUCCESS"):
        """Log security-sensitive operations"""
        # message = f"Operation: {operation}" +
        # if username:
        #     message += f" | User: {username}"
        # if resource:
        #     message += f" | Resource: {resource}"
        parts = [
            f"Operation: {operation}",
            f"User: {username}" if username else None,
            f"Resource: {resource}" if resource else None,
            f"Status: {status}"
        ]
        message = " | ".join(part for part in parts if part is not None)
        self.logger.info(message)
# Create a default instance for convenience, Logger Instance class
security_audit = SecurityAuditLogger()
setup_logging = Logger(log_level=LoggingLevel)