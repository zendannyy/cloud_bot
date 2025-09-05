#!/usr/bin/env python3

from .logger import Logger
# from utils.logger import Logger

logger_obj = Logger(log_level='DEBUG')
logger = logger_obj.setup_logging()
logger.info("Successful Logger Run")
