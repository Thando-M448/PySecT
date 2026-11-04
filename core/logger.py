import logging
import os

def setup_logger(module_name: str) -> logging.Logger:
    """
    Creates and configures a standardized logger for PySecT modules.
    Logs both to the console and to a persistent file in the logs/ directory.
    """
    #Ensure the logs directory exists
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)

    #Create logger instance
    logger = logging.getLogger(module_name)
    logger.setLevel(logging.DEBUG)

    #Prevent duplicate handlers if logger is called multiple times
    if logger.handlers:
        return logger

    #Create file handler for saving logs to disk
    log_file = os.path.join(log_dir, "pysect.log")
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)

    #Create console handler for real-time terminal feedback
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    #Define a clean, professional logging format
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Attach handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger