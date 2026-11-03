from core.logger import setup_logger

# Initialize logger for the main application
logger = setup_logger("PySecT-Main")

def main():
    logger.info("PySecT framework initialized successfully.")
    logger.debug("This is a debug message for testing purposes.")
    logger.warning("This is a warning test message.")

if __name__ == "__main__":
    main()