import logging
import os

### This file is not needed anymore as I do logging on each script  

if not os.path.exists("logs"):
    os.makedirs("logs")

logging.basicConfig(
    filename="logs/pentest.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_info(message):
    print(f"[INFO] {message}")
    logging.info(message)

def log_error(message):
    print(f"[ERROR] {message}")
    logging.error(message)

