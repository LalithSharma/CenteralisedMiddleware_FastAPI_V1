from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import os

logs_dir = os.path.join(os.getcwd(), "static", "app_logs")
os.makedirs(logs_dir, exist_ok=True)
    
current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_file_name = os.path.join(logs_dir, f"{current_time}.log")

log_formatter = logging.Formatter(
    "%(asctime)s - IP: %(client_ip)s - Domain: %(host)s - URL: %(url)s - Token: %(token)s - LogMessage: %(log_message)s"
)

log_handler = RotatingFileHandler(
    log_file_name, maxBytes=10 * 1024 * 1024, backupCount=5
)
log_handler.setFormatter(log_formatter)
logger = logging.getLogger("apps_logger")
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# Logging utility functions
def log_info(client_ip="unknown", host="unknown", url="unknown", token="none", message=""):
    log_data = {
        "log_type": "Info",
        "client_ip": client_ip,
        "host": host,
        "url": url,
        "token": token,
        "log_message": message,
    }
    logger.info("", extra=log_data)


def log_error(client_ip="unknown", host="unknown", url="unknown", token="none", message=""):
    log_data = {
        "log_type": "Error",
        "client_ip": client_ip,
        "host": host,
        "url": url,
        "token": token,
        "log_message": message,
    }
    logger.error("", extra=log_data)
