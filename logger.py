import logging
import os
from pathlib import Path

def setup_logging():
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    logfile_path = Path(log_dir) / "virus_scanner.log"

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] | %(message)s',
        handlers=[logging.FileHandler(logfile_path), logging.StreamHandler()]
    )