import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scanner import scan_file
from config import downloads_path
from logger import setup_logging

setup_logging()

def process_file(route):
    if any(route.endswith(extension) for extension in ['.download', '.part', '.tmp']):
        return None

    time.sleep(5)

    if os.path.exists(route):
        return scan_file(route)

    return None

class Handler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.route_results = {}

    def handle_route(self, route):
        if route in self.route_results:
            logging.warning(f"File: {os.path.basename(route)} already scanned, the results were:\n{self.route_results[route]}")
            return self.route_results[route]
        else:
            logging.info(f"Scanning -> {os.path.basename(route)} <-")
            result = process_file(route)
            self.route_results[route] = result

        return result

    def on_created(self, event):
        if event.is_directory:
            return

        self.handle_route(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return

        self.handle_route(event.dest_path)


if __name__ == "__main__":
    observer = Observer()
    handler = Handler()

    observer.schedule(handler, str(downloads_path), recursive=False)
    observer.start()

    logging.info("Searching for files in the downloads folder...")

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        observer.stop()
        logging.info("Stopping")

    observer.join()
