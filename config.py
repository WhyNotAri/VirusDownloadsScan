import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("API_KEY")
downloads_path = Path.home() / "Downloads"