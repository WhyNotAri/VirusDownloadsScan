# Virus(Total) Auto Scanner
Using the VirusTotal API to scan files for malware and other threats.

---

## Features
- Scan downloaded files for malware and other threats.
- Get the results of the scan and save them to a log file.
---

## Tech Stack

- VirusTotal API
- Python 3.14
- Python Packages: 
  - python-dotenv
  - requests
  - watchdog

---

## Installation
````
git clone https://github.com/WhyNotAri/VirusDownloadsScan.git
cd <project_directory>
pip install -r requirements.txt
python main.py
````

---

## Project Tree
````
.
├── main.py -> main script
├── config.py -> configuration file that holds the API key
├── logger.py -> logging configuration file
├── scanner.py -> main logic for scanning files
├── logs
│    └── virus_scanner.log
├── requirements.txt
└── .env (create this file with your API key)
````

---

## Notes
- The API key is stored in a ```.env``` file.
- The log file is saved in the same directory as the script on ```logs/virus_scanner.log```.
- The script will scan for new files in the directory it is run in ```downloads_path = Path.home() / "Downloads"```.