import hashlib
import os

import requests
import logging
from config import api_key
from file import is_heavy_download

headers = {"x-apikey": api_key}

def calculate_hash(file_path):
    if is_heavy_download(file_path):
        logging.error("File is too heavy")
        return None
    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        return None

    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def consult_hash(hash_file):
    url = f"https://www.virustotal.com/api/v3/files/{hash_file}"

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()

            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            return {
                "status": response.status_code,
                "found": True,
                "stats": stats
            }

        if response.status_code == 404:
            return {
                "status": response.status_code,
                "found": False,
                "stats": None
            }

        logging.error(f"HTTP error: {response.status_code} | {response.text}")
        return {
            "status": response.status_code,
            "error": f"http_error_{response.status_code}"
        }

    except requests.RequestException as e:
        logging.error(f"Error consulting hash: {e}")
        return {
            "status": False,
            "error": "request_failed"
        }

def upload_file(file_path):
    url = "https://www.virustotal.com/api/v3/files"

    try:
        with open(file_path, "rb") as file:
            files = {"file": file}
            response = requests.post(url, headers=headers, files=files)
        return {
            "status_code": response.status_code,
            "data": response.json()
        }

    except Exception as e:
        logging.error(f"Error uploading file: {e}")
        return None

def scan_file(path):
    hash_file = calculate_hash(path)
    result = consult_hash(hash_file)

    if isinstance(result, dict) and result.get("error"):
        logging.error(f"Error: {result.get('error')}")
        return result

    if result is None:
        logging.info("File not found in VirusTotal")
        logging.info("Uploading file to VirusTotal")
        status = upload_file(path)
        logging.info(f"Upload status: {status}")
        return {"upload_status": status}

    if result.get("status") == 200 and result.get("found"):
        logging.info(f"Result: {result}")
    else:
        logging.error(f"Result: {result}")

    return result
