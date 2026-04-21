import os

def finished_downloading(file_path):
    if os.path.exists(file_path):
        return True
    return False

def is_downloading(file_path):
    if os.path.exists(file_path + ".download") or os.path.exists(file_path + ".part") or os.path.exists(file_path + ".tmp"):
        return True
    return False

def get_file_size(file_path):
    return os.path.getsize(file_path)

def is_heavy_download(file_path):
    if get_file_size(file_path) > 650 * 1024 * 1024:
        return True
    return False