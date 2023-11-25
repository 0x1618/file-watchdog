import hashlib
import time

def hash_file(file_path):
    """Calculate the hash of a file using the SHA-256 algorithm.

    Args:
        file_path (str): The path to the file.

    Returns:
        str: The hexadecimal representation of the file's SHA-256 hash.
    """

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    
    return sha256.hexdigest()

def monitor_files(file_paths, callback_function):
    """Monitor files for changes and execute a callback function upon detection of a change.

    Args:
        file_paths (list): List of file paths to monitor.
        callback_function (function): The callback function to execute when a file change is detected.
    """

    file_hashes = {file_path: hash_file(file_path) for file_path in file_paths}

    while True:
        time.sleep(1)

        for file_path in file_paths:
            current_hash = hash_file(file_path)
            if current_hash != file_hashes[file_path]:
                print(f"Change detected in file: {file_path}")
                callback_function(file_path)
                file_hashes[file_path] = current_hash

def my_callback(file_path):
    print(f"Callback executed for file: {file_path}")

if __name__ == "__main__":
    files_to_monitor = ["file1.txt", "file2.txt", "file3.txt"]

    monitor_files(files_to_monitor, my_callback)