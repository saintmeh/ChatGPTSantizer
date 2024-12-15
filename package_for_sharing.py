#!/usr/bin/env python3
import os
import re
import shutil
import sys
import zipfile
import stat

def is_config_or_source_file(file_name):
    """
    Determine if a file is likely a configuration or user source file.
    """
    extensions = ['.conf', '.json', '.yaml', '.yml', '.ini', '.sh', '.py', '.pl', '.rb', '.java', '.js', '.ts', '.c', '.cpp', '.h', '.html', '.css', '.xml', '.service', '.timer']
    return any(file_name.endswith(ext) for ext in extensions)

def cat_config_and_source_files(directory, log_file):
    """
    Recursively traverse a directory and cat configuration or source files, writing to a log file.

    Args:
        directory (str): The root directory to scan.
        log_file (str): The path to the log file.

    Returns:
        None
    """
    with open(log_file, 'w', encoding='utf-8') as log:
        for root, _, files in os.walk(directory):
            for file_name in files:
                if is_config_or_source_file(file_name):
                    file_path = os.path.join(root, file_name)
                    try:
                        log.write(f"\n### {os.path.abspath(file_path)} ###\n")
                        with open(file_path, 'r', encoding='utf-8') as f:
                            log.write(f.read())
                    except Exception as e:
                        log.write(f"Error reading {file_path}: {e}\n")
               
def save_tree_output(directory, tree_file):
    """
    Generate a tree-like structure of the directory and save to a file.

    Args:
        directory (str): The directory to scan.
        tree_file (str): The path to save the tree output.
    """
    try:
        with open(tree_file, 'w', encoding='utf-8') as tree:
            for root, dirs, files in os.walk(directory):
                level = root.replace(directory, '').count(os.sep)
                indent = ' ' * 4 * level
                tree.write(f"{indent}{os.path.basename(root)}/\n")
                sub_indent = ' ' * 4 * (level + 1)
                for f in files:
                    tree.write(f"{sub_indent}{f}\n")
    except Exception as e:
        print(f"Error generating tree output: {e}")
         
def redact_folders(directory, folder_name):
    """
    GETTING STARTED:
    1 run backup_configs.sh
    2 extract to folder
    3 run package_for_sharing.py <relative or absolute path to config folder>

    WHAT IT DOES:
    Recursively searches for and redacts all files in folders with the specified name
    by replacing them with blank files of the same name.

    Args:
        directory (str): The root directory to scan.
        folder_name (str): The name of the folder to redact.
    """
    if os.geteuid() != 0:
        print("Error: This script must be run as root (sudo).")
        sys.exit(1)

    print(f"Redacting all files in '{folder_name}' folders in the specified directory: {directory}")

    for root, dirs, files in os.walk(directory):
        if folder_name in dirs:
            folder_path = os.path.join(root, folder_name)
            try:
                # Replace all files in the folder with blank files
                for sub_root, _, sub_files in os.walk(folder_path):
                    for file_name in sub_files:
                        file_path = os.path.join(sub_root, file_name)
                        try:
                            # Ensure the file is writable by modifying permissions
                            os.chmod(file_path, stat.S_IWUSR)
                            
                            # Overwrite the file with a blank file
                            with open(file_path, 'w') as blank_file:
                                blank_file.write("")
                            print(f"Redacted file: {file_path}")
                        except Exception as e:
                            print(f"Error redacting file {file_path}: {e}")
            except Exception as e:
                print(f"Error processing folder {folder_path}: {e}")

def delete_folders(directory, folder_name):
    """
    Recursively search for and delete all folders with the specified name in the given directory.

    Args:
        directory (str): The root directory to scan.
        folder_name (str): The name of the folder to delete.
    """
    print(f"Deleting all '{folder_name}' folders in the specified directory: {directory}")

    for root, dirs, files in os.walk(directory):
        if folder_name in dirs:
            folder_path = os.path.join(root, folder_name)
            try:
                shutil.rmtree(folder_path)
                print(f"Deleted: {folder_path}")
            except Exception as e:
                print(f"Error deleting {folder_path}: {e}")

def delete_known_fat_folders_and_files(directory):
    """
    Recursively search for and delete known "fat" folders and files in the specified directory.
    """
    known_fat_folders_and_files = {
        "Porkbun DynDNS Lib": f"{directory}/usr/bin/porkBunDns/libs",
        "Porkbun DynDNS Jar": f"{directory}/usr/bin/porkBunDns/porkbun-ddns.jar",
        "Python virtual environments": "venv",
        "Git folders": ".git",
    }

    for name, path in known_fat_folders_and_files.items():
        absolute_path = os.path.abspath(path)
        if os.path.exists(absolute_path):
            try:
                if os.path.isdir(absolute_path):
                    shutil.rmtree(absolute_path)
                    print(f"Deleted folder: {name} ({absolute_path})")
                else:
                    os.remove(absolute_path)
                    print(f"Deleted file: {name} ({absolute_path})")
            except Exception as e:
                print(f"Error deleting {name} ({absolute_path}): {e}")
        else:
            print(f"{name} not found: {absolute_path}")

def search_sensitive_data(directory):
    """
    Search for sensitive data like API keys and passwords in the specified directory.

    Args:
        directory (str): The directory to scan.

    Returns:
        list: A list of sensitive data entries found.
    """
    patterns = {
        # JSON Patterns
        "JSON API Key": r"(?i)\"(apiKey|authToken|accessToken)\":\s*[\"']([A-Za-z0-9_\-]{16,})[\"']",
        "JSON AWS Access Key": r"(?i)\"awsAccessKeyId\":\s*[\"']([A-Za-z0-9]{16,20})[\"']",
        "JSON AWS Secret Key": r"(?i)\"awsSecretAccessKey\":\s*[\"']([A-Za-z0-9/+]{40})[\"']",
        "JSON Database Password": r"(?i)\"(dbPassword|databasePassword|dbPass)\":\s*[\"']([^\"']+)[\"']",
        "JSON JWT Secret": r"(?i)\"(jwtSecret|jwtKey)\":\s*[\"']([A-Za-z0-9_\-]{32,})[\"']",

        # XML Patterns
        "XML API Key": r"<(apiKey|authToken|accessToken)>\s*([A-Za-z0-9_\-]{16,})\s*</\1>",
        "XML Database Password": r"<(dbPassword|databasePassword|password)>\s*([^<]+)\s*</\1>",
        "XML AWS Access Key": r"<awsAccessKeyId>\s*([A-Za-z0-9]{16,20})\s*</awsAccessKeyId>",
        "XML AWS Secret Key": r"<awsSecretAccessKey>\s*([A-Za-z0-9/+]{40})\s*</awsAccessKey>",

        # Config File Patterns
        "Config API Key": r"(?i)(form_secret|registration_shared_secret|macaroon_secret_key|api_key|auth_token|access_token)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})[\"']?",
        "Config Database Password": r"(?i)(db_password|database_password|password)\s*[:=]\s*[\"']?([^\"'\n]+)[\"']?",
        "Config Bearer Token": r"(?i)(bearer_token|token)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{20,})[\"']?",
        "Config Env Password": r"(?i)(secret|password|api_key|token)_env\s*[:=]\s*[\"']?([^\s\"';]+)[\"']?",
        "Config AWS Access Key": r"(?i)aws_access_key_id\s*[:=]\s*[\"']?([A-Za-z0-9]{16,20})[\"']?",
        "Config AWS Secret Key": r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+]{40})[\"']?",
    }

    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            try:
                if not file.endswith(('.py', '.js', '.env', '.config', '.txt', '.json', '.yaml', '.yml')):
                    continue

                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.readlines()

                for i, line in enumerate(content, 1):
                    for label, pattern in patterns.items():
                        match = re.search(pattern, line)
                        if match:
                            results.append({
                                "type": label,
                                "file": file_path,
                                "line": i,
                                "content": line.strip()
                            })
            except Exception as e:
                print(f"Error reading {file}: {e}")

    if results:
        print(f"Found {len(results)} potential sensitive data entries:")
        for result in results:
            print(f"{result['type']} in {result['file']} on line {result['line']}:")
            print(f"  {result['content']}")
    else:
        print("No sensitive data found.")
    return results

def zip_directory(directory, output_filename):
    """
    Compress the given directory into a zip file.

    Args:
        directory (str): The directory to compress.
        output_filename (str): The name of the resulting zip file.
    """
    print(f"Zipping directory '{directory}' into '{output_filename}'...")
    try:
        with zipfile.ZipFile(output_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, start=directory)
                    zipf.write(file_path, arcname)
        print(f"Directory successfully zipped into '{output_filename}'.")
    except Exception as e:
        print(f"Error zipping directory: {e}")
        

if __name__ == "__main__":
    directory_to_scan = None
    if len(sys.argv) > 1:
        directory_to_scan = sys.argv[1]  # Get the first argument
        print(f"Using passed in directory: {directory_to_scan}")
    else:
    	directory_to_scan = input("Enter the directory path to scan: ").strip()

    if not directory_to_scan or directory_to_scan == "/":
        print("Error: Invalid directory path. Cannot proceed with root directory or blank input.")
        sys.exit(1)

    if os.path.isdir(directory_to_scan):
        log_file = "config_and_source_files.log"
        tree_file = "directory_tree.log"
        
        delete_known_fat_folders_and_files(directory_to_scan)
        delete_folders(directory_to_scan, 'venv')
        delete_folders(directory_to_scan, '.git')
        redact_folders(directory_to_scan, 'images')
        redact_folders(directory_to_scan, 'accounts')

        cat_config_and_source_files(directory_to_scan, log_file)
        save_tree_output(directory_to_scan, tree_file)

        results = search_sensitive_data(directory_to_scan)
        if results:
            print("Error: Cannot proceed with sensitive data.")
            sys.exit(2)
            
        zip_directory(directory_to_scan, "packageForSharing.zip")
    else:
        print("Invalid directory path.")
