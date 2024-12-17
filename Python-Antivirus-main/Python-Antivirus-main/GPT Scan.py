import requests
import hashlib
import time
from tkinter import Tk
from tkinter.filedialog import askopenfilename
import json

# Replace with your actual API key
API_KEY = "b50bb2a6ea26edf717c86cd35f927d9c157a92de20bb7ae986be917d4796a59c"
VT_FILE_SCAN_URL = "https://www.virustotal.com/api/v3/files"

def get_file_hash(file_path):
    """Calculate SHA256 hash of the file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error calculating hash: {e}")
        return None

def check_file_status(file_hash):
    """Check the status of a file using its SHA256 hash."""
    headers = {"x-apikey": API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        print("File already scanned. Retrieving report...")
        return response.json()
    elif response.status_code == 404:
        print("File not found in VirusTotal's database.")
        return None
    else:
        print(f"Error checking file status: {response.status_code}, {response.text}")
        return None

def upload_file_to_virustotal(file_path):
    """Upload a file to VirusTotal for scanning."""
    headers = {"x-apikey": API_KEY}
    with open(file_path, "rb") as file:
        files = {"file": file}
        print("Uploading file to VirusTotal...")
        response = requests.post(VT_FILE_SCAN_URL, headers=headers, files=files)
    
    if response.status_code == 200:
        file_id = response.json()["data"]["id"]
        print("File uploaded successfully. Waiting for scan to complete...")
        return file_id
    else:
        print(f"Error uploading file: {response.status_code}, {response.text}")
        return None

def wait_for_scan(file_id):
    """Wait for the scan report to become available."""
    headers = {"x-apikey": API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{file_id}"  # Correct URL for fetching report
    
    for _ in range(20):  # Poll for 5 minutes (20 tries, 15 seconds each)
        print("Checking scan status...")
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            print("Scan complete!")
            return response.json()
        elif response.status_code == 404:
            print("Scan not ready yet. Waiting for 15 seconds...")
            time.sleep(15)
        else:
            print(f"Error fetching report: {response.status_code}, {response.text}")
            return None
    print("Scan timed out. Please try again later.")
    return None

def display_report(report):
    """Display the VirusTotal scan report."""
    print("\n--- Scan Report ---")
    stats = report["data"]["attributes"]["last_analysis_stats"]
    print(f"Malicious: {stats['malicious']}")
    print(f"Suspicious: {stats['suspicious']}")
    print(f"Harmless: {stats['harmless']}")
    print(f"Undetected: {stats['undetected']}")
    
    if stats["malicious"] > 0:
        print("WARNING: The file is flagged as MALICIOUS!")
        
        # Display the detailed results of antivirus engines that flagged the file
        last_analysis = report["data"]["attributes"]["last_analysis_results"]
        print("\n--- Detailed Analysis ---")
        for engine, result in last_analysis.items():
            print(f"Engine: {result['engine_name']}, Detection: {result['category']}")
    else:
        print("The file appears to be safe.")

def scan_file_with_virustotal(file_path):
    """Orchestrates the VirusTotal scanning process."""
    file_hash = get_file_hash(file_path)
    if not file_hash:
        return
    
    print(f"File: {file_path}")
    print(f"SHA256 Hash: {file_hash}")
    
    # Check if the file has already been scanned
    report = check_file_status(file_hash)
    
    if report:
        display_report(report)  # Display the existing report from VirusTotal
    else:
        file_id = upload_file_to_virustotal(file_path)
        if file_id:
            report = wait_for_scan(file_id)
            if report:
                display_report(report)  # Display the new scan result

def main():
    """Main function to select and scan a file."""
    Tk().withdraw()  # Hide root window
    print("Select a file to scan:")
    file_path = askopenfilename()
    
    if file_path:
        scan_file_with_virustotal(file_path)
    else:
        print("No file selected. Exiting.")

if __name__ == "__main__":
    main()

