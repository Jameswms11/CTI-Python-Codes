import csv
import requests
import time
import os
from datetime import datetime


def get_hashes_from_virustotal(api_key, md5_hash):
    """
    Query VirusTotal API to get SHA1 and SHA256 hashes associated with an MD5 hash
    
    Args:
        api_key (str): VirusTotal API key
        md5_hash (str): MD5 hash to look up
        
    Returns:
        dict: SHA1 and SHA256 hashes and any error message
    """
    base_url = "https://www.virustotal.com/api/v3/files/"
    headers = {"x-apikey": api_key}
    result = {
        "md5": md5_hash,
        "sha1": "",
        "sha256": "",
        "first_seen": "",
        "last_analysis_date": "",
        "detection_ratio": "",
        "names": "",
        "error": ""
    }
    
    try:
        # Query VirusTotal API
        response = requests.get(base_url + md5_hash, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            
            # Extract hashes
            result["sha1"] = attributes.get("sha1", "")
            result["sha256"] = attributes.get("sha256", "")
            
            # Extract additional useful information
            # First seen date
            if "first_submission_date" in attributes:
                timestamp = attributes["first_submission_date"]
                result["first_seen"] = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            # Last analysis date
            if "last_analysis_date" in attributes:
                timestamp = attributes["last_analysis_date"]
                result["last_analysis_date"] = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            # Detection ratio
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            if total > 0:
                result["detection_ratio"] = f"{malicious + suspicious}/{total}"
            
            # File names (if available)
            names = attributes.get("names", [])
            if names:
                result["names"] = "; ".join(names[:5])  # Limit to first 5 names
                
        elif response.status_code == 404:
            result["error"] = "Hash not found in VirusTotal database"
        elif response.status_code == 429:
            result["error"] = "API rate limit exceeded"
        else:
            result["error"] = f"API error: {response.status_code}"
            
    except Exception as e:
        result["error"] = f"Request error: {str(e)}"
        
    return result


def process_md5_hashes(api_key, input_file, output_file=None, hash_column="md5"):
    """
    Process a CSV file containing MD5 hashes to retrieve SHA1 and SHA256 hashes
    Output format: Two columns - "Hash Type" and "Hash Value"
    
    Args:
        api_key (str): VirusTotal API key
        input_file (str): Path to input CSV file with MD5 hashes
        output_file (str, optional): Path to output CSV file
        hash_column (str): Column name containing MD5 hashes
    
    Returns:
        str: Status message
    """
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"hash_results_{timestamp}.csv"
    
    results = []
    total_hashes = 0
    processed_hashes = 0
    
    try:
        # Count total hashes for progress reporting
        with open(input_file, 'r') as f:
            reader = csv.DictReader(f)
            if hash_column not in reader.fieldnames:
                return f"Error: Column '{hash_column}' not found in CSV. Available columns: {', '.join(reader.fieldnames)}"
            total_hashes = sum(1 for _ in reader)
        
        # Process each hash
        with open(input_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                processed_hashes += 1
                md5_hash = row[hash_column].strip().lower()
                
                # Skip empty or invalid hashes
                if not md5_hash or len(md5_hash) != 32 or not all(c in '0123456789abcdef' for c in md5_hash):
                    results.append({"Hash Type": "MD5", "Hash Value": md5_hash})
                    results.append({"Hash Type": "SHA1", "Hash Value": ""})
                    results.append({"Hash Type": "SHA256", "Hash Value": ""})
                    results.append({"Hash Type": "Error", "Hash Value": "Invalid MD5 hash format"})
                    results.append({"Hash Type": "", "Hash Value": ""})  # Blank row separator
                    continue
                
                print(f"Processing {processed_hashes}/{total_hashes}: {md5_hash}")
                
                # Get hashes from VirusTotal
                vt_result = get_hashes_from_virustotal(api_key, md5_hash)
                
                # Add results in transposed format (each hash type on its own row)
                results.append({"Hash Type": "MD5", "Hash Value": md5_hash})
                results.append({"Hash Type": "SHA1", "Hash Value": vt_result["sha1"]})
                results.append({"Hash Type": "SHA256", "Hash Value": vt_result["sha256"]})
                
                # Add additional information
                if vt_result["first_seen"]:
                    results.append({"Hash Type": "First Seen", "Hash Value": vt_result["first_seen"]})
                if vt_result["last_analysis_date"]:
                    results.append({"Hash Type": "Last Analysis", "Hash Value": vt_result["last_analysis_date"]})
                if vt_result["detection_ratio"]:
                    results.append({"Hash Type": "Detection Ratio", "Hash Value": vt_result["detection_ratio"]})
                if vt_result["names"]:
                    results.append({"Hash Type": "File Names", "Hash Value": vt_result["names"]})
                if vt_result["error"]:
                    results.append({"Hash Type": "Error", "Hash Value": vt_result["error"]})
                
                # Add blank row as separator between different hash lookups
                results.append({"Hash Type": "", "Hash Value": ""})
                
                # Respect VirusTotal API rate limits (4 requests/minute for public API)
                if vt_result["error"] != "API rate limit exceeded" and processed_hashes < total_hashes:
                    time.sleep(15)  # 15 seconds between requests
                elif vt_result["error"] == "API rate limit exceeded":
                    print("Rate limit reached. Waiting 60 seconds...")
                    time.sleep(60)
        
        # Write results to CSV
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["Hash Type", "Hash Value"])
            writer.writeheader()
            writer.writerows(results)
        
        return f"Processing complete. Results saved to {output_file}"
        
    except FileNotFoundError:
        return f"Error: File '{input_file}' not found"
    except Exception as e:
        return f"Error: {str(e)}"


# Set your parameters here
api_key = "f611a659631959cbb48e44690597093b32d525167ba58c773ef72a8e4a307eed"  # Replace with your actual API key
input_file = "daily_MD5s.csv"   # Replace with your CSV file name
output_file = "MD5_results.csv"  # Custom output file name
hash_column = "MD5"                  # Column containing MD5 hashes

# Run the process
result = process_md5_hashes(api_key, input_file, output_file=output_file, hash_column=hash_column)
print(result)