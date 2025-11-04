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
    Output format: MD5, Hash Type, Hash Value columns
    
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
                    results.append({"MD5": md5_hash, "Hash Type": "sha1", "Hash Value": ""})
                    results.append({"MD5": md5_hash, "Hash Type": "sha256", "Hash Value": ""})
                    continue
                
                print(f"Processing {processed_hashes}/{total_hashes}: {md5_hash}")
                
                # Get hashes from VirusTotal
                vt_result = get_hashes_from_virustotal(api_key, md5_hash)
                
                # Add results with MD5 in first column, hash type in second, hash value in third
                results.append({"MD5": md5_hash, "Hash Type": "sha1", "Hash Value": vt_result["sha1"]})
                results.append({"MD5": md5_hash, "Hash Type": "sha256", "Hash Value": vt_result["sha256"]})
                
                # Respect VirusTotal API rate limits (4 requests/minute for public API)
                if vt_result["error"] != "API rate limit exceeded" and processed_hashes < total_hashes:
                    time.sleep(15)  # 15 seconds between requests
                elif vt_result["error"] == "API rate limit exceeded":
                    print("Rate limit reached. Waiting 60 seconds...")
                    time.sleep(60)
        
        # Write results to CSV
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["MD5", "Hash Type", "Hash Value"])
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
hash_column = "MD5"  # Column containing MD5 hashes

# Run the process
result = process_md5_hashes(api_key, input_file, output_file=output_file, hash_column=hash_column)
print(result)