# Cell 1: Import Required Libraries
import os
import csv
import requests
import time
from pathlib import Path
from datetime import datetime

# Cell 2: VirusTotal API Configuration
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"
VT_API_URL = "https://www.virustotal.com/api/v3/files/"

# Cell 3: Function to Query VirusTotal
def get_vt_hashes(md5_hash):
    """
    Query VirusTotal API to get SHA1 and SHA256 for a given MD5 hash.
    Returns a dict with sha1 and sha256, or None if not found.
    """
    headers = {
        "x-apikey": VT_API_KEY
    }
    
    try:
        response = requests.get(f"{VT_API_URL}{md5_hash}", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            return {
                'sha1': attributes.get('sha1', ''),
                'sha256': attributes.get('sha256', '')
            }
        elif response.status_code == 404:
            print(f"MD5 {md5_hash} not found in VirusTotal")
            return None
        else:
            print(f"VirusTotal API error for {md5_hash}: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"Error querying VirusTotal for {md5_hash}: {e}")
        return None
    
    # Rate limiting: VirusTotal free tier allows 4 requests per minute
    time.sleep(15)  # 15 seconds between requests = 4 per minute

# Cell 4: Function to Process Mandiant CSV Files
def process_mandiant_csv(file_path):
    """
    Process a Mandiant CSV file and extract IOCs.
    Returns a list of IOC dictionaries.
    """
    iocs = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                indicator_value = row.get('Indicator Value', '').strip()
                indicator_type = row.get('Indicator Type', '').strip()
                
                if not indicator_value or not indicator_type:
                    continue
                
                # Base IOC entry
                ioc_entry = {
                    'TLP:': 'TLP: AMBER+STRICT',
                    'Classification:': 'UNCLASSIFIED',
                    'IOC': indicator_value,
                    'Association:': '',
                    'Type:': indicator_type,
                    'Note:': '',
                    'Source:': os.path.basename(file_path),
                    'Date:': datetime.now().strftime('%Y-%m-%d')
                }
                
                iocs.append(ioc_entry)
                
                # If it's an MD5, query VirusTotal for SHA1 and SHA256
                if indicator_type.lower() == 'md5' or 'md5' in indicator_type.lower():
                    print(f"Processing MD5: {indicator_value}")
                    vt_data = get_vt_hashes(indicator_value)
                    
                    if vt_data:
                        # Add SHA1 entry
                        if vt_data.get('sha1'):
                            sha1_entry = ioc_entry.copy()
                            sha1_entry['IOC'] = vt_data['sha1']
                            sha1_entry['Type:'] = 'SHA1'
                            sha1_entry['Association:'] = ''
                            iocs.append(sha1_entry)
                        
                        # Add SHA256 entry
                        if vt_data.get('sha256'):
                            sha256_entry = ioc_entry.copy()
                            sha256_entry['IOC'] = vt_data['sha256']
                            sha256_entry['Type:'] = 'SHA256'
                            sha256_entry['Association:'] = ''
                            iocs.append(sha256_entry)
    
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    
    return iocs

# Cell 4b: Function to Process CrowdStrike CSV Files
def process_crowdstrike_csv(file_path):
    """
    Process a CrowdStrike CSV file and extract IOCs.
    Returns a list of IOC dictionaries.
    """
    iocs = []
    
    # Mapping of CrowdStrike types to standardized types
    type_mapping = {
        'domain': 'DOMAIN',
        'ip_address': 'IPV4',
        'url': 'URL',
        'hash_sha1': 'SHA1',
        'hash_md5': 'MD5',
        'hash_sha256': 'SHA256',
        'email': 'EMAIL'
    }
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            # Debug: Print column headers
            print(f"  CrowdStrike column headers found: {reader.fieldnames}")
            
            row_count = 0
            for row in reader:
                row_count += 1
                
                # Try different case variations for column names
                indicator_value = (row.get('indicator', '') or row.get('Indicator', '') or 
                                 row.get('INDICATOR', '')).strip()
                indicator_type = (row.get('type', '') or row.get('Type', '') or 
                                row.get('TYPE', '')).strip()
                
                # Debug: Print first few rows data
                if row_count <= 3:
                    print(f"  Row {row_count} - Indicator: '{indicator_value}', type: '{indicator_type}'")
                
                if not indicator_value or not indicator_type:
                    if row_count <= 3:
                        print(f"  Row {row_count} - SKIPPED (missing indicator or type)")
                    continue
                
                # Convert CrowdStrike type to standardized type
                standardized_type = type_mapping.get(indicator_type.lower(), indicator_type.upper())
                
                # Base IOC entry
                ioc_entry = {
                    'TLP:': 'TLP: AMBER+STRICT',
                    'Classification:': 'UNCLASSIFIED',
                    'IOC': indicator_value,
                    'Association:': '',
                    'Type:': standardized_type,
                    'Note:': '',
                    'Source:': os.path.basename(file_path),
                    'Date:': datetime.now().strftime('%Y-%m-%d')
                }
                
                iocs.append(ioc_entry)
            
            print(f"  Total rows processed: {row_count}, IOCs extracted: {len(iocs)}")
    
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    
    return iocs

# Cell 5: Main Function to Compile All IOCs
def compile_iocs(folder_path, output_file):
    """
    Main function to compile all IOCs from CSV files in a folder.
    """
    folder = Path(folder_path)
    all_iocs = []
    
    # Find all CSV files matching Mandiant format (25-XXXXXXXX)
    mandiant_files = list(folder.glob("25-*.csv"))
    
    # Find all CrowdStrike CSV files (CSA-XXXXXX or CSIT-XXXXX)
    csa_files = list(folder.glob("CSA-*.csv"))
    csit_files = list(folder.glob("CSIT-*.csv"))
    crowdstrike_files = csa_files + csit_files
    
    total_files = len(mandiant_files) + len(crowdstrike_files)
    
    if total_files == 0:
        print(f"No IOC CSV files found in {folder_path}")
        return
    
    print(f"Found {len(mandiant_files)} Mandiant file(s) and {len(crowdstrike_files)} CrowdStrike file(s)")
    
    # Process Mandiant CSV files
    for csv_file in mandiant_files:
        print(f"\nProcessing Mandiant file: {csv_file.name}")
        iocs = process_mandiant_csv(csv_file)
        all_iocs.extend(iocs)
        print(f"Extracted {len(iocs)} IOCs from {csv_file.name}")
    
    # Process CrowdStrike CSV files
    for csv_file in crowdstrike_files:
        print(f"\nProcessing CrowdStrike file: {csv_file.name}")
        iocs = process_crowdstrike_csv(csv_file)
        all_iocs.extend(iocs)
        print(f"Extracted {len(iocs)} IOCs from {csv_file.name}")
    
    # Write compiled IOCs to output file
    if all_iocs:
        fieldnames = ['TLP:', 'Classification:', 'IOC', 'Association:', 'Type:', 'Note:', 'Source:', 'Date:']
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_iocs)
        
        print(f"\n✓ Successfully compiled {len(all_iocs)} IOCs to {output_file}")
    else:
        print("\nNo IOCs found to compile")

# Cell 6: Configuration and Execution
if __name__ == "__main__":
    # Configuration
    IOC_FOLDER = "./ioc_folder"  # Change this to your IOC folder path
    OUTPUT_FILE = "compiled_iocs.csv"
    
    # Validate VirusTotal API key is set
    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        print("⚠ WARNING: Please set your VirusTotal API key in the VT_API_KEY variable")
        print("You can get a free API key at: https://www.virustotal.com/gui/join-us")
    
    # Run the compiler
    compile_iocs(IOC_FOLDER, OUTPUT_FILE)