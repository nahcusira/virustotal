import requests

def check_hash(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        malicious = data['data']['attributes']['last_analysis_stats']['malicious']
        suspicious = data['data']['attributes']['last_analysis_stats']['suspicious']
        
        if malicious == 0 and suspicious == 0:
            return f"The hash {file_hash} is clean!"
        else:
            return f"The hash {file_hash} is not clean. Malicious: {malicious}, Suspicious: {suspicious}"
    else:
        return f"Error: Unable to fetch details for hash {file_hash}. HTTP Status: {response.status_code}"

def process_hashes(api_key, file_path):
    try:
        with open(file_path, 'r') as file:
            hashes = [line.strip() for line in file.readlines()]
        
        for file_hash in hashes:
            if file_hash:  # Skip empty lines
                print(check_hash(api_key, file_hash))
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    # Replace 'your_api_key_here' with your actual VirusTotal API key
    api_key = "4d7d14cf872549c99bcb18aaea0de18bac42888a646b52e61c69aac60d46e3d0"
    
    # Input the path to the text file containing hashes
    file_path = input("Enter the path to the text file with hashes: ").strip()
    
    process_hashes(api_key, file_path)
