import re
from iocs_extraction import remove_empty_fields, is_valid_md5, is_valid_sha256, convert_md5_to_sha256

import requests
import os  # Added for environment variables
from dotenv import load_dotenv # Added to load .env
import pprint # Added for pretty printing
import logging # Add logging import

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables
load_dotenv()
MALTIVERSE_API_KEY = os.getenv("MALTIVERSE_API_KEY")

def fetch_maltiverse_data(ioc_type, ioc_value):
    """
    Query Maltiverse API for essential threat intelligence data.
    :param ioc_type: Type of IOC (e.g., 'ip', 'domain', 'url', 'hostname', 'sample').
    :param ioc_value: Value of the IOC (e.g., '185.220.101.24', 'malware-hosting.com').
    :return: Dictionary containing 'data', 'classification', and 'score', or None if error.
    """
    # Map IOC types to Maltiverse endpoints
    endpoint_map = {
        "ip": "ip",
        "domain": "hostname",
        "url": "url",
        "hostname": "hostname",
        "sample": "sample",
    }

    # Construct the endpoint URL
    if ioc_type not in endpoint_map:
        logging.warning(f"Unsupported IOC type for Maltiverse: {ioc_type}")
        return None

    # Handle MD5-to-SHA256 conversion for samples if needed (Maltiverse prefers SHA256)
    effective_ioc_value = ioc_value
    if endpoint_map[ioc_type] == "sample":
        if is_valid_md5(ioc_value):
            logging.info(f"Converting MD5 hash to SHA256 for Maltiverse: {ioc_value}")
            effective_ioc_value = convert_md5_to_sha256(ioc_value)
            if not effective_ioc_value:
                 logging.warning(f"Failed to convert MD5 {ioc_value} to SHA256. Skipping Maltiverse lookup.")
                 return None
        elif not is_valid_sha256(ioc_value):
            logging.warning(f"Invalid hash format for Maltiverse sample: {ioc_value}. Skipping...")
            return None

    endpoint = endpoint_map[ioc_type]
    url = f"https://api.maltiverse.com/{endpoint}/{effective_ioc_value}"

    headers = {}
    if MALTIVERSE_API_KEY:
        headers["Authorization"] = f"Bearer {MALTIVERSE_API_KEY}"
    else:
        logging.warning("MALTIVERSE_API_KEY not found in environment variables. Making unauthenticated Maltiverse request.")

    try:
        # Send the GET request with headers
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()

            # Check if the data is empty or irrelevant
            if not data or not any(value for key, value in data.items() if key != 'address'): # Check more robustly for empty data
                logging.info(f"No substantial data found in Maltiverse for {ioc_type} {ioc_value}.")
                return {"data": {}, "classification": "unknown", "score": 0.1}

            # Extract relevant fields
            blacklist_status = None
            if isinstance(data.get("blacklist"), dict):
                blacklist_status = data.get("blacklist", {}).get("status")
            elif isinstance(data.get("blacklist"), list):
                blacklist_status = [item.get("status") for item in data.get("blacklist")]

            extracted_data = {
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "tags": data.get("tag", []),
                "classification": data.get("classification"),
                "blacklist_status": blacklist_status,
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_seen"),
                "http_status": data.get("http_status") if ioc_type == "url" else None,
                "malware_family": data.get("malware_family") if ioc_type == "sample" else None,
                # Additional fields for IPs
                "asn": data.get("asn") if ioc_type == "ip" else None,
                "country": data.get("country") if ioc_type == "ip" else None,
                "region": data.get("region") if ioc_type == "ip" else None,
                "city": data.get("city") if ioc_type == "ip" else None,
                # Additional fields for file hashes
                "malware_type": data.get("malware_type") if ioc_type == "sample" else None,
                "behaviors": data.get("behaviors") if ioc_type == "sample" else None,
                # Temporal fields
                "creation_date": data.get("creation_date"),
                "modification_date": data.get("modification_date"),
                # Related entities
                "related_ips": data.get("related_ips", []) if ioc_type in ["domain", "hostname"] else [],
                "related_domains": data.get("related_domains", []) if ioc_type in ["ip", "hostname"] else [],
                "related_urls": data.get("related_urls", []) if ioc_type in ["domain", "hostname"] else [],
                # Contextual fields
                "targeted_countries": data.get("targeted_countries", []),
                "industries": data.get("industries", []),
                "attack_ids": data.get("attack_ids", []),
                # Metadata fields
                "source": "Maltiverse",
                "confidence_score": data.get("confidence_score"),
                "reference_links": data.get("reference_links", []),
            }

            # Remove empty fields
            cleaned_data = remove_empty_fields(extracted_data)

            # --- Classification and Scoring Logic ---
            classification = "unknown" # Default
            score = 0.1 # Default
            malicious_keywords = ["malware", "phishing", "c2", "exploit", "trojan", "ransomware", "compromised", "botnet", "spam"] # Added spam

            # 1. Use Maltiverse's classification if available
            api_classification = data.get("classification", "").lower()
            if api_classification in ["malicious", "suspicious", "neutral", "whitelisted"]:
                classification = api_classification
                if classification == "malicious":
                    score = 0.8
                elif classification == "suspicious":
                    score = 0.5
                elif classification == "neutral":
                    score = 0.2
                    classification = "unknown" # Treat neutral as unknown for our purpose
                elif classification == "whitelisted":
                    score = 0.1
                    classification = "benign" # Treat whitelisted as benign
            else:
                # If no API classification, derive from other fields
                is_blacklisted = False
                blacklist_count = 0
                if "blacklist" in data and isinstance(data["blacklist"], list):
                    for item in data["blacklist"]:
                        if isinstance(item, dict) and item.get("first_seen") and item.get("last_seen") and item.get("description"):
                           blacklist_count += 1
                           is_blacklisted = True

                has_malicious_tags = False
                malicious_tags_count = 0
                if "tag" in data and isinstance(data["tag"], list):
                    for tag in data["tag"]:
                        if any(keyword in tag.lower() for keyword in malicious_keywords):
                            has_malicious_tags = True
                            malicious_tags_count +=1

                if is_blacklisted:
                    classification = "malicious"
                    score = 0.7 + min(blacklist_count, 3) * 0.05 # Increase score slightly with count
                elif has_malicious_tags:
                    classification = "suspicious"
                    score = 0.4 + min(malicious_tags_count, 4) * 0.05 # Lower base, increase with tags
                # else remains unknown / 0.1

            # Refine score based on blacklist count if classification was initially from API
            if api_classification == "malicious" and "blacklist" in data and isinstance(data["blacklist"], list):
                 blacklist_count = sum(1 for item in data["blacklist"] if isinstance(item, dict) and item.get("first_seen"))
                 score += min(blacklist_count, 5) * 0.03 # Slightly boost score based on blacklist count

            # Refine score based on tags
            malicious_tags_count = 0
            if "tag" in data and isinstance(data["tag"], list):
                 malicious_tags_count = sum(1 for tag in data["tag"] if any(keyword in tag.lower() for keyword in malicious_keywords))
                 if classification == "malicious":
                      score += min(malicious_tags_count, 5) * 0.02
                 elif classification == "suspicious":
                      score += min(malicious_tags_count, 5) * 0.04

            # Cap the score
            score = min(score, 0.98) # Cap slightly higher than OTX potential max
            score = max(score, 0.05) # Ensure a minimum floor score

            logging.info(f"Maltiverse classification for {ioc_value}: {classification} (Score: {score:.2f})")
            return {"data": cleaned_data, "classification": classification, "score": score}

        elif response.status_code == 404:
            logging.info(f"Maltiverse indicator not found for {ioc_type} {ioc_value}. Status code: 404")
            return {"data": {}, "classification": "unknown", "score": 0.1}
        else:
            logging.error(f"Error querying Maltiverse for {ioc_type} {ioc_value}: {response.status_code} - {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error querying Maltiverse for {ioc_type} {ioc_value}: {str(e)}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error processing Maltiverse data for {ioc_type} {ioc_value}: {str(e)}")
        return None

# Main execution block for testing
if __name__ == "__main__":
    # Example IOC to test (you can change this)
    test_ioc_type = "ip"
    test_ioc_value = "8.8.8.8"

    print(f"\nTesting Maltiverse fetch for {test_ioc_type}: {test_ioc_value}")
    
    if not MALTIVERSE_API_KEY:
        print("Error: MALTIVERSE_API_KEY not found in environment. Please set it in .env")
    else:
        try:
            result = fetch_maltiverse_data(test_ioc_type, test_ioc_value)
            print("\nMaltiverse API Result:")
            if result:
                pprint.pprint(result)
            else:
                print("No data retrieved or an error occurred (check logs above).")
        except Exception as e:
            print(f"An error occurred during the test: {e}")