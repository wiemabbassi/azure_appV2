# ============================
# OTX Data Retrieval
# ============================
import json     
import requests
import re
import hashlib
import numpy as np
from iocs_extraction import remove_empty_fields
import logging # Add logging import

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def fetch_otx_data(ioc_type, ioc_value):
    """
    Query AlienVault OTX API for essential threat intelligence data.
    :param ioc_type: Type of IOC (e.g., 'IPv4', 'domain', 'URL', 'file').
    :param ioc_value: Value of the IOC (e.g., '185.220.101.24', 'example.com').
    :return: Dictionary containing 'data', 'classification', and 'score', or None if error.
    """
    # Define the API key and base URL for OTX
    API_KEY = "68daf6252b0b16e35bdf2e28e08adf2be5f7b1f65e959d90f190c010dc794815"  # Replace with your actual OTX API key
    BASE_URL = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc_value}/general"

    # Set headers with the API key
    headers = {"X-OTX-API-KEY": API_KEY}

    try:
        # Send the GET request
        response = requests.get(BASE_URL, headers=headers)
        if response.status_code == 200:
            data = response.json()

            # Check if the data is empty or irrelevant
            if not data or not any(data.values()):
                logging.info(f"No substantial data found in OTX for {ioc_type} {ioc_value}.")
                # Return unknown with low score if no data
                return {"data": {}, "classification": "unknown", "score": 0.1}

            # Extract relevant fields
            extracted_data = {
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "tags": data.get("tags", []),
                "targeted_countries": data.get("targeted_countries", []),
                "malware_families": data.get("malware_families", []),
                "asn": data.get("asn"),
                "geolocation": {
                    "country": data.get("country_name"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                },
                "validation_status": data.get("validation", {}).get("message"),
                "pulse_info": [
                    {
                        "name": pulse.get("name"),
                        "description": pulse.get("description"),
                        "tags": pulse.get("tags", []),
                    }
                    for pulse in data.get("pulse_info", {}).get("pulses", [])
                ],
            }

            # Remove empty fields
            cleaned_data = remove_empty_fields(extracted_data)

            # --- Classification and Scoring Logic ---
            classification = "unknown"
            score = 0.1  # Base score for unknown
            malicious_keywords = ["malware", "phishing", "c2", "exploit", "trojan", "ransomware", "compromised", "botnet"]
            is_malicious = False
            malicious_pulses_count = 0
            malicious_tags_count = 0

            # 1. Check Pulses
            if cleaned_data.get("pulse_info"):
                for pulse in cleaned_data["pulse_info"]:
                    pulse_text = f"{pulse.get('name', '').lower()} {pulse.get('description', '').lower()} {' '.join(pulse.get('tags', [])).lower()}"
                    if any(keyword in pulse_text for keyword in malicious_keywords):
                        is_malicious = True
                        malicious_pulses_count += 1
                        logging.debug(f"Malicious keyword found in pulse: {pulse.get('name')}")


            # 2. Check Tags
            if cleaned_data.get("tags"):
                 if any(keyword in tag.lower() for tag in cleaned_data["tags"] for keyword in malicious_keywords):
                     is_malicious = True
                     # Count specific malicious tags
                     for tag in cleaned_data["tags"]:
                         if any(keyword in tag.lower() for keyword in malicious_keywords):
                             malicious_tags_count += 1
                     logging.debug(f"Malicious keyword found in general tags.")


            # 3. Check Malware Families
            if cleaned_data.get("malware_families"):
                is_malicious = True
                malicious_tags_count += len(cleaned_data["malware_families"]) # Count families as malicious indicators
                logging.debug(f"Malware families found: {cleaned_data['malware_families']}")

            # Determine final classification and score
            if is_malicious:
                classification = "malicious"
                score = 0.7  # Base score for malicious
                score += min(malicious_pulses_count, 2) * 0.1  # Add score for pulses
                score += min(malicious_tags_count, 3) * 0.05   # Add score for tags/families
                score = min(score, 0.95)  # Cap score
            elif cleaned_data.get("pulse_info") or cleaned_data.get("tags") or cleaned_data.get("malware_families"):
                # If not clearly malicious but has some info, classify as suspicious
                classification = "suspicious"
                score = 0.4  # Base score for suspicious
                score += min(len(cleaned_data.get("pulse_info", [])), 2) * 0.05 # Add small score for any pulse
                score += min(len(cleaned_data.get("tags", [])), 5) * 0.02      # Add small score for any tag
                score = min(score, 0.6) # Cap score
            # else: classification remains 'unknown', score remains 0.1

            logging.info(f"OTX classification for {ioc_value}: {classification} (Score: {score:.2f})")

            return {"data": cleaned_data, "classification": classification, "score": score}

        elif response.status_code == 404:
             logging.info(f"OTX indicator not found for {ioc_type} {ioc_value}. Status code: 404")
             return {"data": {}, "classification": "unknown", "score": 0.1} # Not found is unknown
        else:
            logging.error(f"Error querying OTX for {ioc_type} {ioc_value}: {response.status_code} - {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error querying OTX for {ioc_type} {ioc_value}: {str(e)}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error processing OTX data for {ioc_type} {ioc_value}: {str(e)}")
        return None