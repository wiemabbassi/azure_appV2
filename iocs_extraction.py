import re
import requests
import hashlib
import numpy as np
from pymongo import MongoClient
import io
import sys  

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
# ============================
# Helper Functions for IOC Detection
# ============================
def remove_empty_fields(data):
    """
    Recursively remove empty fields (None, [], {}) from a dictionary or list.
    :param data: Dictionary or list to clean up
    :return: Cleaned-up dictionary or list
    """
    if isinstance(data, dict):
        return {
            k: remove_empty_fields(v)
            for k, v in data.items()
            if v not in [None, "", [], {}, "N/A"]
        }
    elif isinstance(data, list):
        return [remove_empty_fields(item) for item in data if item not in [None, "", []]]
    else:
        return data

def extract_iocs(prompt):
    """
    Extract IOCs (IPs, domains, URLs, hashes) from the user's query.
    :param prompt: The user's query as a string.
    :return: A list of dictionaries containing IOC type and value.
    """
    iocs = []

    # Regex patterns for different types of IOCs
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    domain_pattern = r"(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})"
    url_pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
    md5_pattern = r"\b[a-fA-F\d]{32}\b"
    sha256_pattern = r"\b[a-fA-F\d]{64}\b"

    # Extract IPs
    for match in re.findall(ip_pattern, prompt):
        iocs.append({"type": "ip", "value": match})

    # Extract domains
    for match in re.findall(domain_pattern, prompt):
        iocs.append({"type": "domain", "value": match})

    # Extract URLs
    for match in re.findall(url_pattern, prompt):
        iocs.append({"type": "url", "value": match})

    # Extract MD5 hashes
    for match in re.findall(md5_pattern, prompt):
        iocs.append({"type": "sample", "value": match})

    # Extract SHA256 hashes
    for match in re.findall(sha256_pattern, prompt):
        iocs.append({"type": "sample", "value": match})

    return iocs

def is_valid_md5(hash_value):
    """Check if the hash is a valid MD5."""
    return len(hash_value) == 32 and all(c in "0123456789abcdefABCDEF" for c in hash_value)

def is_valid_sha256(hash_value):
    """Check if the hash is a valid SHA256."""
    return len(hash_value) == 64 and all(c in "0123456789abcdefABCDEF" for c in hash_value)

def convert_md5_to_sha256(md5_hash):
    """Convert an MD5 hash to SHA256."""
    sha256_hash = hashlib.sha256(bytes.fromhex(md5_hash)).hexdigest()
    return sha256_hash