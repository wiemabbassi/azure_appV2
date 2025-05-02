# ============================
# Build LLM Context
# ============================

import requests
import os # Added import for os
import logging # Add logging
import re # Import re module for regex substitution

# Configure logging if not already configured elsewhere
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define context limit (using characters as proxy for tokens)
# TODO: Replace character count with a proper tokenizer for the target LLM for accurate context limit.
MAX_CONTEXT_CHARACTERS = 100000

def build_llm_context(knowledge_base_results, otx_data, maltiverse_data, user_query):
    """
    Build a structured context for the LLM, ensuring it fits within the character limit.
    :param knowledge_base_results: List of Q&A pairs from the Knowledge Base.
    :param otx_data: List of OTX-retrieved IOC data dictionaries.
    :param maltiverse_data: List of Maltiverse-retrieved IOC data dictionaries.
    :param user_query: The user's query.
    :return: Aggregated and potentially truncated context as a string.
    """
    
    # Keep references to the original list objects passed in
    current_kb_results = knowledge_base_results
    current_otx_data = otx_data
    current_maltiverse_data = maltiverse_data
    
    while True: # Loop until context fits or cannot be truncated further
        # --- Assemble the context string based on CURRENT lists --- 
        system_prompt = (
            "You are a helpful cybersecurity assistant. Analyze the provided context " 
            "(knowledge base, OTX data, Maltiverse data) in relation to the user query. " 
            "Generate a concise and well-structured response using Markdown." 
            "Structure your response as follows:" 
            "1. **Summary:** Briefly answer the user's main question based on the context." 
            "2. **Key Findings:** Use bullet points to list important details, classifications, or correlations " 
            "found in the context regarding the query or any IOCs mentioned. Use **bold** text for emphasis on " 
            "critical findings (e.g., malicious classifications)." 
            "3. **Recommendations:** If applicable, provide clear, actionable recommendations based on the findings, using bullet points." 
            "4. **Confidence Note:** Briefly state the confidence level (high, medium, low) based on the agreement and sources of the information." 
            "If the context does not provide enough information to answer significantly, clearly state that and explain what information is missing."
        )
        
        # Knowledge Base Section
        knowledge_base_section = "**Knowledge Base**:\n"
        if current_kb_results:
            for doc in current_kb_results:
                # Ensure doc and answer exist and are strings before formatting
                answer = doc.get('answer') if isinstance(doc, dict) else None
                if isinstance(answer, str):
                    knowledge_base_section += f"- Answer: {answer}\n"
                else:
                    logging.warning(f"Skipping invalid KB item: {doc}")
        else:
            knowledge_base_section += "No relevant information found in the Knowledge Base.\n"
        
        # OTX Section
        otx_section = "\n**OTX Retrieved Data**:\n"
        if current_otx_data:
            for ioc in current_otx_data:
                if not isinstance(ioc, dict):
                    logging.warning(f"Skipping invalid OTX item: {ioc}")
                    continue
                otx_section += f"- IOC: {ioc.get('ioc_value', 'Unknown')}\n"
                otx_section += f"  - Type: {ioc.get('ioc_type', 'Unknown')}\n"
                otx_section += f"  - Tags: {ioc.get('tags', [])}\n"
                otx_section += f"  - Malware Families: {ioc.get('malware_families', [])}\n"
                otx_section += f"  - Targeted Countries: {ioc.get('targeted_countries', [])}\n"
                otx_section += f"  - ASN: {ioc.get('asn', 'N/A')}\n"
                geo = ioc.get('geolocation', {})
                geo_str = f"{geo.get('city', '')}, {geo.get('region', '')}, {geo.get('country', 'N/A')}".strip(', ')
                otx_section += f"  - Geolocation: {geo_str if geo_str != 'N/A' else 'N/A'}\n"
                otx_section += f"  - Validation Status: {ioc.get('validation_status', 'N/A')}\n"
                pulses = ioc.get('pulse_info', [])
                pulse_names = [p.get('name', 'Unknown') for p in pulses[:3]] # Limit to first 3 pulses
                otx_section += f"  - Pulse Info (Sample): {pulse_names}{'...' if len(pulses) > 3 else ''}\n\n"
        else:
            otx_section += "No data retrieved from OTX.\n"
        
        # Maltiverse Section
        maltiverse_section = "\n**Maltiverse Retrieved Data**:\n"
        if current_maltiverse_data:
            for ioc in current_maltiverse_data:
                if not isinstance(ioc, dict):
                    logging.warning(f"Skipping invalid Maltiverse item: {ioc}")
                    continue
                maltiverse_section += f"- IOC: {ioc.get('ioc_value', 'Unknown')}\n"
                maltiverse_section += f"  - Type: {ioc.get('ioc_type', 'Unknown')}\n"
                maltiverse_section += f"  - API Classification: {ioc.get('classification_source', 'N/A')}\n" # Added source classification
                maltiverse_section += f"  - Tags: {ioc.get('tags', [])}\n"
                maltiverse_section += f"  - Malware Family: {ioc.get('malware_family', 'N/A')}\n"
                maltiverse_section += f"  - Malware Type: {ioc.get('malware_type', 'N/A')}\n"
                blacklist_count = len(ioc.get('blacklist_status', [])) if isinstance(ioc.get('blacklist_status'), list) else 'N/A'
                maltiverse_section += f"  - Blacklist Count: {blacklist_count}\n"
                maltiverse_section += f"  - Targeted Countries: {ioc.get('targeted_countries', [])}\n"
                maltiverse_section += f"  - Industries: {ioc.get('industries', [])}\n"
                maltiverse_section += f"  - ATT&CK IDs: {ioc.get('attack_ids', [])}\n"
                maltiverse_section += f"  - ASN: {ioc.get('asn', 'N/A')}\n"
                maltiverse_section += f"  - Country: {ioc.get('country', 'N/A')}\n"
                maltiverse_section += f"  - Region: {ioc.get('region', 'N/A')}\n"
                maltiverse_section += f"  - City: {ioc.get('city', 'N/A')}\n"
                maltiverse_section += f"  - First Seen: {ioc.get('first_seen', 'N/A')}\n"
                maltiverse_section += f"  - Last Seen: {ioc.get('last_seen', 'N/A')}\n\n"
        else:
            maltiverse_section += "No data retrieved from Maltiverse.\n"
        
        # Combine everything into the full prompt
        full_prompt = f"""
{system_prompt}

Context:
{knowledge_base_section}
{otx_section}
{maltiverse_section}

User Query:
{user_query}
"""
        current_context_string = full_prompt.strip()
        current_length = len(current_context_string)

        # --- Check length and truncate if necessary --- 
        if current_length <= MAX_CONTEXT_CHARACTERS:
            logging.info(f"Final context length: {current_length} characters.")
            return current_context_string # Context fits, return it
        else:
            logging.warning(f"Context length ({current_length}) exceeds limit ({MAX_CONTEXT_CHARACTERS}). Attempting truncation...")
            truncated = False
            # Priorité de suppression : KB (fin), Maltiverse (fin), OTX (fin)
            if current_kb_results:
                current_kb_results.pop() # Modify list directly
                logging.info(f"Truncated KB result. {len(current_kb_results)} remaining.")
                truncated = True
            elif current_maltiverse_data:
                current_maltiverse_data.pop()
                logging.info(f"Truncated Maltiverse result. {len(current_maltiverse_data)} remaining.")
                truncated = True
            elif current_otx_data:
                current_otx_data.pop()
                logging.info(f"Truncated OTX result. {len(current_otx_data)} remaining.")
                truncated = True
            
            if not truncated:
                logging.error(f"Cannot truncate context further. Final length {current_length} may exceed LLM limit.")
                return current_context_string # Return oversized context as last resort
            
            # If truncation happened, the loop continues to rebuild and recheck length

# ============================
# Send to LLM
# ============================

def send_to_llm(prompt, api_url, api_key):
    """Send the formatted input to the LLM API."""
    model_id = os.getenv('LLM_MODEL_ID', 'mistralai/mistral-7b-instruct') # Get model ID from env, default to Mistral 7B

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # OpenAI/OpenRouter format
    payload = {
        "model": model_id,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 1000 # Reduced max output tokens
    }
    
    try:
        response = requests.post(api_url, headers=headers, json=payload)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        
        result = response.json()
        
        # Extract the response from OpenAI/OpenRouter format
        if result.get("choices") and len(result["choices"]) > 0:
            message = result["choices"][0].get("message")
            if message and message.get("content"):
                raw_content = message["content"]
                # 1. Strip leading/trailing whitespace
                content_stripped = raw_content.strip()
                # 2. Replace multiple consecutive newlines with a single newline
                content_concise = re.sub(r'\n{2,}', '\n', content_stripped)
                # 3. Replace ALL remaining newlines with spaces
                content_final = re.sub(r'\n', ' ', content_concise)
                return content_final
            else:
                logging.error(f"Could not extract content from LLM response: {result}")
                return "Error: Could not extract content from LLM response."
        else:
            logging.error(f"Unexpected LLM response format: {result}")
            return f"Error: Unexpected LLM response format: {result}"
            
    except requests.exceptions.RequestException as e:
        logging.error(f"API request failed: {e}")
        return f"Error: API request failed: {e}"
    except Exception as e:
        logging.error(f"An unexpected error occurred in send_to_llm: {e}")
        return f"Error: An unexpected error occurred: {e}"