import logging
from iocs_extraction import remove_empty_fields, extract_iocs
from semantic_search import semantic_search
from otx import fetch_otx_data
from maltiverse import fetch_maltiverse_data
from llm import build_llm_context, send_to_llm
import os
import json        
import re    
import numpy as np
from pymongo import MongoClient
import io
import sys  
import azure.functions as func
import re
import hashlib
import requests
from dotenv import load_dotenv


# Load environment variables
load_dotenv()

# Retrieve the environment variables
COSMOSDB_CONNECTION_STRING = os.getenv('COSMOSDB_CONNECTION_STRING')
LLM_URL = os.getenv('LLM_URL')
LLM_API_KEY = os.getenv('LLM_API_KEY')
OTX_API_KEY = os.getenv('OTX_API_KEY')



app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="http_trigger")
def main2(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Python HTTP trigger function processed a request.")

    try:
        # Étape 1 : Extraire la requête utilisateur depuis la requête HTTP
        try:
            req_body = req.get_json()
            user_query = req_body.get('prompt')
        except ValueError:
            return func.HttpResponse("Invalid JSON in request body.", status_code=400)

        if not user_query:
            return func.HttpResponse("Please provide a 'prompt' in the request body.", status_code=400)

        # Étape 2 : Effectuer la recherche sémantique
        knowledge_base_results = semantic_search(user_query, top_n=10, min_similarity=0.85)
        # Log the number of documents retrieved
        logging.info(f"Retrieved {len(knowledge_base_results)} documents from Cosmos DB via semantic search.")

        # Étape 3 : Extraire les IoCs de la requête
        iocs = extract_iocs(user_query)

        # Étape 4 : Interroger OTX et Maltiverse pour chaque IoC et filtrer basé sur la confiance
        otx_data_final = []
        maltiverse_data_final = []
        for ioc in iocs:
            ioc_type = ioc["type"]
            ioc_value = ioc["value"]

            # Récupérer les données OTX et Maltiverse (en supposant qu'elles retournent {'data': ..., 'classification': ..., 'score': ...})
            otx_result = fetch_otx_data(ioc_type, ioc_value)
            maltiverse_result = fetch_maltiverse_data(ioc_type, ioc_value)

            otx_classification = otx_result.get('classification') if otx_result else None
            otx_score = otx_result.get('score') if otx_result else 0
            maltiverse_classification = maltiverse_result.get('classification') if maltiverse_result else None
            maltiverse_score = maltiverse_result.get('score') if maltiverse_result else 0

            # Vérifier la contradiction et comparer les scores
            if otx_result and maltiverse_result and \
               otx_classification and maltiverse_classification and \
               otx_classification != maltiverse_classification:

                logging.info(f"Contradiction found for IoC {ioc_value}: OTX({otx_classification}, {otx_score}), Maltiverse({maltiverse_classification}, {maltiverse_score})")
                if otx_score >= maltiverse_score:
                    otx_data_final.append(otx_result['data'])
                    logging.info(f"Keeping OTX data for {ioc_value} due to higher score.")
                else:
                    maltiverse_data_final.append(maltiverse_result['data'])
                    logging.info(f"Keeping Maltiverse data for {ioc_value} due to higher score.")
            else:
                # Pas de contradiction ou informations insuffisantes, garder les deux
                if otx_result and 'data' in otx_result:
                    otx_data_final.append(otx_result['data'])
                if maltiverse_result and 'data' in maltiverse_result:
                    maltiverse_data_final.append(maltiverse_result['data'])

        # Étape 5 : Construire le contexte pour le LLM (truncation handled within)
        llm_context = build_llm_context(knowledge_base_results, otx_data_final, maltiverse_data_final, user_query)
        # logging.info(f"Initial context length: {len(llm_context)} characters") # Logging now done inside build_llm_context

        # Étape 5.1 : Tronquer le contexte si nécessaire - MOVED TO build_llm_context in llm.py
        # while len(llm_context) > MAX_CONTEXT_CHARACTERS:
        #    ... (removed truncation loop) ...

        # Étape 6 : Envoyer le contexte au LLM
        llm_response = send_to_llm(llm_context, LLM_URL, LLM_API_KEY)

        # Étape 7 : Retourner la réponse du LLM via HTTP
        if llm_response:
            return func.HttpResponse(json.dumps({"response": llm_response}), status_code=200, mimetype="application/json")
        else:
            return func.HttpResponse("Error: Failed to retrieve a response from the LLM.", status_code=500)

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return func.HttpResponse(f"Internal Server Error: {str(e)}", status_code=500)
