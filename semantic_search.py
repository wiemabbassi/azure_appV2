# ============================
# MongoDB Semantic Search
# ============================
import numpy as np
from pymongo import MongoClient, errors # Import errors for better exception handling
from sklearn.metrics.pairwise import cosine_similarity
import os
import logging
import requests  # Added for API calls
from dotenv import load_dotenv  # Load environment variables from .env
import pprint # Added for pretty printing
from dotenv import load_dotenv
# Load environment variables
load_dotenv()

# Retrieve the environment variables
# MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/') # Default to local MongoDB if not set
COSMOSDB_CONNECTION_STRING = os.getenv('COSMOSDB_CONNECTION_STRING')
DB_NAME = os.getenv('DB_NAME', 'security_qna')
COLLECTION_NAME = os.getenv('COLLECTION_NAME', 'questions_answers')
# Assuming LLM_API_KEY is used for Hugging Face embeddings
EMBEDDING_API_KEY = os.getenv('EMBEDDING_API_KEY') 


# Initialize MongoDB client
# client = MongoClient(MONGO_URI)
if not COSMOSDB_CONNECTION_STRING:
    logging.error("COSMOSDB_CONNECTION_STRING environment variable not set.")
    # Depending on requirements, you might raise an error or handle this gracefully
    # raise ValueError("COSMOSDB_CONNECTION_STRING environment variable not set.")
    client = None 
    db = None
    collection = None
else:
    try:
        # Add server selection timeout and connection timeout
        client = MongoClient(
            COSMOSDB_CONNECTION_STRING, 
            serverSelectionTimeoutMS=200000, # Increased to 200s
            connectTimeoutMS=100000 # Increased to 100s
        )
        # The ismaster command is cheap and does not require auth.
        client.admin.command('ismaster') 
        logging.info("Successfully connected to Cosmos DB.")
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
    except errors.ConnectionFailure as e:
        logging.error(f"Could not connect to Cosmos DB: {e}")
        client = None # Ensure client is None if connection fails
        db = None
        collection = None

# Configure logging
logging.basicConfig(level=logging.INFO)

# Hugging Face Inference API details
HF_EMBEDDING_MODEL_ID = "intfloat/e5-base-v2"
HF_API_URL = f"https://api-inference.huggingface.co/pipeline/feature-extraction/{HF_EMBEDDING_MODEL_ID}"
model=HF_API_URL
# Removed lazy loading for local model
# _model = None
# def get_model():
#     """Lazy-load the SentenceTransformer model."""
#     global _model
#     if _model is None:
#         logging.info("Loading e5-base-v2 model...")
#         _model = SentenceTransformer("intfloat/e5-base-v2")
#     return _model

def generate_embedding(text):
    """
    Generate an embedding for the given text using the Hugging Face Inference API.
    Handles both single strings and lists of strings.
    """
    # Use the module-level HF_API_KEY
    if not EMBEDDING_API_KEY:
        logging.error("Hugging Face API key (loaded from LLM_API_KEY env var) not found.")
        raise ValueError("Missing Hugging Face API Key")

    # e5 models require a prefix, but the Inference API handles this implicitly for feature extraction.
    # We send the raw text.
    inputs = text # API expects a string or list of strings

    headers = {"Authorization": f"Bearer {EMBEDDING_API_KEY}"}
    payload = {"inputs": inputs, "options": {"wait_for_model": True}}

    try:
        response = requests.post(HF_API_URL, headers=headers, json=payload)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        result = response.json()

        # The API returns embeddings directly (or a list of embeddings if input was a list)
        if isinstance(result, list) and len(result) > 0:
             # Check if the first element is a list (batch embedding) or float (single embedding)
            if isinstance(result[0], list):
                # It's a list of embeddings for a batch input
                return result
            elif isinstance(result[0], float):
                 # It's a single embedding for a single string input
                return result
            else:
                logging.error(f"Unexpected embedding format in API response list: {result[0]}")
                raise ValueError("Unexpected embedding format in API response")
        else:
            logging.error(f"Unexpected or empty response from Embedding API: {result}")
            raise ValueError("Invalid response from Embedding API")

    except requests.exceptions.RequestException as e:
        logging.error(f"Hugging Face API request failed: {e}")
        raise
    except Exception as e:
        logging.error(f"Error processing embedding API response: {e}")
        raise 

def semantic_search(query, top_n=5, min_similarity=0.80):
    """Perform semantic search using cosine similarity.
       Note: This implementation fetches ALL documents and compares locally.
       This is INEFFICIENT for large datasets. Consider Azure Search integration
       or Cosmos DB's vector search capabilities for production scenarios.
    """
    # Use the globally initialized client, db, and collection
    if client is None or collection is None:
        logging.error("Database connection is not available.")
        # raise ConnectionError("Database connection is not available.")
        return [] # Return empty list or raise error

    try:
        # Generate embedding for the query using the local SentenceTransformer model
        query_embedding = generate_embedding(query) # Using HF API
        #query_embedding = model.encode(query) # Using local SentenceTransformer

        # Fetch all documents from MongoDB with timeout to prevent operation cancellation
        try:
            # Add max_time_ms to prevent long-running queries
            cursor = collection.find({
                "embedded_question": {"$exists": True},
                "question": {"$exists": True},
                "answer": {"$exists": True}
            }, max_time_ms=30000000)  # 200-second timeout
            
            documents = list(cursor)
            logging.info(f"Retrieved {len(documents)} documents from database")
        except errors.PyMongoError as e:
            logging.error(f"CosmosDB query error: {str(e)}")
            return []  # Return empty results on database error

        # Compute cosine similarity for each document
        results = []
        for doc in documents:
            try:
                similarity = cosine_similarity(
                    [query_embedding], [doc["embedded_question"]]
                )[0][0]  # sklearn returns a matrix; extract the scalar value
                if similarity >= min_similarity:  # Only include results above the threshold
                    results.append({
                        "id": doc.get("id", "N/A"),
                        "question": doc["question"],
                        "answer": doc["answer"],
                        "similarity": similarity
                    })
            except KeyError:
                logging.warning(f"Skipping document with missing 'embedded_question': {doc}")

        # Sort results by similarity (descending)
        results.sort(key=lambda x: x["similarity"], reverse=True)

        # Deduplicate results based on the question text
        seen_questions = set()
        unique_results = []
        for result in results:
            if result["question"] not in seen_questions:
                seen_questions.add(result["question"])
                unique_results.append(result)
            if len(unique_results) >= top_n:
                break

        return unique_results

    except Exception as e:
        logging.error(f"An error occurred during semantic search: {str(e)}")
        raise
    