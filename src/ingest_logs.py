import io
import os
import requests
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from azure.storage.blob import BlobServiceClient

# Load configuration values from the hidden localized .env layer
load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
AZURE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
CONTAINER_NAME = "bronze-threat-logs"

def extract_api_logs():
    """
    Extracts live global malicious IP traffic coordinates from public threat intelligence endpoints.
    """
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    
    #Adding User-Agent makes the python request resemble a standard browser,
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    params = {
        'confidenceMinimum': '75',
        'limit': '500'
    }
    
    print("Connecting to live public threat intelligence feed...")
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        raw_payload = response.json().get('data')
        if not raw_payload:
            print("Endpoint active but returned an empty dataset stream.")
            return None
            
        df = pd.DataFrame(raw_payload)
        
        # Adding structural tracking parameters for data governance audit paths
        df['ingestion_timestamp'] = datetime.utcnow()
        df['data_source_feed'] = 'AbuseIPDB_Public_Developer_Tier'
        
        print(f"Successfully extracted {len(df)} live threat signature records.")
        return df
    else:
        print(f"Handshake failed. API response error code: {response.status_code}")
        return None

def ship_to_azure_bronze(dataframe):
    """
    Streams the pandas dataframe directly to Azure Blob Storage as an immutable raw text file.
    """
    if dataframe is None or dataframe.empty:
        print("Extraction was empty. Aborting cloud staging process loops.")
        return
        
    # File suffix with date-hour-second tracking tags
    timestamp_suffix = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    blob_name = f"raw_threat_log_{timestamp_suffix}.csv"
    
    # Prevents writing temporary cache fragments to local storage
    csv_string_io = io.StringIO()
    dataframe.to_csv(csv_string_io, index=False)
    csv_payload = csv_string_io.getvalue()
    
    try:
        blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
        blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=blob_name)
        
        print(f"Shipping raw text payload to Azure Blob Storage: {blob_name}")
        blob_client.upload_blob(csv_payload, overwrite=True)
        print("Bronze layer sync completed successfully.")
    except Exception as network_error:
        print(f"Error encountered during Azure Blob storage copy: {str(network_error)}")

if __name__ == "__main__":
    print("Running Raw Threat Telemetry Extraction...")
    extracted_df = extract_api_logs()
    ship_to_azure_bronze(extracted_df)
