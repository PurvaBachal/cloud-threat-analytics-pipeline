import os
import psycopg2
import pandas as pd
from io import StringIO
from dotenv import load_dotenv
from azure.storage.blob import BlobServiceClient

# Fetching localized environment configurations from your hidden .env file
load_dotenv()

AZURE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
CONTAINER_NAME = "bronze-threat-logs"

DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

def get_latest_blob_from_bronze():
    """
    Scans the cloud storage container, sorts files by time, and returns the newest file name.
    """
    blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
    container_client = blob_service_client.get_container_client(CONTAINER_NAME)
    
    blob_list = list(container_client.list_blobs())
    if not blob_list:
        print("No data log sets detected inside the cloud Bronze storage zone.")
        return None
        
    blob_list.sort(key=lambda x: x.last_modified, reverse=True)
    latest_blob_name = blob_list[0].name
    print(f"Isolated newest raw block inside cloud container: {latest_blob_name}")
    return latest_blob_name

def process_and_load_staging():
    """
    Downloads the newest cloud file stream and moves it into PostgreSQL staging.
    """
    target_file = get_latest_blob_from_bronze()
    if not target_file:
        return
        
    blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
    blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=target_file)
    
    download_stream = blob_client.download_blob()
    df = pd.read_csv(StringIO(download_stream.content_as_text()))
    
    # structural sequence of our SQL staging table columns, avoiding schema mapping collisions.
    db_column_order = [
        'ipAddress', 'abuseConfidenceScore', 'countryCode', 
        'totalReports', 'lastReportedAt', 'ingestion_timestamp', 'data_source_feed'
    ]
    
    # Fallback to ensure all required columns exist in the DataFrame context
    for col in db_column_order:
        if col not in df.columns:
            df[col] = None
            
    df_ordered = df[db_column_order]
    
    # Establish direct connection with Azure PostgreSQL Flexible Server instance
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        port="5432",
        sslmode="require",
        options="-c search_path=public"
    )
    cursor = conn.cursor()
    
    # Prepare clean text buffer data without headers for bulk copy ingestion
    buffer = StringIO()
    df_ordered.to_csv(buffer, index=False, header=False)
    buffer.seek(0)
    
    try:
        print("Executing structural bulk COPY operations directly into PostgreSQL staging...")
        cursor.copy_from(buffer, 'stg_security_threat_logs', sep=',', null="")
        conn.commit()
        print("Silver staging dataset updated and locked successfully.")
    except Exception as db_fault:
        conn.rollback()
        print(f"Staging transaction failed. Database error trace: {str(db_fault)}")
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    process_and_load_staging()
