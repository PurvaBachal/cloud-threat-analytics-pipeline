import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

# Grabbing the exact same configurations as your loader script uses
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

def initialize_database_schema():
    print(f"Connecting directly to target database catalog: {DB_NAME}...")
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        port="5432",
        sslmode="require"
    )
    cursor = conn.cursor()
    
    # The exact same query parameters from the analytical_transformation.sql file
    ddl_query = """
    DROP TABLE IF EXISTS public.stg_security_threat_logs CASCADE;
    
    CREATE TABLE public.stg_security_threat_logs (
        ip_address VARCHAR(50),
        abuse_confidence_score INT,
        country_code VARCHAR(10),
        total_reports INT,
        last_reported_at VARCHAR(50),
        ingestion_timestamp TIMESTAMP,
        data_source VARCHAR(100)
    );

    CREATE OR REPLACE VIEW public.vw_threat_incident_rankings AS
    WITH CleansedBase AS (
        SELECT 
            ip_address,
            COALESCE(abuse_confidence_score, 0) AS threat_confidence_score,
            UPPER(TRIM(country_code)) AS normalized_country,
            COALESCE(total_reports, 0) AS report_volume,
            CAST(last_reported_at AS TIMESTAMP) AS incident_logged_time,
            ingestion_timestamp,
            ROW_NUMBER() OVER (PARTITION BY ip_address ORDER BY ingestion_timestamp DESC) as duplicate_rank
        FROM public.stg_security_threat_logs
        WHERE ip_address IS NOT NULL AND country_code != '' AND country_code != 'NULL'
    )
    SELECT 
        normalized_country as country,
        COUNT(DISTINCT ip_address) as distinct_attacker_count,
        ROUND(AVG(threat_confidence_score), 2) as mean_threat_score,
        SUM(report_volume) as raw_incident_volume,
        DENSE_RANK() OVER (ORDER BY COUNT(DISTINCT ip_address) DESC) as global_risk_rank
    FROM CleansedBase
    WHERE duplicate_rank = 1
    GROUP BY normalized_country;
    """
    
    try:
        print("Forcing relational table schemas inside target engine context...")
        cursor.execute(ddl_query)
        conn.commit()
        print("Success! Structural tables and analytical views initialized perfectly.")
    except Exception as e:
        conn.rollback()
        print(f"Initialization failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    initialize_database_schema()
