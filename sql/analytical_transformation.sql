-- Create Staging Data Table within the default open public schema
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
-- Build the Curated Gold Layer Analytical View directly over the open public layer
CREATE OR REPLACE VIEW public.vw_threat_incident_rankings AS WITH CleansedBase AS (
    SELECT ip_address,
      COALESCE(abuse_confidence_score, 0) AS threat_confidence_score,
      UPPER(TRIM(country_code)) AS normalized_country,
      COALESCE(total_reports, 0) AS report_volume,
      CAST(last_reported_at AS TIMESTAMP) AS incident_logged_time,
      ingestion_timestamp,
      -- Deduplicating identical threat signatures using partition row ranking sequences
      ROW_NUMBER() OVER (
        PARTITION BY ip_address
        ORDER BY ingestion_timestamp DESC
      ) as duplicate_rank
    FROM public.stg_security_threat_logs
    WHERE ip_address IS NOT NULL
      AND country_code != ''
      AND country_code != 'NULL'
  )
SELECT normalized_country as country,
  COUNT(DISTINCT ip_address) as distinct_attacker_count,
  ROUND(AVG(threat_confidence_score), 2) as mean_threat_score,
  SUM(report_volume) as raw_incident_volume,
  -- Core Skill Highlight: Using DENSE_RANK Window function to create geographic threat priority ranks
  DENSE_RANK() OVER (
    ORDER BY COUNT(DISTINCT ip_address) DESC
  ) as global_risk_rank
FROM CleansedBase
WHERE duplicate_rank = 1 -- Filters out duplicate logs from successive API ingestions
GROUP BY normalized_country;
-- DELETE FROM public.stg_security_threat_logs WHERE ingestion_timestamp < CURRENT_DATE - INTERVAL '30 days';