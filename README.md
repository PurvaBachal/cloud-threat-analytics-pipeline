# End-to-End Cloud Threat Intelligence & Log Analytics Pipeline

### Real-Time Ingest, Storage, and Global Risk Ranking Dashboard

---

## Business Problem & Project Objective

Cybersecurity teams monitor massive amounts of network traffic daily. When a company's firewalls detect unauthorized pings from suspicious IP addresses, security analysts need to know where these threats are coming from and how dangerous they are. Looking at raw log files manually is slow and makes it hard to see the big picture.

The objective of this project is to build a automated data pipeline that pulls live cyber threat data from a public intelligence feed, stores it securely in the cloud, and transforms it into clean metrics. The final goal is to display this data on a clear dashboard so that managers can instantly spot global threat hotspots and see which countries host the highest volume of malicious actors.

---

## Core Architecture & Data Flow

The project follows a standard structured data flow to move raw telemetry from the web straight to a polished dashboard visual:

1.  **Ingestion Phase (Raw Data):** A Python script connects to the public threat intelligence API, extracts the latest malicious IP records in JSON format, and saves them as backup CSV files directly inside an Azure Blob Storage container.
2.  **Staging Phase (Structured Data):** A second Python script downloads the newest file from cloud storage, organizes the columns to fix formatting inconsistencies, and loads the records cleanly into an Azure PostgreSQL database table.
3.  **Transformation Phase (Analytics Data):** Inside the database, a custom SQL View filters out duplicate entries, cleans country codes, and automatically calculates risk ranks using advanced ranking functions based on the volume of threat actors.
4.  **Consumption Phase (Visualization Dashboard):** Power BI Desktop connects directly to the cloud database SQL view, importing the rows to display real-time global threat maps, priority bar indexes, and automated data grids.

---

## Tech Stack & Cloud Infrastructure

- **Code Editor & Client Driver:** Visual Studio Code (VS Code) utilizing integrated local database client adapters.
- **Cloud File Storage:** Azure Blob Storage used to save and back up raw data logs.
- **Cloud Database Engine:** Azure PostgreSQL Flexible Server hosting our relational staging tables and views.
- **Programming Language:** Python 3.12+ leveraging standard data handling and database connection libraries.
- **Data Transformation:** ANSI-SQL executing database schemas, data cleansing filters, and ranking functions.
- **Pipeline Orchestration Blueprint:** Azure Data Factory (ADF) visually mapping out our execution workflow steps.
- **Data Visualization Tier:** Power BI Desktop styled with a clean dark-mode monitoring theme.

---

## Repository Structure

```unset
cloud-threat-analytics-pipeline/
│
├── dashboard/                     # Finalized presentation assets
│   |── threat_monitor_report.pbix # Compiled Power BI analytical workspace
|   └── screenshot
├── sql/                           # Relational structural definitions
│   └── analytical_transformation.sql # Core SQL schema initialization scripts
├── src/                           # Programmatic compute modules
│   ├── db_init.py                 # Structural cloud schema generator
│   ├── db_loader.py               # High-speed database data loader
│   └── ingest_logs.py             # Live endpoint extraction script
├── .env                           # Secret configuration file (Hidden locally)
├── .gitignore                     # Security filter preventing credential leaks
└── README.md                      # Project documentation run-book
```

---

## Database Transformations & SQL Logic

The core analytical calculations happen directly inside the Azure PostgreSQL database through an optimized SQL View. The logic cleans and organizes the data automatically using the following steps:

1.  **Data Cleansing & Standardizing:** The query trims accidental white spaces and converts all two-letter country codes into clean uppercase strings, while filtering out empty or invalid rows.
2.  **Log Deduplication:** Because multiple pipeline runs might capture the same malicious IP, the script uses a partitioning row-ranking function (`ROW_NUMBER()`) to isolate the most recent entry for each unique IP address and filter out duplicate entries.
3.  **Geographic Risk Ranking:** The script groups unique threat actors by country, counts the total number of distinct attackers, and applies a statistical window function (`DENSE_RANK()`). This function ranks the countries from highest to lowest threat volume. If two countries have the exact same number of attackers, it assigns them a matching rank smoothly without skipping the next number in sequence.

---

## Project Notes & Operational Realities

### Cloud Data Center Security Parameters

During the cloud integration phase, running a direct web request from an Azure Data Factory cloud node to the public API endpoint encounters a firewall block from the provider. This happens because public threat intelligence networks block shared cloud data center IP subnets on their developer tiers to prevent automated server scraping.

- **The Workflow Solution:** To keep the project functional and realistic, the ADF workspace is used as an project visual blueprint mapping out the design logic. The actual data processing tasks are triggered via our Python scripts, which use standard network routes to feed the cloud database, while keeping the ADF canvas as a complete structural reference ready for production deployment.

### Sustainable Storage Management

To prevent the cloud database from accumulating unnecessary data over time, a data purging query is documented at the bottom of our SQL file. Running this statement automatically removes log records older than 30 days, keeping our storage footprint clean and organized.
