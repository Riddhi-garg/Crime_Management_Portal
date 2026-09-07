# Crime Management Portal

A Flask-based Crime Management Portal integrated with real **Kaggle / NCRB Crime Statistics Dataset (2001–2014)**.

## Features

- 📊 **Interactive Analytics & Charts** — Crime trends over years, Top States, Crime category distribution (Chart.js)
- 🔍 **Crime Statistics Explorer** — Multi-filter search by State, District, Year, Crime Category with pagination
- 👩 **Women & Children Reports** — Dedicated domain analytics
- 💰 **Property & Arrest Statistics** — Stolen vs recovered property, Arrest/Conviction data
- 🏢 **Operational Modules** — Add stations and officers, file FIRs, maintain criminal records, and open/update case files
- 🔗 **Dataset Context in Operations** — NCRB state coverage, crime-category, arrest, and yearly reference tables are shown alongside operational records; aggregate historical statistics remain separate from individual records
- 📡 **REST API** — `/api/stats` JSON endpoint

## Dataset

Real NCRB district-wise crime statistics from `archive/` folder:
- `01_District_wise_crimes_committed_IPC_2001_2012/2013/2014.csv`
- `42_District_wise_crimes_committed_against_women_*.csv`
- `03_District_wise_crimes_committed_against_children_*.csv`
- `10_Property_stolen_and_recovered.csv`
- `04_02_Person_arrested_and_their_disposal_*_IPC_crime_*.csv`
- `dataful_police_stations_and_outposts.csv` - Dataful dataset 20145, Police: Year-, State- and Region-wise Number of Police Stations and Outposts

> **341,108** IPC crime records across **38 states**, **950 districts**, **14 years**, **97 crime categories**.

The Dataful police infrastructure export is loaded into `police_infrastructure_statistics` and displayed at `/police-infrastructure`. Download the CSV export for [Dataful dataset 20145](https://dataful.in/datasets/20145), save it as `archive/dataful_police_stations_and_outposts.csv`, and rerun the importer. The expected columns are `data_as_on`, `state`, `station_or_outpost`, `station_or_outpost_type`, `category`, `value`, `unit`, and `note`.

## Setup & Run

```bash
# 1. Install dependencies
pip3 install flask

# 2. Import Kaggle dataset into SQLite
python3 import_kaggle_data.py

# 3. Start the web application
python3 app.py
```

Open your browser at: **http://127.0.0.1:5050**

## Data Source

Kaggle / NCRB Crime Statistics Dataset (2001-2014), plus Dataful/BPRD Police Organizations Dataset 20145 (2011-2024)
