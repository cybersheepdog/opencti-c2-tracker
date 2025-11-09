# OpenCTI Connector

[![Build Status](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue.svg)](https://shields.io/)
![Maintenance](https://img.shields.io/maintenance/yes/2025.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/cybersheepdog/opencti-c2-tracker.svg?style=flat-square)](https://github.com/cybersheepdog/opencti-c2-tracker/commit/main)
#![GitHub](https://img.shields.io/github/license/cybersheepdog/opencti-c2-tracker)


Ingest data [C2 Tracker Data](https://github.com/montysecurity/C2-Tracker/tree/main/data) into an [OpenCTI](https://github.com/OpenCTI-Platform/opencti) instance.

## Features

- Import C2 Tracker IOCs as Observablesi in OpenCTI in STIX format to allow for enrichment workflows to take place.
- Promotes Observable to an Indicator
- Intelligently manage Indicators
    ~~- Delete indicators if they are no longer seen in C2 Tracker~~
    - Allows OPENCTI's built in Indicator Decay rule to age out indicators
    - Labels
        - Use "c2-tracker" label to denote the source of the intel
        - Auto creates additional labels based on Tool name with a random color selection if it does not already exist.
    - Link indicators to MITRE tools and malware (requires [MITRE Connector](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/mitre))
- Docker compose file is configured to automatically launch the image on boot
- The script will automatically restart if an error is encountered

## Install (Docker) (Recommended)

1. Create a user with "Connector" & "Default" roles, take note of the Token that is made and put it in an environment variable called `CONNECTOR_IMPORT_C2_TRACKER'
2. Download the repo: `git clone https://github.com/cybersheepdog/opencti-c2-tracker.git`
3. Navigate to connector: `cd opencti-c2-tracker/`
4. Review `docker-compose.yml` and update `OPENCTI_URL` if necessary
5. Run `docker-compose up -d`

## Install (Standalone Python)

Requires Python 3

1. Create a user with "Connector" & "Default" roles, take note of the Token that is made and put it in an environment variable called `CONNECTOR_IMPORT_C2_TRACKER`
2. Download the repo: `git clone https://github.com/cybersheepdog/opencti-c2-tracker.git`
3. Navigate to connector: `cd opencti-c2-tracker/`
4. Review `src/connector.py` variables `api_url` and `api_token`; set environment variable `OPENCTI_BASE_URL`
5. Install packages: `pip3 install --upgrade pip && pip3 install -r src/requirements.txt`
6. Run `src/connector.py`
7. Set Cron Job or Service to run `src/connector.py` when OpenCTI starts up

## Purge Script

There is a script at `opencti-connector/src/purge.py` that is not executed by the docker container. It solely exists to allow the operator to easily delete all of the indicators that were made by this connector. It relies on the label `c2-tracker` to identify those.
