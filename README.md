# WAZUH - Email CSV Reporting [![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/license/mit/)

## Overview
- Mini App Tool for fetching wazuh security events, generating CSV files, and attaching them via email.

## **Prerequisites**

Step 1: **Download**
Open https://github.com/lr2t9iz/wazuh-email-csvreporting and click on "Code" then click "Download Zip". Once the archive is downloaded, you can extract it in a preferred directory.

Step 2: **Install**
Open a Shell command and navigate to the extraced folder
- [create an python virtual environment (venv), activate the venv] (Optional)
```    
python3 -m venv venv
source ./venv/bin/activate
```
- install python requirements `pip install requirements.txt`

Step 3: **Configuration**
Create the .env file for smtp and wazuh indexer credentials. Reference: .env-example

## **Usage**

Step 1: **Reporting Config**
Configure the ./conf.d/**config_reports.yml** file. 

Step 2: **Schedule Task**
configure a cron job to trigger the report.
- Example: `0 * * * * python3 .\csvreporting.py --config config_reports.yml`

See [Cron Generator](https://crontab.guru/)
