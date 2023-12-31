# WAZUH - Email CSV Reporting [![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/license/mit/)

## Overview
- Mini App Tool for fetching wazuh security events, generating CSV files, and attaching them via email.

## **Prerequisites**

Step 1: **Download**
Open https://github.com/lr2t9iz/wazuh-email-csvreporting and click on "Code" then click "Download Zip". Once the archive is downloaded, you can extract it in a preferred directory.

Step 2: **Install**
Open a Shell command and navigate to the extraced folder, create an python virtual environment (venv), activate the venv and install `requirements.txt`
```    
python3 -m venv venv
source ./venv/bin/activate
pip install -r requirements.txt
```

Step 3: **Configuration**
Create the .env file for smtp and wazuh indexer credentials. Reference:
```
# Configuration and Credential
## wazuh indexer
WI_HOST="127.0.0.1"
WI_PORT=9200
WI_USER="admin"
WI_PASS="changeme"
## mail server
MAIL_SERVER="smtp-server"
MAIL_PORT=25
MAIL_USER="admin"
MAIL_PASS="changeme"
```

## **Usage**

Step 1: **Reporting Config**
Configure the ./config/reports.yml file for earch report. 

Step 2: **Schedule Task**
configure a cron job to trigger the report with <config>_report.yml parameter - bydefault reports.yml:  Example:
![1](https://github.com/lr2t9iz/wazuh-email-csvreporting/assets/46981088/ca9ecaaf-71e9-4734-a01d-dd5507d17c21)

See [Cron Generator](https://crontab.guru/)
