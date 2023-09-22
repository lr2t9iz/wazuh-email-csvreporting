#!/bin/bash

APP_DIR=$(dirname $0)
source ${APP_DIR}/venv/bin/activate
python3 ${APP_DIR}/app_csvreporting.py >> ${APP_DIR}/csvreporting.log
deactivate
