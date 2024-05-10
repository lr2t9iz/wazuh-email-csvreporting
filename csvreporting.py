# Written by lr2t9iz (2023.09.21)
# Script to fetch data, generate csv report and attaches it in an email

# Stepts
#  1. Fetch Wazuh Security Events (data)
#  2. Process data and generate a csv report
#  3. Send an email with csv report attached

## for creds
from dotenv import dotenv_values
import os
import sys
## for config report
import yaml
## for data report
import requests
import pandas as pd
import urllib3
## send mail
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

import argparse
import datetime
import logging

log = logging.getLogger(__name__)
month = datetime.datetime.now().strftime('%Y.%m')
log_filename = os.path.basename(__file__)[:-3]
log_filename = os.path.join('logs', f"{month}_{log_filename}")
log_format = '%(asctime)s %(levelname)s %(message)s'
logging.basicConfig(filename=f"{log_filename}.log", level=logging.INFO, format=log_format)

is_debug_mode = False
def debug(message):
  if is_debug_mode:
    print(message)

def send_mail(mail_host, mail_port, mail_user, mail_pass, report, cfg_report, csv_content):
  SUBJECT = cfg_report['notification_email']['subject']
  BODY = cfg_report['notification_email']['body']
  SENDER = cfg_report['notification_email']['sender_email']
  RECEIVER = cfg_report['notification_email']['receiver_emails']
  csv_name = report+".csv"
  try:
    server = smtplib.SMTP(mail_host, mail_port)
    server.starttls()
    server.login(mail_user, mail_pass)
    msg = MIMEMultipart()
    msg['From'] = SENDER
    msg['Subject'] = SUBJECT
    msg.attach(MIMEText(BODY, "plain"))
    part = MIMEApplication(csv_content.encode('utf-8'), Name=csv_name)
    part['Content-Disposition'] = "attachment; filename="+csv_name
    msg.attach(part)
    for email in RECEIVER:
      msg['To'] = email
      server.sendmail(SENDER, email, msg.as_string())
    debug(f"send_mail: email sent")
    log.info(f"send_mail: email sent")
  except Exception as e:
    debug(f"send_mail: {e}")
    log.error(f"send_mail: {e}")
  finally:
    server.quit()

def gen_report(data_json, report, cfg_report):
  FIELDS = cfg_report['report_params']['fields']
  RENAME = cfg_report['report_params']['enable_field_renaming']
  NEW_FIELDS = cfg_report['report_params']['rename_fields_to']
  DT_TZ = cfg_report['time_settings']['timezone']
  DT_FORMAT = cfg_report['time_settings']['time_format']
  AGG = cfg_report['aggregation']['enabled']
  AGG_FREQ = cfg_report['aggregation']['frequency']
  df = pd.json_normalize(data_json, max_level=10)
  
  if "_type" in df.columns:
    df.drop(columns=["_index", "_type", "_id", "_score"], inplace=True)
  else:
    df.drop(columns=["_index", "_id", "_score"], inplace=True)

  delete_source = [col[8::] for col in df.columns]
  df.columns = delete_source

  df['@timestamp'] = pd.to_datetime(df['@timestamp'], utc=True)
  df['@timestamp'] = df['@timestamp'].dt.tz_convert(DT_TZ)
  df['@timestamp'] = df['@timestamp'].dt.strftime(DT_FORMAT)
  df = df.reindex(columns=FIELDS)
  
  if RENAME:
    if len(FIELDS) == len(NEW_FIELDS):
      if len(set(NEW_FIELDS)) != len(NEW_FIELDS):
        debug(f"Error, there are duplicate rename_fields_to")
        log.error(f"gen_report: there are duplicate rename_fields_to")
        sys.exit()
      df.columns = NEW_FIELDS
    else:
      debug("verify the rename_fields_to")
      log.error(f"gen_report: verify the rename_fields_to")
      sys.exit()

  if len(set(df.columns)) != len(df.columns):
    debug(f"Error, there are duplicate fields")
    log.error(f"gen_report: there are duplicate fields")
    sys.exit()
    
  if AGG:
    agg_col = df.columns.tolist()
    df[agg_col[0]] = pd.to_datetime(df[agg_col[0]], format=DT_FORMAT)
    df.fillna('NA', inplace=True)
    df = df.groupby([pd.Grouper(key=agg_col[0], freq=f"{AGG_FREQ}min")]+agg_col[1:]).size().reset_index(name="count")
    df[agg_col[0]] = df[agg_col[0]].dt.strftime(DT_FORMAT)
    log.info(f"gen_report: agg activated {len(df)} events")
  debug(f"gen_report: csv created")
  log.info(f"gen_report: csv created")
  return df.to_csv(index=False)

def get_data(wi_url, wi_user, wi_pass, cfg_report, docs_limit, change_limit):
  INDEX_PATTERN = cfg_report['event_source']['index_pattern']
  QUERY_STRING = cfg_report['event_source']['query']
  REPORT_FIELDS = cfg_report['report_params']['fields']
  SINCE_HOURS = cfg_report['report_params']['last']
  # https://www.elastic.co/guide/en/elasticsearch/reference/current/esql-limitations.html
  if change_limit:
    db_config = requests.put(f"{wi_url}/{INDEX_PATTERN}/_settings",
      auth=HTTPBasicAuth(wi_user, wi_pass), verify=False,
      json={"index":{"max_result_window":docs_limit}})
  if docs_limit > 10000 and change_limit == False:
    debug("get_data, change_limit not setted, setting docs_limit to 10000")
    docs_limit = 10000
  query_dsl={
    "_source": { "includes": REPORT_FIELDS },
    "size": docs_limit,
    "query": {
      "bool": {
        "filter": [
          { "range": { "@timestamp": { "gte": f"now/m-{SINCE_HOURS}/m", "lt": "now/m" } } },
          { "query_string": { "query": QUERY_STRING } }
        ]
      }
    }
  }
  data = requests.get(f"{wi_url}/{INDEX_PATTERN}/_search",
    auth=requests.auth.HTTPBasicAuth(wi_user, wi_pass), verify=False,
    json=query_dsl)
  events = data.json()['hits']['hits']
  log.info(f"get_data: {len(events)} events")
  debug(f"Wazuh Indexer Result Code: {data.status_code}")
  return events

def check_file(filepath):
  if not os.path.exists(filepath):
    debug(f"File not found, Check {filepath} file")
    sys.exit()

def main():
  global is_debug_mode
  parser = argparse.ArgumentParser(description="Script to fetch data, generate csv report and attaches it in an email.")
  parser.add_argument('--config', type=str, required=True, help='Name Config in conf.d i.e. --config main.yml')
  parser.add_argument('--debug', action='store_true', help='Debug and test the configuration, --degub True')
  if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)
  args = parser.parse_args()
  is_debug_mode = args.debug
  
  app_dir = os.path.dirname(os.path.realpath(__file__))
  
  env_file = f"{app_dir}/.env"
  creds = dotenv_values(env_file)
  
  conf_file = f"{app_dir}/conf.d/{args.config}"
  check_file(conf_file)
  
  with open(conf_file, "r") as yamlfile:
    cfg_reports = yaml.safe_load(yamlfile)
  
  check_file(env_file)
  
  WI_URL = creds['WI_URL']
  WI_USER = creds['WI_USER']
  WI_PASS = creds['WI_PASS']
  MAIL_HOST = creds['MAIL_HOST']
  MAIL_PORT = creds['MAIL_PORT']
  MAIL_USER = creds['MAIL_USER']
  MAIL_PASS = creds['MAIL_PASS']
  
  docs_limit = 10000 # wi support 10000, 
  # if you want increase the limit, set default_limit to False, NOT work with cloud instances
  change_limit = False
  
  log.info(f"main: starting")
  for report, cfg_report in cfg_reports.items():
    debug(f"main: {report} processing ++++++++++++++++++++++++")
    log.info(f"main: {report} processing ++++++++++++++++++++++++")
    data_json = get_data(WI_URL, WI_USER, WI_PASS, cfg_report, docs_limit, change_limit)
    if len(data_json):
      data_csv = gen_report(data_json, report, cfg_report)
      send_mail(MAIL_HOST, MAIL_PORT, MAIL_USER, MAIL_PASS, report, cfg_report, data_csv)
    else:
      df_vacio = pd.DataFrame()
      csv_data = df_vacio.to_csv()
      send_mail(MAIL_HOST, MAIL_PORT, MAIL_USER, MAIL_PASS, report, cfg_report, csv_data)
      debug(f"main: {report}, 0 events")
      log.info(f"main: {report}, 0 events")

if __name__=="__main__":
  urllib3.disable_warnings()
  main()
  