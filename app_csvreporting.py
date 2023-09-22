# Written by lr2t9iz (2023.09.21)
# Script to generate and csv report and attaches it in an email

# Stepts
#  1. Fetch Wazuh Security Events (data)
#  2. Process data and generate a csv report
#  3. Send an email with csv report attached

## for creds
from dotenv import dotenv_values
import os
## for config report
import yaml
## for data report
import requests
from requests.auth import HTTPBasicAuth
import pandas as pd
import urllib3
## send mail
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

def send_mail(creds, cfg_report, report, csv_content):
    try:
        server = smtplib.SMTP(creds['MAIL_SERVER'], creds['MAIL_PORT'])
        server.starttls()
        server.login(creds['MAIL_USER'], creds['MAIL_PASS'])
        msg = MIMEMultipart()
        msg['From'] = cfg_report['sender_email']
        msg['Subject'] = "Report: "+report+".csv"
        msg.attach(MIMEText("Hi\n\nReport "+report+" Attached\n\n--\nWazuh ReportGenAutomation", "plain"))
        part = MIMEApplication(csv_content.encode('utf-8'), Name=report+".csv")
        part['Content-Disposition'] = "attachment; filename=\""+report+".csv\""
        msg.attach(part)
        for email in cfg_report['receiver_email']:
            msg['To'] = email
            server.sendmail(cfg_report['sender_email'], email, msg.as_string())
    except Exception as e:
        print("Mail ERROR", e)
    finally:
       server.quit()

def gen_report(data_json, report, col, rename_col):
    df = pd.json_normalize(data_json, max_level=10)
    df.drop(columns=["_index", "_type", "_id", "_score"], inplace=True)
    df['_source.@timestamp'] = pd.to_datetime(df['_source.@timestamp'], utc=True)
    df['_source.@timestamp'] = df['_source.@timestamp'].dt.tz_convert("America/Guatemala")
    df['_source.@timestamp'] = df['_source.@timestamp'].dt.strftime("%d/%m/%Y %H:%M")
    aux_col = [col[8::] for col in df.columns]
    df.columns=aux_col
    df = df.reindex(columns=col)
    df.columns=rename_col
    return df.to_csv(index=False)

def get_data(creds, cfg_report):
    query_dsl={
            "_source": { "includes": cfg_report['fields'] },
            "query": {
              "bool": {
                "filter": [
                  { "range": { "@timestamp": { "gt": cfg_report['since_date'], "lte": "now/m" } } },
                  { "query_string": { "query": cfg_report['query'] } }
                ]
              }
            }
          }
    data = requests.post(f"https://{creds['WI_HOST']}:{creds['WI_PORT']}/{cfg_report['index_pattern']}/_search",
            auth=HTTPBasicAuth(creds['WI_USER'], creds['WI_PASS']), verify=False,
            json=query_dsl)
    print(f"Wazuh Indexer Result Code: {data.status_code}")
    return data.json()

def main():
    app_dir = os.path.dirname(os.path.realpath(__file__))
    creds = dotenv_values(f"{app_dir}/.env")
    with open(f"{app_dir}/config/reports.yml", "r") as yamlfile:
        cfg_reports = yaml.safe_load(yamlfile)
    for report, cfg_report in cfg_reports.items():
        # prepare report
        data_json = get_data(creds, cfg_report)['hits']['hits']
        if len(data_json):
            data_csv = gen_report(data_json, report, cfg_report['fields'], cfg_report['rename_fields_to'])
            send_mail(creds, cfg_report, report, data_csv)
        else:
            print("CSV Empty")

if __name__=="__main__":
    urllib3.disable_warnings()
    main()
