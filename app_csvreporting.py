# Written by lr2t9iz (2023.09.21)
# Script to generate and csv report and attaches it in an email

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

def gen_report(data_json, report, cfg_report):
    new_col=cfg_report['rename_fields_to']
    dtf=cfg_report['dt'][1]
    df = pd.json_normalize(data_json, max_level=10)
    df.drop(columns=["_index", "_type", "_id", "_score"], inplace=True)
    df['_source.@timestamp'] = pd.to_datetime(df['_source.@timestamp'], utc=True)
    df['_source.@timestamp'] = df['_source.@timestamp'].dt.tz_convert(cfg_report['dt'][0])
    df['_source.@timestamp'] = df['_source.@timestamp'].dt.strftime(dtf)
    aux_col = [col[8::] for col in df.columns]
    df.columns=aux_col
    df = df.reindex(columns=cfg_report['fields'])
    df.columns=new_col
    if cfg_report['agg'][0]:
        df[new_col[0]] = pd.to_datetime(df[new_col[0]], format=dtf)
        df.fillna('NA', inplace=True)
        df = df.groupby([pd.Grouper(key=new_col[0], freq=f"{cfg_report['agg'][1]}min")]+new_col[1:]).size().reset_index(name="count")
        df[new_col[0]] = df[new_col[0]].dt.strftime(dtf)
        return df.to_csv(index=False)
    else:
        return df.to_csv(index=False)

def get_data(creds, cfg_report):
    db_docs_limit=50000
    query_dsl={
            "_source": { "includes": cfg_report['fields'] },
            "size": db_docs_limit,
            "query": {
              "bool": {
                "filter": [
                  { "range": { "@timestamp": { "gt": cfg_report['since_date'], "lte": "now/m" } } },
                  { "query_string": { "query": cfg_report['query'] } }
                ]
              }
            }
          }
    db_config = requests.put(f"https://{creds['WI_HOST']}:{creds['WI_PORT']}/{cfg_report['index_pattern']}/_settings",
             auth=HTTPBasicAuth(creds['WI_USER'], creds['WI_PASS']), verify=False,
             json={"index":{"max_result_window":db_docs_limit}})
    data = requests.post(f"https://{creds['WI_HOST']}:{creds['WI_PORT']}/{cfg_report['index_pattern']}/_search",
            auth=HTTPBasicAuth(creds['WI_USER'], creds['WI_PASS']), verify=False,
            json=query_dsl)
    print(f"Wazuh Indexer Result Code: {data.status_code}")
    #print(data.json()) #debug
    return data.json()

def main(config_reports="reports.yml"):
    app_dir = os.path.dirname(os.path.realpath(__file__))
    creds = dotenv_values(f"{app_dir}/.env")
    with open(f"{app_dir}/config/{config_reports}", "r") as yamlfile:
        cfg_reports = yaml.safe_load(yamlfile)
    for report, cfg_report in cfg_reports.items():
        # prepare report
        data_json = get_data(creds, cfg_report)['hits']['hits']
        if len(data_json):
            data_csv = gen_report(data_json, report, cfg_report)
            send_mail(creds, cfg_report, report, data_csv)
        else:
            print("CSV Empty")

if __name__=="__main__":
    urllib3.disable_warnings()
    main(sys.argv[1]) if len(sys.argv) == 2 else main()
