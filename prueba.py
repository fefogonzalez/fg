import pyodbc
import datetime
from datetime import datetime as dt
import json
import requests
import logging
import time
import Allowhost
import Allowapps
import uuid
import pytz

tz = pytz.timezone('America/Argentina/Buenos_Aires')


logging.basicConfig(filename='request_date.log',
                            filemode='a',
                            format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S',
                            level=logging.DEBUG)

def connect_app_db(server, port, database, username, password):
    cnxn = pyodbc.connect('Driver={SQL Server};SERVER='+server+';PORT='+port+';DATABASE='+database+';UID='+username+';PWD='+ password)
    cursor = cnxn.cursor()
    return cursor

def get_table(cursor):
    table_index = ""
    query_table = """SELECT PARTITION_INDEX FROM dbo.PA_EVENT_PARTITION_CATALOG
                    WHERE  GETDATE() >= FROM_DATE and GETDATE() <= TO_DATE"""
    cursor.execute(query_table)
    result_set = cursor.fetchall()
    for row in result_set:
        table_index = str(row[0])
    return table_index

def read_alerts(cursor, table_index):
    dateMax = ""
    with open('lastDate.txt', 'r') as reader:  
        dateMax = reader.read()
    reader.close()
    query_alerts = """SELECT [SUBJECT], [ANALYZED_BY] , [LOCAL_DETECT_TS], IIF([DESTINATIONS] = ' ','N/A',DESTINATIONS) as DESTINATIONS, [APP_VERSION] , [APP_NAME_SRC],
                     [POLICY_CATEGORIES], [RUN_AS_USER] , PE.[ID], IIF(ATT_NAMES is NULL,'N/A',ATT_NAMES) as ATT_NAMES , [TOTAL_MATCHES], MIN([SEVERITY]) , [CHANNEL_NAME],
                     [BREACH_CONTENT], [APP_NAME_DEST], [DEVICE_NAME_DEST], PE.[INSERT_DATE]
                     FROM dbo.PA_EVENTS_%s PE 
                     JOIN dbo.PA_EVENT_POLICIES_%s PO on PE.ID = PO.EVENT_ID
                     JOIN  dbo.PA_RP_SERVICES PS on PE.SERVICE_ID = PS.ID
                     WHERE PE.INSERT_DATE > '%s'
                     GROUP BY [SUBJECT], [ANALYZED_BY] , [LOCAL_DETECT_TS], DESTINATIONS, [APP_VERSION] , [APP_NAME_SRC],[POLICY_CATEGORIES], [RUN_AS_USER] , PE.[ID], ATT_NAMES , [TOTAL_MATCHES] , [CHANNEL_NAME], [BREACH_CONTENT], [APP_NAME_DEST], [DEVICE_NAME_DEST], PE.[INSERT_DATE]
                     ORDER BY PE.[INSERT_DATE] ASC""" % (table_index, table_index, dateMax[:-3])
    print(query_alerts)
    cursor.execute(query_alerts)
    for (SUBJECT, ANALYZED_BY, LOCAL_DETECT_TS, DESTINATIONS, APP_VERSION, APP_NAME_SRC, POLICY_CATEGORIES, RUN_AS_USER, ID , ATT_NAMES, TOTAL_MATCHES, SEVERITY, CHANNEL_NAME, BREACH_CONTENT, APP_NAME_DEST, DEVICE_NAME_DEST, INSERT_DATE) in cursor:
        diccionarios = []
        destino = DESTINATIONS

        dateMax = dt.strptime(dateMax, "%Y-%m-%d %H:%M:%S.%f")
        ins_date = INSERT_DATE

        if ins_date >= dateMax:
            dateMax = str(INSERT_DATE)
            
        if "https://" in DESTINATIONS:
            destino = DESTINATIONS.replace("https://","")
            domain, detail = destino.split('/', 1)
            destino = domain.upper()
            
        if "http://" in DESTINATIONS:
            destino = DESTINATIONS.replace("http://","")
            domain, detail = destino.split('/', 1)
            destino = domain.upper()

        if destino == "" and APP_NAME_DEST != "":
            destino = APP_NAME_DEST
            
        severity_name = ""

        if SEVERITY == 3:
            severity_name = "LOW"
        if SEVERITY == 2:
            severity_name = "MEDIUM"
        if SEVERITY == 1:
            severity_name = "HIGH"
        if "ML" in RUN_AS_USER:
            username = RUN_AS_USER.split('\\')[1]
        else:
            username = RUN_AS_USER
        
        alert = {
            "msg" : SUBJECT,
            "analyzedBy" : ANALYZED_BY,
            "log_timestamp" : LOCAL_DETECT_TS.strftime('%Y-%m-%d %H:%M:%S.%f'),
            "severityType" : severity_name,
            "destinationHosts" : destino,
            "productVersion" : APP_VERSION,
            "sourceServiceName": CHANNEL_NAME,
            "duser" : APP_NAME_SRC,
            "cat" : POLICY_CATEGORIES,
            "loginName" : username, #test originalmente era username
            "sourceHost" : "N/A" ,
            "action" : "N/A",
            "log_id" : str(ID),
            "fname" : ATT_NAMES,
            "level" : "5",
            "sourceIp" : "N/A",
            "maxMatches" : str(TOTAL_MATCHES),
            "user": "N/A",
            "breachContent": BREACH_CONTENT,
            "deviceDestName": DEVICE_NAME_DEST
        }
        sent_to_mensajeria = False
        diccionarios.append(alert)
        if (alert["sourceServiceName"] == "Endpoint Removable Media" or alert["sourceServiceName"] == "Endpoint HTTPS"):
              if not ((alert["sourceServiceName"] == "Endpoint Removable Media" and (alert["fname"].startswith("G:\\") or alert["deviceDestName"]=="N/A")) or (alert["sourceServiceName"] == "Endpoint HTTPS" and (Allowhost.in_allowList(alert["destinationHosts"])))):
##              print(str(diccionarios))
                logging.debug(alert["log_id"] + " - " + str(diccionarios))
                send_alert_to_mensajeria(diccionarios)
                sent_to_mensajeria = True

        if (alert["sourceServiceName"] == "Endpoint Applications"):
              if not (Allowapps.in_allowList(alert["destinationHosts"])):
                OneDrive_Corporativo = "OneDrive - Mi-Empresa S.A."
                if not (OneDrive_Corporativo in alert["fname"]):
                    logging.debug(alert["log_id"] + " - " + str(diccionarios))
                    send_alert_to_mensajeria(diccionarios)
                    sent_to_mensajeria = True
                    
        if not sent_to_mensajeria:
            logging.debug('No enviado a mensajeria -> %s', alert["log_id"])
##          print(alert["sourceServiceName"] + " - host: " + alert["destinationHosts"] + " fname: " + alert["fname"] + " - " + str(alert["destinationHosts"].startswith("DRIVE.GOOGLE")) + " - " + str(alert["destinationHosts"].startswith("DOCS.GOOGLE")))
        time.sleep(1)
    save_to_file(dateMax)

def save_to_file(dateMax):
    f = open("lastDate.txt", "w")
    f.write(dateMax)
    logging.debug("Cargado max date: " + dateMax)
    f.close()

def send_alert_to_mensajeria(alerts):
    url = "http://empresa.com/mensajeria/v2/events/"
    headers = {
      'Content-Type': 'application/json'
    }
    try:
        response = requests.request("POST", url, headers=headers, json=alerts)
        response.raise_for_status()
        if response.ok:
            logging.info("OK: " + str(response.text))
    except requests.exceptions.HTTPError as e:
        url = "http://empresa.com/aplicacion/send_email"
        response = requests.request("POST", url, headers=headers)
        if response.ok:
            logging.info("Error : " + str(response.text))
        print(e)
        raise e    

 



    
########################MAIN########################

server = 'mi_servidor'
port = '1234'

database = 'mi_bbdd' 
username = 'usuario' 
password = 'password'

cursor = connect_app_db(server,port,database,username,password)
table_index = get_table(cursor)
read_alerts(cursor, table_index)
