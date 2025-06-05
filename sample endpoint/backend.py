from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

import gspread
import os
import json


import requests
import os
import io
import shutil
import json
import time
import re
from datetime import datetime, timedelta, timezone

import gspread
from google.oauth2.service_account import Credentials

# from pyspark.sql import SparkSession
# from azure.identity import ClientSecretCredential, DefaultAzureCredential
from urllib.parse import urlparse, parse_qs
# from azure.storage.filedatalake import (
#     DataLakeServiceClient,
#     DataLakeDirectoryClient,
#     FileSystemClient
# )

import pandas as pd
import csv
import webbrowser


import sys
import traceback

################################################################################################################################################################################################

TOKEN_FILE = "token.json"

def set_credentials(path="./env/secret_fabrictest.json"):
    """Set SharePoint API credentials as global variables."""
    with open(path, "r") as file: secret_json = json.load(file)
    global client_id, client_secret, tenant_id, tenant_name
    client_id = secret_json["client_id"]
    client_secret = secret_json["client_secret"]
    tenant_id = secret_json["tenant_id"]
    tenant_name = secret_json["tenant_name"]
    print("Microsoft credentials set successfully.")

def extract_auth_code(url):
    """Extracts the authorization code from a given URL."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    return query_params.get("code", [None])[0]

def get_delegated_access_token(key_name,scope='https://graph.microsoft.com/.default',redirect_uri="https://login.microsoftonline.com/common/oauth2/nativeclient"):
    """
    Fetch an OAuth token using the device code flow, which is suitable for environments where redirects are not available (e.g., Fabric).
    
    Args:
        key_name: name for you token, for storage

    Returns:
        str: The OAuth access token, or None if the request fails.
    """

    if not all([client_id, tenant_id]):
        print("Error: Credentials not set. Use 'set_credentials()' to configure.")
        return None

    # Step 1: Request the device code
    auth_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
    auth_request_url = (
        f"{auth_url}?client_id={client_id}"
        f"&response_type=code"
        f"&redirect_uri={redirect_uri}"
        f"&scope={scope} offline_access openid profile"
        f"&response_mode=query"
    )

    # Open the login page in the user's default browser
    print(f"Opening browser for authentication: {auth_request_url}")
    webbrowser.open(auth_request_url)

    # Ask the user to paste the full redirected URL
    redirected_url = input("Paste the full redirected URL here: ")
    
    # Extract the authorization code
    parsed_url = urlparse(redirected_url)
    auth_code = parse_qs(parsed_url.query).get("code", [None])[0]

    payload = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": auth_code,
        "redirect_uri": redirect_uri,
        "scope": scope,
    }

    response = requests.post(f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token", data=payload)
    token_data = response.json()


    if "access_token" in token_data:
        oauth_token = token_data["access_token"]
        refresh_token = token_data.get("refresh_token", None)
        expiration_date = time.time() + token_data["expires_in"]
        store_token(key_name, oauth_token, refresh_token=refresh_token, expire_at=str(expiration_date))
        print(f"Delegated Access Token retrieved successfully.")
        return oauth_token
    else:
        print(f"Error fetching token: {token_data}")


def get_devicecode_access_token(key_name,scope='https://orgc8458fa6.api.crm5.dynamics.com/user_impersonation offline_access'):
    """
    Fetch an OAuth token using the device code flow, which is suitable for environments where redirects are not available (e.g., Fabric).
    
    Args:
        key_name: name for you token, for storage

    Returns:
        str: The OAuth access token, or None if the request fails.
    """
    global client_id, client_secret, tenant_id, oauth_token, refresh_token

    if not all([client_id, tenant_id]):
        print("Error: Credentials not set. Use 'set_credentials()' to configure.")
        return None

    # Step 1: Request the device code
    device_code_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': scope + " offline_access"
    }

    response = requests.post(device_code_url, data=payload)
    response_data = response.json()

    if "error" in response_data:
        print(f"Error: {response_data['error_description']}")
        return None

    device_code = response_data['device_code']
    user_code = response_data['user_code']
    verification_url = response_data['verification_uri']
    interval = response_data['interval']


    # Step 2: Open the authorization URL in the default browser
    print(f"Redirecting to: {verification_url}, enter the code: {user_code}")
    webbrowser.open(verification_url)

    # Step 2: Poll for the token
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_payload = {
        'client_id': client_id,
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        'device_code': device_code
    }

    while True:
        token_response = requests.post(token_url, data=token_payload)
        token_data = token_response.json()

        if "access_token" in token_data:
            oauth_token = token_data["access_token"]
            refresh_token = token_data["refresh_token"]
            expiration_date = time.time() + token_data["expires_in"]
            store_token(key_name, oauth_token, refresh_token=refresh_token, expire_at=str(expiration_date))
            print(f"Delegated Access Token retrieved successfully.")
            return oauth_token
            break
        elif token_data.get("error") == "authorization_pending":
            time.sleep(interval)
        else:
            print(f"Error fetching token: {token_data}")
            break

def refresh_token(key_name,oauth_token,refresh_token):
    global client_id, client_secret, tenant_id

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }

    response = requests.post(token_url, data=payload)
    token_data = response.json()

    oauth_token = token_data.get("access_token")  # Valid for another 1 hour
    refresh_token = token_data.get("refresh_token")  # Use this next time!
    expiration_date = token_data.get("expires_in")
    store_token(key_name, oauth_token, refresh_token=refresh_token, expire_at=str(expiration_date))
    print(f"Delegated Access Token refreshed successfully.")
    return token_data

def get_application_access_token(key_name,scope="https://graph.microsoft.com/.default"):
    global client_id, client_secret, tenant_id, oauth_token
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope
    }
    
    response = requests.post(token_url, data=token_data)
    token_response = response.json()
    if response.status_code == 401:
        print("Response Status:", response.status_code)
        print("Response Data:", response.text)  # Print full response for debugging
        return None
    access_token = token_response.get("access_token")
    token_expiry = time.time() + token_response.get("expires_in", 3600)

    store_token(key_name, access_token, expire_at=str(token_expiry))

    return access_token


def store_token(key: str, token: str, refresh_token: str = "", expire_at: float = None):
    """
    Stores a token in the 'tokens' table. Creates the table if it doesn't exist.
    If the key exists, it updates the existing record.
    """
    expire_at = expire_at or (datetime.now().timestamp() + 3600)  # Default 1-hour expiry

    # Load existing tokens
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as file:
            tokens = json.load(file)
    else:
        tokens = {}

    # Update or insert new token    
    tokens[key] = {
        "access_token": token,
        "refresh_token": refresh_token,
        "expire_at": expire_at
    }

    # Save back to file
    with open(TOKEN_FILE, "w") as file:
        json.dump(tokens, file, indent=4)

    print(f"Token stored successfully for key: {key}")

def get_token(key: str):
    """
    Retrieves a token from the JSON file if it exists and has not expired.
    Returns None if the token is expired or does not exist.
    """

    if not os.path.exists(TOKEN_FILE):
        print("No tokens stored yet.")
        return None

    with open(TOKEN_FILE, "r") as file:
        tokens = json.load(file)

    if key not in tokens:
        print(f"No token found for key: {key}")
        return None

    token_data = tokens[key]
    expire_at = float(token_data["expire_at"])

    if token_data["refresh_token"] and datetime.now().timestamp() >= expire_at:
        print(f"Refreshing token: {key}")

        return refresh_token(key,token_data["access_token"],token_data["refresh_token"])

    # Check if token is expired
    if datetime.now().timestamp() >= expire_at:
        print(f"Token expired for key: {key}")
        return None

    print(f"Succesfully retrieved [{key}] token.")
    return token_data

def set_access_token(token):
    global oauth_token
    oauth_token = token

def check_token(token_name,grant_type="application",scope="https://graph.microsoft.com/.default"):
    token = get_token(token_name)

    if not token:
        print("Getting new access token...")
        if grant_type == "application":
            access_token = get_application_access_token(token_name,scope)
        elif grant_type == "devicecode":
            access_token = get_devicecode_access_token(token_name,scope)
        elif grant_type == "delegated":
            access_token = get_delegated_access_token(token_name,scope)
        else:
            print(f"Invalid grant type: {grant_type}. \n\nChoose only [ application | delegated ]")
            return None
    else:
        access_token = token["access_token"]
        
    print(f"Access Token: {access_token[:20]}...{access_token[len(access_token)-20:]} (Truncated).")

    return access_token

def delete_token(key: str):
    """
    Deletes a token from the JSON file based on the given key.
    """
    if not os.path.exists(TOKEN_FILE):
        print("Error: Tokens file does not exist.")
        return

    with open(TOKEN_FILE, "r") as file:
        tokens = json.load(file)

    if key in tokens:
        del tokens[key]
        with open(TOKEN_FILE, "w") as file:
            json.dump(tokens, file, indent=4)
        print(f"Token deleted successfully for key: {key}")
    else:
        print(f"No token found for key: {key}")


########################################################################################################################################################################################################################################################################################################################################################
###########  GSPREAD  #########################################################################################################################################################################################################################################################################################################################
########################################################################################################################################################################################################################################################################################################################################################



SPEC_ERROR = "__WATCHDOG_ERROR__:"
CREDENTIALS_PATH = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")

def set_gspread(spreadsheet_name,worksheet_name,cred_path=CREDENTIALS_PATH):
    global worksheet, spreadsheet, logs_worksheet

    # Authenticate with Google Sheets
    credentials = Credentials.from_service_account_file(
        cred_path,
        scopes=['https://www.googleapis.com/auth/spreadsheets',
                'https://www.googleapis.com/auth/drive'])
    gc = gspread.Client(auth=credentials)

    # Open the Google Sheet
    spreadsheet = gc.open(spreadsheet_name)
    logs_worksheet = gc.open("GPS VEHICLE LIVE DATA - ALL PLATFORMS").worksheet("LOGS")
    worksheet = spreadsheet.worksheet(worksheet_name)

    return worksheet

def set_rowlogs(row,name="TEST"):
    global rowlogs, script_name
    rowlogs = row
    script_name = name


def error_Logger(error,error_desc):
    """Logs an error message to the 'LOGS' sheet in the given spreadsheet.

    Args:
        error: The exception object representing the error.
    """
    
    try:
        error_message = str(error)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logs_worksheet.append_row([script_name,current_time, error_desc, error_message])
        traceback.print_exc()
        print(f"Error logged to 'LOGS' sheet: {error_desc} - {error}", flush=True)
        print(f"{SPEC_ERROR}{error_message}")
    except Exception as logging_error:
        print(f"Error logging to 'LOGS' sheet: {logging_error}", flush=True)

def show_progress(progress):
  """Updates the script progress by writing the current time to cell E5 in the 'LOGS' sheet."""
  try:
      logs_worksheet.update_acell('E'+str(rowlogs), progress)
      print(f"{progress}", flush=True)
  except Exception as e:
      print(f"Error updating script progress: {e}", flush=True)

def show_runs(runs):
  """Updates the script runs by writing the current time to cell F5 in the 'LOGS' sheet."""
  try:
      logs_worksheet.update_acell('F'+str(rowlogs), runs)
      print(f"Run (x{runs})", flush=True)
  except Exception as e:
      print(f"Error updating script progress: {e}", flush=True)

def show_duration(dur):
  """Updates the script duration by writing the current time to cell G5 in the 'LOGS' sheet."""
  try:
      logs_worksheet.update_acell('G'+str(rowlogs), dur)
      print(f"duration updated", flush=True)
  except Exception as e:
      print(f"Error updating script progress: {e}", flush=True)



########################################################################################################################################################################################################################################################################################################################################################
## FOR FILE UPLOAD ####################################################################################################################################################################################################################################################################################################################################
########################################################################################################################################################################################################################################################################################################################################################

FILESYSTEM = "lakehouse"


def set_lakehouse_name(name="Sandbox_test2"):
    global lakehouse_name
    lakehouse_name = name

# def initialize_spark():
#     global spark

#     # Set up Spark session
#     spark = SparkSession.builder \
#     .appName("FabricUpload") \
#     .config("spark.hadoop.fs.azure.account.auth.type", "OAuth") \
#     .config("spark.hadoop.fs.azure.account.oauth.provider.type", "org.apache.hadoop.fs.azurebfs.oauth2.ClientCredsTokenProvider") \
#     .config("spark.hadoop.fs.azure.account.oauth2.client.id", client_id) \
#     .config("spark.hadoop.fs.azure.account.oauth2.client.secret", client_secret) \
#     .config("spark.hadoop.fs.azure.account.oauth2.client.endpoint", f"https://login.microsoftonline.com/{tenant_id}/oauth2/token") \
#     .getOrCreate()

#     return spark

def set_fabric_ids(url):
    """Extracts and sets Workspace ID and Lakehouse ID as global variables from a Fabric URL."""
    global workspace_id, lakehouse_id

    # Regex pattern to extract IDs from the URL
    match = re.search(r"groups/([\w-]+)/lakehouses/([\w-]+)", url)
    if match:
        workspace_id, lakehouse_id = match.groups()
        print(f"Workspace ID: {workspace_id}")
        print(f"Lakehouse ID: {lakehouse_id}")
    else:
        raise ValueError("Invalid Fabric Lakehouse URL format.")
    
def get_lakehouse_id(token,workspace_id,lakehouse_name):

    global lakehouse_id

    load_url = f"https://api.fabric.microsoft.com/v1/workspaces/{workspace_id}/lakehouses"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }


    response = requests.get(load_url, headers=headers).json()
    for lakehouse in response.get("value", []):
        if lakehouse.get("displayName") == lakehouse_name:
                lakehouse_id = lakehouse.get("id")
                return lakehouse_id
    print(f"Did not find ID for lakehouse with display name: {lakehouse_name}")
    return None


def get_workspace_id(token,workspace_name):
    global workspace_id

    load_url = f"https://api.fabric.microsoft.com/v1/workspaces/"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }


    response = requests.get(load_url, headers=headers).json()
    for workspace in response.get("value", []):
        if workspace.get("displayName") == workspace_name:
                workspace_id = workspace.get("id")
                return workspace_id
    print(f"Did not find ID for workspace with display name: {workspace_name}")
    return None 



def fabric_load_to_table(token,table_name,file_name="output.csv"):

    if not table_name:
        print("Input table name.")
        return

    load_url = f"https://api.fabric.microsoft.com/v1/workspaces/{workspace_id}/lakehouses/{lakehouse_id}/tables/{table_name}/load"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "relativePath": f"Files/{file_name}",
        "pathType": "File",
        "mode": "overwrite",
        "formatOptions": {
            "header": "true",
            "delimiter": ",",
            "format": "CSV"
        }
    }

    response = requests.post(load_url, headers=headers, json=payload)
    print(response.text)


# Get user home directory
user_home = os.path.expanduser("~")
onelake_base = os.path.join(user_home, "OneLake - Microsoft")

def upload_to_onelake(file_path, workspace_name, lakehouse_name, file_name=None):
    if not file_name:
        file_name = os.path.basename(file_path)  # if no name specified keep original name

    #onelake desktop app path
    onelake_folder = os.path.join(onelake_base, workspace_name, f"{lakehouse_name}.Lakehouse", "Files", "output", file_name)

    #check if exist
    os.makedirs(os.path.dirname(onelake_folder), exist_ok=True)

    # Copy to onelake
    shutil.copy(file_path, onelake_folder)

    print(f"File uploaded successfully to OneLake: {onelake_folder}")

    
    


########################################################################################################################################################################################################################################################################################################################################################
###### FOR LIST & CSV ########################################################################################################################################################################################################################################################################################################################################
########################################################################################################################################################################################################################################################################################################################################################

def list_to_csv(data, filename="output.csv"):
    """Convert a 2D list to a CSV file and save it locally."""
    if not data or not isinstance(data, list) or not all(isinstance(row, list) for row in data):
        raise ValueError("Input must be a 2D list.")

    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerows(data)
    
    print(f"CSV file saved: {filename}")


def read_csv(file_path):
    data = []

    if not os.path.exists(file_path):  
        return None  # Return None if the file doesn't exist
    
    with open(file_path, mode='r', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            data.append(row)  # Each row is appended as a list
    return data

def get_desried_columns(data, desired_columns):
    """
    Filters specific columns from a 2D list based on header names.

    Parameters:
        data (list of lists): A 2D list where the first row contains headers.
        desired_headers (list of str): A list of column names to extract.

    Returns:
        list of lists: A new 2D list containing only the specified columns, including headers.
    """
    if not data:
        return []  # Return empty list if data is empty

    header_row = data[0]  # Get the headers from the first row
    col_indices = [header_row.index(col) for col in desired_columns if col in header_row]

    # Extract only the desired columns
    filtered_data = [[row[i] for i in col_indices] for row in data]

    return filtered_data




































#######################################################################################################################################################################################################


#CONFIG
CONFIG_TXT = "./config/CONFIG_WRU.txt"

#for lakehouse
OUTPUT_FILE = "./output_csv/output_sap.csv"

#for logging
GSPREAD_SS = "GPS VEHICLE LIVE DATA - ALL PLATFORMS"
GPSREAD_WS = "TEMP SAP"
ROW_LOGS = 7

worksheet = set_gspread(GSPREAD_SS,GPSREAD_WS)
set_rowlogs(ROW_LOGS,name=GPSREAD_WS)

app = Flask(__name__)
CORS(app, resources={r"/api/upload": {"origins": "*"}})  # end point

@app.route("/api/upload", methods=["POST", "OPTIONS"])  # Allow both POST and OPTIONS
def handle_post():
    if request.method == "OPTIONS":
        return '', 204  # Respond to OPTIONS request with no content

    payload = request.json  # Receive JSON data
    oe = payload.get("sourceOrderId", "")
    headers = [
        "id",
        "type",
        "sourceOrderId",
        "teamId",
        "lineItem_id",
        "lineItem_quantity",
        "lineItem_quantityUnit",
        "lineItem_price_amount",
        "lineItem_price_currency",
        "volume_value",
        "volume_unit",
        "SO_REF",
        "CLASS_CODE",
        "TRAN_TYPE",
        "CUSTOMER_PO",
        "TRUCKLOAD_NO",
        "LOAD_NO",
        "PAYMENT_TERMS",
        "Homebase_Name_info",
        "Loading_Sequence",
        "homebaseId",
        "locationId",
        "date",
        "orderDate"
    ]

    data = [
        payload.get("id", ""),
        payload.get("type", ""),
        payload.get("sourceOrderId", ""),
        payload.get("teamId", ""),
    ]

    # dissect data
    line_item = payload.get("lineItems", [{}])[0]
    data += [
        line_item.get("id", ""),
        line_item.get("quantity", ""),
        line_item.get("quantityUnit", ""),
        line_item.get("price", {}).get("amount", ""),
        line_item.get("price", {}).get("currency", ""),
    ]

    volume = payload.get("volume", {})
    data += [
        volume.get("value", ""),
        volume.get("unit", ""),
    ]

    custom = payload.get("customProperties", {})
    data += [
        custom.get("SO_REF", ""),
        custom.get("CLASS_CODE", ""),
        custom.get("TRAN_TYPE", ""),
        custom.get("CUSTOMER_PO", ""),
        custom.get("TRUCKLOAD_NO", ""),
        custom.get("LOAD_NO", ""),
        custom.get("PAYMENT_TERMS", ""),
        custom.get("Homebase_Name_info", ""),
        custom.get("Loading_Sequence", ""),
    ]

    data += [
        payload.get("homebaseId", ""),
        payload.get("locationId", ""),
        payload.get("date", ""),
        payload.get("orderDate", ""),
    ]

    # for timestamping
    for_upload = [headers, data]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S") 

    print(f"Received Upload: {oe}, Time: {timestamp}")
    
    print(for_upload)

    worksheet.append_rows(for_upload[1:])

    return jsonify({
        "message": "File Uploaded!",
        "received": timestamp #time received
    }), 200  # Respond with JSON data





if __name__ == "__main__":
    print("Endpoint Initialized")
    app.run(host="0.0.0.0", port=5000, threaded=True) # run on local host


