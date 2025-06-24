from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

import gspread
import os
import json
import uuid

import base64
from typing import Literal

import smtplib
from email.message import EmailMessage

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

import threading


import sys
import traceback

# load_dotenv("./env/key64.env")

################################################################################################################################################################################################

TOKEN_FILE = "token.json"

# Where to save the decoded Microsoft credentials
msft_secret_path = "/tmp/msft-secret.json"

# Decode and write key if not already written
if "fabric_key64" in os.environ:
    msft_key_data = base64.b64decode(os.environ["fabric_key64"])

    with open(msft_secret_path, "wb") as f:
        f.write(msft_key_data)
else:
    raise RuntimeError("Missing fabric_key64 environment variable.")


def set_credentials(path=msft_secret_path):
    """Set SharePoint API credentials as global variables."""
    with open(path, "r") as file:
        secret_json = json.load(file)

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

def get_delegated_access_token(key_name, scope='https://graph.microsoft.com/.default',redirect_uri="https://login.microsoftonline.com/common/oauth2/nativeclient", to_gmail=None):
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

def get_devicecode_access_token(key_name, scope, to_gmail=None):
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
        'scope': scope.replace("api/data/v9.2", "user_impersonation") + " offline_access"
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


    # Step 2: Open the authorization URL in the default browser or thru GMAIL
    if to_gmail:
        print(f"Sending verification code/url to {to_gmail}.")
        send_to_gmail(to_gmail,verification_url,user_code)
        pass
    else:
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
            store_token(key_name, oauth_token, refresh_token=refresh_token, expire_at=str(expiration_date), is_public=True)
            print(f"Delegated Access Token retrieved successfully.")
            return oauth_token
            break
        elif token_data.get("error") == "authorization_pending":
            time.sleep(interval)
        else:
            print(f"Error fetching token: {token_data}")
            break


APP_PASSWORD = "ehek tlyp arfr bwtc"
SENDER_EMAIL = "gs.gpsprojectAPI1@gmail.com"

def send_to_gmail(receiver_email,redirect=None,code=None):

    subject = "Device Code Authentication"
    body = f"Click here to authenticate. {redirect}\n\nAuthentication Code:{code}"

    # Create the email
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = receiver_email

    # Gmail SMTP settings
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    app_password = APP_PASSWORD  # Use App Password, not Gmail password

    # Send the email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(SENDER_EMAIL, app_password)
        server.send_message(msg)



def refresh_token(key_name,oauth_token,refresh_token,is_public=False):
    global client_id, client_secret, tenant_id

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    payload = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }

    # Include client_secret only if not public
    if not is_public:
        payload["client_secret"] = client_secret

    response = requests.post(token_url, data=payload)
    token_data = response.json()

    oauth_token = token_data.get("access_token")  # Valid for another 1 hour
    refresh_token = token_data.get("refresh_token", refresh_token)  # Use this next time!
    expiration_date = time.time() + token_data.get("expires_in", 3600)
    store_token(key_name, oauth_token, refresh_token=refresh_token, expire_at=str(expiration_date), is_public=is_public)
    print(f"Delegated Access Token refreshed successfully.")
    return {
        "access_token":  oauth_token,
        "refresh_token": refresh_token,
        "expire_at": str(expiration_date),
        }


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

def store_token(key: str, token: str, refresh_token: str = "", expire_at: float = None, is_public: bool = False):
    """
    Stores a token in the 'tokens' file. Creates the file if it doesn't exist.
    If the key exists, it updates the existing record.
    """
    import os
    import json
    from datetime import datetime

    expire_at = expire_at or (datetime.now().timestamp() + 3600)  # Default 1-hour expiry

    # Load existing tokens safely
    tokens = {}
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r") as file:
                content = file.read().strip()
                if content:  # Avoid error if file is empty
                    tokens = json.loads(content)
        except json.JSONDecodeError:
            print(f"Warning: {TOKEN_FILE} is invalid or corrupted. Reinitializing.")

    # Update or insert new token    
    tokens[key] = {
        "access_token": token,
        "refresh_token": refresh_token,
        "expire_at": expire_at,
        "is_public": is_public
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

    print("Expire at:", expire_at)
    print("Has refresh_token:", bool(token_data["refresh_token"]))

    if token_data["refresh_token"] and datetime.now().timestamp() >= expire_at:
        print(f"Refreshing token: {key}")

        return refresh_token(key,token_data["access_token"],token_data["refresh_token"],is_public=token_data["is_public"])

    # Check if token is expired
    if datetime.now().timestamp() >= expire_at:
        print(f"Token expired for key: {key}")
        return None

    print(f"Succesfully retrieved [{key}] token.")
    return token_data

def set_access_token(token):
    global oauth_token
    oauth_token = token

def check_token(token_name,grant_type: Literal["application", "devicecode", "delegated"] = "application", scope="https://graph.microsoft.com/.default", to_gmail=None):
    try:
        token = get_token(token_name)
        access_token = token["access_token"]
    except:
        access_token = None

    if not access_token:
        print("Getting new access token...")
        if grant_type == "application":
            access_token = get_application_access_token(token_name,scope)
        elif grant_type == "devicecode":
            # access_token = get_devicecode_access_token(token_name,scope,to_gmail)
            pass
        elif grant_type == "delegated":
            access_token = get_delegated_access_token(token_name,scope)
        else:
            print(f"Invalid grant type: {grant_type}. \n\nChoose only [ application | delegated ]")
            return None
        
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


key_path = "/tmp/gcp-key.json"


if "gspread_key64" in os.environ: #decode
    key_data = base64.b64decode(os.environ["gspread_key64"])


    with open(key_path, "wb") as f:
        f.write(key_data)

    # Set this env var for Google SDKs to auto-detect
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = key_path
else:
    raise RuntimeError("Missing gspread_key64 environment variable.")


def set_gspread(spreadsheet_name,worksheet_name,cred_path=key_path):
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

def get_sheet_data(worksheet_name, range=None):
    """
    Retrieve data from a specified worksheet in a Google Sheet.

    Args:
        worksheet_name (str): The name of the worksheet to fetch data from.
        range (str, optional): The range of cells to retrieve in A1 notation. 
                               If None, retrieves all data from the worksheet.

    Returns:
        list: A 2D list containing the data from the specified worksheet and range.
    """
    global spreadsheet

    # Open the Google Sheet
    worksheet = spreadsheet.worksheet(worksheet_name)

    # Read all data from the sheet into a 2D list
    if range is None:  # If range is None or not provided, fetch all data
        data = worksheet.get_all_values()
    else:
        data = worksheet.get(range)  # This will get all rows from the specified range

    return data

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

def initialize_spark():
    # global spark

    # # Set up Spark session
    # spark = SparkSession.builder \
    # .appName("FabricUpload") \
    # .config("spark.hadoop.fs.azure.account.auth.type", "OAuth") \
    # .config("spark.hadoop.fs.azure.account.oauth.provider.type", "org.apache.hadoop.fs.azurebfs.oauth2.ClientCredsTokenProvider") \
    # .config("spark.hadoop.fs.azure.account.oauth2.client.id", client_id) \
    # .config("spark.hadoop.fs.azure.account.oauth2.client.secret", client_secret) \
    # .config("spark.hadoop.fs.azure.account.oauth2.client.endpoint", f"https://login.microsoftonline.com/{tenant_id}/oauth2/token") \
    # .getOrCreate()

    # return spark
    pass

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


CACHE_FILE = "cache.json"
EXPIRY = 1 # 1 day from now

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

def to_dict(data_2d):
    headers = data_2d[0]
    rows = data_2d[1:]
    return [dict(zip(headers, row)) for row in rows]

def save_cache(key: str, content, file_path: str = CACHE_FILE, expiry=None):
    """
    Save a dictionary to cache under the specified key.
    """
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            try:
                cache = json.load(f)
            except json.JSONDecodeError:
                cache = {}
    else:
        cache = {}

    expiry_time = get_expiry_timestamp(expiry) # Set expiration timestamp

    cache[key] = {
        "data": content,
        "timestamp": expiry_time
    }

    with open(file_path, "w") as f:
        json.dump(cache, f, indent=4)

def get_cache(key: str, file_path: str = CACHE_FILE):
    """
    Retrieve a cached dictionary by key. Deletes it if expired. Returns None if not found or expired.
    """
    if not os.path.exists(file_path):
        return None

    with open(file_path, "r") as f:
        try:
            cache = json.load(f)
        except json.JSONDecodeError:
            return None

    entry = cache.get(key)
    if not entry:
        return None

    expiry_str = entry.get("timestamp")
    if expiry_str:
        try:
            expiry = datetime.fromisoformat(expiry_str)
            if datetime.now() >= expiry:
                del cache[key] # Expired: delete entry
                with open(file_path, "w") as f:
                    json.dump(cache, f, indent=4)
                return None
        except ValueError:
            del cache[key] # If timestamp is invalid, treat as expired
            with open(file_path, "w") as f:
                json.dump(cache, f, indent=4)
            return None

    return entry.get("data")


def get_expiry_timestamp(expiry=None):
    """
    Returns ISO 8601 expiry timestamp.
    
    - If `expiry` is None: returns now + default EXPIRY_DAYS.
    - If `expiry` is a string: parses to datetime and converts to ISO.
    - If `expiry` is a datetime object: converts to ISO.
    """
    if not expiry:
        return (datetime.now() + timedelta(days=EXPIRY)).isoformat()
    
    if isinstance(expiry, str):
        try:
            # Try full datetime first
            return datetime.fromisoformat(expiry).isoformat()
        except ValueError:
            try:
                # Try date-only string (YYYY-MM-DD)
                date_part = datetime.strptime(expiry, "%Y-%m-%d")
                end_of_day = date_part.replace(hour=23, minute=59, second=59)
                return end_of_day.isoformat()
            except ValueError:
                raise ValueError(f"Invalid expiry format: {expiry}")

    elif isinstance(expiry, datetime):
        return expiry.isoformat()

    raise TypeError("Expiry must be a datetime or ISO 8601 string")

def get_or_cache(key, fetch_fn, *args, expiry=None, file_path=CACHE_FILE, **kwargs):
    """
    Retrieve a cached value by key, or compute and cache it if missing or expired.

    Args:
        key (str): Cache key.
        fetch_fn (callable): Function to fetch the data if not cached.
        *args: Positional arguments for fetch_fn.
        **kwargs: Keyword arguments for fetch_fn.
        expiry (str|datetime, optional): Expiry time for the cache.
        file_path (str): Path to cache file.

    Returns:
        The cached or freshly fetched value.
    """
    value = get_cache(key, file_path)
    if value is not None:
        return value

    value = fetch_fn(*args, **kwargs)

    if not value:
        print("No value fetched from the function provided.")
        return None

    save_cache(key, value, file_path=file_path, expiry=expiry)
    return value




########################################################################################################################################################################################################################################################################################################################################################
###########  DATAVERSE  #########################################################################################################################################################################################################################################################################################################################
########################################################################################################################################################################################################################################################################################################################################################


def upload_data_to_dataverse(oauth_token, dataverse_url, table_name, data):
    """Upload data from Google Sheets to a Dataverse"""

    if not oauth_token:
        print("Error: No OAuth token available. Retrieve a token first.")
        return
    
    headers = {
        "Authorization": f"Bearer {oauth_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "OData-Version": "4.0"
    }
    
    endpoint = f"{dataverse_url}/{table_name}s"
    
    response = requests.post(endpoint, json=data, headers=headers)
    
    if response.status_code == 204 or response.status_code == 201:
        print("Data uploaded successfully.")
    else:
        print(f"Error uploading data: {response.status_code} - {response.text}")

def check_table_exists(oauth_token,dataverse_url, table_name):

    headers = {
        "Authorization": f"Bearer {oauth_token}",
        "Accept": "application/json",
        "OData-Version": "4.0"
    }

    # Construct the endpoint to retrieve records from the table
    endpoint = f"{dataverse_url}/{table_name}"

    # Send the GET request
    response = requests.get(endpoint, headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        print(f"Table '{table_name}' exists and data retrieved successfully!")
        print(response.json())  # Optionally print the response JSON to see the data
    else:
        print(f"Error accessing the table: {response.status_code} - {response.text}")

def list_tables(oauth_token, dataverse_url):
    headers = {
        "Authorization": f"Bearer {oauth_token}",
        "Accept": "application/json",
        "OData-Version": "4.0"
    }

    endpoint = f"{dataverse_url}/EntityDefinitions?$select=LogicalName,SchemaName,DisplayName"

    response = requests.get(endpoint, headers=headers)

    if response.status_code == 200:
        entities = response.json().get("value", [])
        result = {}

        for entity in entities:
            logical_name = entity.get("LogicalName", "")
            display = entity.get("DisplayName", {})
            label = display.get("UserLocalizedLabel") or {}
            display_name = label.get("Label", "")

            if display_name:  # Skip if there's no label
                result[display_name] = logical_name

        return result

    else:
        print(f"Error fetching tables: {response.status_code} - {response.text}")
        return {}

def get_col_logical_names(oauth_token, url, table):
    """
    Fetch display name → logical name mapping for user-defined columns in a Dataverse table.

    Returns:
        dict: {Display Name: LogicalName}
    """
    endpoint = f"{url}/EntityDefinitions(LogicalName='{table}')/Attributes"
    
    headers = {
        "Authorization": f"Bearer {oauth_token}",
        "Accept": "application/json"
    }
    
    response = requests.get(endpoint, headers=headers)

    if response.status_code == 200:
        data = response.json()
        result = {}

        for attribute in data.get('value', []):
            if not attribute.get("IsCustomAttribute", False):
                continue  # Only include user-defined (custom) columns

            logical_name = attribute.get("LogicalName")
            labels = attribute.get("DisplayName", {}).get("LocalizedLabels", [])

            if labels and labels[0].get("Label"):
                display_name = labels[0]["Label"]
                result[display_name] = logical_name

        return result
    
    else:
        print(f"Error fetching metadata: {response.status_code} - {response.text}")
        return {}
    
def to_logical_names(display_list, mapping):
    """
    Given a list of display names and a mapping dictionary of {Display Name: LogicalName},
    returns a new list with each display name replaced by its logical name.
    If a display name isn't found in the mapping, it is kept as-is.
    """
    return [mapping.get(col, col) for col in display_list]


def map_data_to_payload(logical_names, data, limit=0):
    """Map the 2D array data to a batch payload format using logical names, and format dates/numbers properly."""
    payloads = []
    headers = data[0]  # The first row contains column headers

    # Determine the limit of rows to process (if limit is 0, process all)
    rows_to_process = data[1:limit] if limit else data[1:]

    for row in rows_to_process:  # Iterate over each row
        row_payload = {}

        for i, header in enumerate(headers):
            logical_name = logical_names.get(header)  # Get the logical name for the header
            if logical_name:
                value = row[i].strip() if isinstance(row[i], str) else row[i]

                # Handle empty/invalid values
                if value in ["", "--", "N/A"]:
                    value = None  # Convert invalid values to None (null in JSON)

                # Format date fields properly
                if "date" in logical_name.lower() and value:
                    value = format_date(value)  # Apply date formatting

                # Convert numeric fields properly
                elif isinstance(value, str) and value.replace(".", "", 1).isdigit():
                    value = float(value) if "." in value else int(value)

                row_payload[logical_name] = value  # Map the data to the logical name

        payloads.append(row_payload)  # Add the mapped row to the batch payload

    return payloads

def upload_batch_data_to_dataverse(oauth_token, dataverse_url, table_name, data_list):
    """Upload multiple records to Dataverse using a batch request"""

    if not oauth_token:
        print("Error: No OAuth token available. Retrieve a token first.")
        return
    
    # Generate unique batch and change set IDs
    batch_guid = f"batch_{uuid.uuid4()}"
    changeset_guid = f"changeset_{uuid.uuid4()}"

    # Headers for the batch request
    headers = {
        "Authorization": f"Bearer {oauth_token}",
        "Content-Type": f"multipart/mixed;boundary={batch_guid}",
        "Accept": "application/json",
        "OData-Version": "4.0"
    }

    # Construct batch request body
    batch_body = []
    
    # Opening boundary for batch
    batch_body.append(f"--{batch_guid}")
    batch_body.append(f"Content-Type: multipart/mixed; boundary={changeset_guid}")
    batch_body.append("")  # Blank line required

    # Add each record as part of the change set
    i=0
    for record in data_list:
        batch_body.append(f"--{changeset_guid}")
        batch_body.append("Content-Type: application/http")
        batch_body.append("Content-Transfer-Encoding: binary")
        batch_body.append(f"Content-ID: {i}")
        batch_body.append("")
        batch_body.append(f"POST {dataverse_url}/{table_name}s HTTP/1.1")
        batch_body.append("Content-Type: application/json")
        batch_body.append("")
        batch_body.append(json.dumps(record))  # Convert dictionary to JSON

        i+=1

    # Close changeset
    batch_body.append(f"--{changeset_guid}--")

    # Close batch
    batch_body.append(f"--{batch_guid}--")

    # Send batch request
    response = requests.post(f"{dataverse_url}/$batch",
                             headers=headers,
                             data="\r\n".join(batch_body))  # Important: Use "\r\n" for proper formatting

    # Handle response
    if response.status_code in [200, 204]:
        print("Batch data uploaded successfully.")
    else:
        print(f"Error uploading batch data: {response.status_code} - {response.text}")

def get_data_from_dataverse(oauth_token, dataverse_url, table_name, column_indexes=None):
    """
    Fetch all data from a Dataverse table with pagination, returning user-defined columns as a 2D list.

    Args:
        oauth_token (str): a Delegated access token.
        dataverse_url (str): Base URL of the Dataverse instance.
        table_name (str): Table name (singular, "s" is added automatically).
        column_indexes (list, optional): List of column indexes (zero-based) to retrieve.
                                         If None, all user-defined columns are returned.

    Returns:
        list: 2D list where the first row contains column names and subsequent rows contain data.
    """

    if not oauth_token:
        print("Error: No OAuth token available. Retrieve a token first.")
        return None

    endpoint = f"{dataverse_url}/{table_name}s"
    headers = {
        "Authorization": f"Bearer {oauth_token}",
        "Accept": "application/json",
        "OData-Version": "4.0"
    }

    all_data = []
    next_link = endpoint  # Start with the first page

    while next_link:
        response = requests.get(next_link, headers=headers)
        
        if response.status_code != 200:
            print(f"Error fetching data: {response.status_code}")
            print("Response:", response.text)
            return None

        response_json = response.json()
        data = response_json.get("value", [])
        
        if not data:
            break  # No more data to fetch

        # Extract column names from the first record and filter out system columns
        if not all_data:  # Only process headers once
            first_record = data[0]
            user_defined_columns = [col for col in first_record.keys() if not col.startswith("@odata")]

            # If column indexes are provided, filter only those columns
            if column_indexes is not None:
                user_defined_columns = [user_defined_columns[i] for i in column_indexes if i < len(user_defined_columns)]
            
            # Add headers as the first row
            all_data.append(user_defined_columns)

        # Append records
        all_data.extend([[record.get(col, None) for col in user_defined_columns] for record in data])

        # Get the next page URL (if available)
        next_link = response_json.get("@odata.nextLink")

    return all_data

def format_date(date_string):
    """Convert date string to the required format 'yyyy-MM-ddTHH:mm:ssZ'."""
    try:
        # Parse the date string and convert to the required format
        date_obj = datetime.strptime(date_string, "%Y-%m-%d")
        return date_obj.strftime("%Y-%m-%dT%H:%M:%SZ")  # ISO 8601 format
    except ValueError:
        # If parsing fails, return the original string (assuming it's already in correct format)
        return date_string






























#######################################################################################################################################################################################################

#for lakehouse
OUTPUT_FILE = "./output_csv/output_sap.csv"

#for logging
GSPREAD_SS = "GPS VEHICLE LIVE DATA - ALL PLATFORMS"
GPSREAD_WS = "testtest"
ROW_LOGS = 10

worksheet = set_gspread(GSPREAD_SS,GPSREAD_WS)
set_rowlogs(ROW_LOGS,name=GPSREAD_WS)


SAP_MASTERDATA = dict(get_sheet_data("SAP - SRC & DST")[1:]) 


#DV
TOKEN_NAME = "dv1"
TABLE_NAME = "F_TEMP_SAP"
DATAVERSE_URL = "https://orge27ae0c3.api.crm5.dynamics.com/api/data/v9.2"

set_credentials()



token = get_sheet_data("Tokens","B2")[0][0]

print(f"Succesfully retrieved token: {token[:20]}...{token[len(token)-20:]} (Truncated).")


def dv_prep():

    table_ids = get_or_cache(TABLE_NAME, list_tables, token, DATAVERSE_URL) # Get column names from cache or fetch from Dataverse
    table_id = table_ids[TABLE_NAME]
    dataverse_col_names = get_or_cache("dv_cols", get_col_logical_names, token, DATAVERSE_URL, table_id) # prep

    return table_id, dataverse_col_names

dv_prep()


app = Flask(__name__)
CORS(app, resources={r"/api/upload": {"origins": "*"}})  # end point

@app.route("/api/upload", methods=["POST", "OPTIONS"])  # Allow both POST and OPTIONS
def handle_post():
    global token

    if request.method == "OPTIONS":
        return '', 204  # Respond to OPTIONS request with no content

    payload = request.json  # Receive JSON data
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

    oe = payload.get("id", "") # get oe

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
        SAP_MASTERDATA.get(payload.get("homebaseId", ""), ""),
        SAP_MASTERDATA.get(payload.get("locationId", ""), ""),
        payload.get("date", ""),
        payload.get("orderDate", ""),
    ]

    gmt_plus_8 = timezone(timedelta(hours=8)) #timezone Asia/Manila
    timestamp = datetime.now(gmt_plus_8).strftime("%Y-%m-%d %I:%M:%S %p")

    data += [
        timestamp
    ]

    print(f"[{timestamp}] Received: {oe}")

    response_dict = {
        "Uploaded OE": oe,
        "Date received": timestamp
    }

    # CHECK OE IF DUPLICATE ##############################################################################################################################################################

    check_oe = get_cache(oe)

    if check_oe:
        response_dict["DUPLICATE"] = "Duplicated OE received. Upload denied."
        print("Duplicated OE received. Upload denied.")
        return jsonify(response_dict), 409  # OE duplicate detected
    else:
        save_cache(oe,oe)

    # UPLAOD TO GSPREAD ################################################################################################################################################################
    try:
        for_upload = [headers, data]
        worksheet.append_rows(for_upload[1:])
        response_dict["gspread"] = "success"
    except Exception as e:
        print(f"[GSPREAD Upload failed] {e}")
        response_dict["gspread"] = "failed"


    # UPLOAD TO DATAVERSE ###############################################################################################################################################################
    try:
        table_id, dataverse_col_names = dv_prep()

        header = headers
        data = data

        header = to_logical_names(header,dataverse_col_names)

        f_data = to_dict([header, data])

        upload_data_to_dataverse(token,DATAVERSE_URL,table_id,f_data)

        response_dict["dataverse"] = "success"

    except Exception as e:
        print(f"[DATAVERSE Upload failed] {e}")
        response_dict["dataverse"] = "failed"



    return jsonify(response_dict), 200  # Respond with JSON data



def schedule_token_refresh():

    def Maintoken():
        global token
        token = get_sheet_data("Tokens","B2")[0][0]
        print(f"[Retrieved latest token] {token[:20]}...{token[len(token)-20:]} (Truncated).")

    while True:
        Maintoken()
        time.sleep(3600)



if __name__ == "__main__":
    print("Endpoint Initialized")
    threading.Thread(target=schedule_token_refresh, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, threaded=True) # run on local host


