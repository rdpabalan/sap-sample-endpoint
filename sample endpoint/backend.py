from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

import gspread
import os
import json

try:
    from egm_connector import *
    print("Setting up connector successful")
except Exception as e:
   print(e)

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


