import requests
import json

url = "http://172.31.47.242:5000/api/upload"

payload = {
	"id": "",
	"type": "DROP",
	"sourceOrderId": "",
	"teamId": "",
	"lineItems": 
	[
		{
			"id": "",
			"quantity": "",
			"quantityUnit": "",
			"price": 
			{
				"amount": "",
				"currency": ""
			}
		}
	],
	"volume": {
		"value": "",
		"unit": ""
	},
	"customProperties": {
		"SO_REF" :"",
		"CLASS_CODE": "",
		"TRAN_TYPE": "",
		"CUSTOMER_PO": "",
		"TRUCKLOAD_NO":"",
		"LOAD_NO": "",
		"PAYMENT_TERMS" :"",
		"Homebase_Name_info": "",
		"Loading_Sequence": ""
	   },
	"homebaseId": "",
	"locationId": "",
	"date": "",
	"orderDate": ""
}

headers = {
    "Content-Type": "application/json"
}

try:
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()  # Raise an error for bad status codes
    data = response.json()

    print("Server Response:", data)
    print(f"Message: {data.get('message')}")
    print(f"Time: {data.get('timestamp')}")

except requests.exceptions.RequestException as e:
    print("Error:", e)