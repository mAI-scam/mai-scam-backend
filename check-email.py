import requests
import json

url = "https://validation-aws.silverlining.cloud/email-address"

payload = json.dumps({
  "emailAddress": "support@silverlining.cloud"
})
headers = {
  'x-api-key': '3bCLguiR6B6zVSWjSZmNM3Q1ZACYfUCG9kLu0XOJ',
  'Content-Type': 'application/json'
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)