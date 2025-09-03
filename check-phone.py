import requests
import json

url = "https://validation-aws.silverlining.cloud/phone-number"

payload = json.dumps({
  "phoneNumber": "+43 670 5509930"
})
headers = {
  'x-api-key': '3bCLguiR6B6zVSWjSZmNM3Q1ZACYfUCG9kLu0XOJ',
  'Content-Type': 'application/json'
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)