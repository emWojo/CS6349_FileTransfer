ntent-type": "application/json"}

data = '{"control":"Master","value":"0.17"}'

response = requests.post(link , headers=headers, data=data)
print (response.json())