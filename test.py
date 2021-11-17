import requests

ip = "192.168.43.111"

link = "http://" + ip + ":30030/api/audiomixer/volume"

headers = {"Content-type": "application/json"}

data = '{"control":"Master","value":"0.17"}'

response = requests.post(link , headers=headers, data=data)
print (response.json())