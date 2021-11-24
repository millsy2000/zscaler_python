import requests
import json

vmanage = {'host' : '192.168.0.230','username' : 'admin', 'password' : 'admin'}

zscloudjson = (requests.get("https://api.config.zscaler.com/zscloud.net/cenr/json")).json()
zscalerjson = (requests.get("https://api.config.zscaler.com/zscaler.net/cenr/json")).json()

zscloudapac = zscloudjson["zscloud.net"]["continent : APAC"]
zscloudemea = zscloudjson["zscloud.net"]["continent : EMEA"]
zscloudamerica = zscloudjson["zscloud.net"]["continent : Americas"]

zscalerapac = zscalerjson["zscaler.net"]["continent : APAC"]
zscaleremea = zscalerjson["zscaler.net"]["continent : EMEA"]
zscaleramerica = zscalerjson["zscaler.net"]["continent : Americas"]

print("\n\n")
print("ZScaler Cloud IPs")
print("\n\n")


for x in zscloudapac:
 print(x)
 for y in zscloudapac[x]:
  print(y["range"])

for x in zscaleremea:
 print(x)
 for y in zscaleremea[x]:
  print(y["range"])

for x in zscloudamerica:
 print(x)
 for y in zscloudamerica[x]:
  print(y["range"])
  
print("\n\n")
print("ZScaler IPs")
print("\n\n")

for x in zscalerapac:
 print(x)
 for y in zscalerapac[x]:
  print(y["range"])

for x in zscaleremea:
 print(x)
 for y in zscaleremea[x]:
  print(y["range"])

for x in zscaleramerica:
 print(x)
 for y in zscaleramerica[x]:
  print(y["range"])
