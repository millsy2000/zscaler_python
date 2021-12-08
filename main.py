"""
Written by Craig B.
https://github.com/Phatkone
           ,,,
          (. .)
-------ooO-(_)-Ooo-------
"""
"""
Altered by millsy2000....
:)
"""

import requests
import json
import vmanage
import time
from lib.cprint import cprint
from itertools import chain

config = {
        "vmanage_user": 'admin',
        "vmanage_password": 'admin',
        "vmanage_address": '192.168.0.230',
        "vmanage_port": 8443,
        "vmanage_user_defined_entries": ["1.1.1.1/32", "2.2.2.2/32"],
        "retries": 5,
        "timeout": 300,
        "ssl_verify": False,
        "http_proxy": False,
        "https_proxy": False
         }

verbose = False
dry = False
zscloudapac_list = []
zscloudamerica_list = []
zscloudemea_list = []
zscalerapac_list = []
zscaleramerica_list = []
zscaleremea_list = []

def main() -> None:

   if config["ssl_verify"] == False:
    if verbose:
     cprint("Disabling SSL Verification", "purple")
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    ipv6 = "Null"
    templatename = input("Please enter name of feature template to update: ")

    cprint("Retrieving ZScaler Public IP Addresses", "purple")
    
    zscloudjson = requests.get("https://api.config.zscaler.com/zscloud.net/cenr/json").json()
    zscalerjson = (requests.get("https://api.config.zscaler.com/zscaler.net/cenr/json")).json()
    zscloudapac = zscloudjson["zscloud.net"]["continent : APAC"]
    zscloudemea = zscloudjson["zscloud.net"]["continent : EMEA"]
    zscloudamerica = zscloudjson["zscloud.net"]["continent : Americas"]
    zscalerapac = zscalerjson["zscaler.net"]["continent : APAC"]
    zscaleremea = zscalerjson["zscaler.net"]["continent : EMEA"]
    zscaleramerica = zscalerjson["zscaler.net"]["continent : Americas"]

    for x in zscloudapac:
     for y in zscloudapac[x]:
      zscloudapac_list.append(y["range"])
 
    for x in zscloudemea:
      for y in zscloudemea[x]:
       zscloudemea_list.append(y["range"])
      
    for x in zscloudamerica:
      for y in zscloudamerica[x]:
       zscloudamerica_list.append(y["range"]) 

    for x in zscalerapac:
     for y in zscalerapac[x]:
      zscalerapac_list.append(y["range"])
 
     for x in zscaleremea:
      for y in zscaleremea[x]:
       zscaleremea_list.append(y["range"])
      
     for x in zscaleramerica:
      for y in zscaleramerica[x]:
       zscaleramerica_list.append(y["range"]) 

    prefixes = []
    prefixes.append(zscloudapac_list)
    prefixes.append(zscloudemea_list)  
    prefixes.append(zscloudamerica_list)  
    prefixes.append(zscalerapac_list)  
    prefixes.append(zscaleremea_list)  
    prefixes.append(zscaleramerica_list)  
    prefixes.append(config["vmanage_user_defined_entries"])

    prefixes_unpacked = list(chain(*prefixes))
    prefixes_unpacked = list(dict.fromkeys(prefixes_unpacked))
    lists = len(prefixes_unpacked)
    
    cprint("\n###################################", "green")
    cprint("Updating vManage VPN Feature Template", "yellow")
    cprint("There are {} prefixes to upload".format(lists), "yellow")
    cprint("###################################\n", "green")

    s,headers = getvManageSession()

    #templates = updateDataPrefix(s,x, headers)
    templates = updateFeature(s, headers, prefixes_unpacked, templatename)
    activateTemplates(s, templates, headers)

    
def updateDataPrefix(s,zscaler_region, headers):
    ipv6 = "Null"
    
    cprint("Getting Data Prefix ID from vManage",'purple')
    data_prefix_list_id = vmanage.getDataPrefixList(s, 
        config["vmanage_address"], 
        config["vmanage_port"], 
        zscaler_region["data_prefix_list"], 
        config["ssl_verify"],
        verbose
    )
    cprint("Pushing updated Prefix list to vManage for {}".format(zscaler_region["data_prefix_list"]),'purple')
    templates = vmanage.updateDataPrefixList(s, 
        config["vmanage_address"], 
        config["vmanage_port"], 
        data_prefix_list_id, 
        zscaler_region["data_prefix_list"], 
        config["ssl_verify"], 
        headers, 
        zscaler_region["prefixes"], 
        ipv6, 
        config["retries"], 
        config["timeout"], 
        config["vmanage_user_defined_entries"],
        verbose,
        dry
    )
    return templates, pol_id

def updatevSmartPolicy(s,pol_id, headers):
    for id in pol_id:
        vmanage.activatePolicies(s, 
            config["vmanage_address"], 
            config["vmanage_port"], 
            config["ssl_verify"], 
            headers, 
            id, 
            config["retries"], 
            config["timeout"],
            verbose,
            dry
        )
def getvManageSession():
 headers = {
    "Content-Type":"application/json",
    "Accept":"application/json"
    }
 if verbose:
        cprint("Setting content headers: {}".format(headers), "purple")    
 
 cprint("Retrieving Session Token", "purple")
 s, headers['X-XSRF-TOKEN'], j = vmanage.getSession(config["vmanage_address"], 
        config["vmanage_user"], 
        config["vmanage_password"], 
        config["ssl_verify"]
    )
 headers["Cookie"]="JSESSIONID={}".format(j)   
 if verbose:
  cprint("Session Token: {}".format(headers['X-XSRF-TOKEN']), "green")
 if verbose:
  cprint("{}".format(headers["Cookie"]), "green")
 return s, headers
 
def activateTemplates(s, templates, headers):
 pol_id = vmanage.activateTemplates(s,
       config["vmanage_address"],
       config["vmanage_port"],
       templates,
       config["ssl_verify"],
       headers,
       config["timeout"],
       config["retries"],
       verbose
      )
 return pol_id

def updateFeature(s,headers, prefixes, templatename):
 cprint("Updating feature template {} with {} prefixes".format(templatename, len(prefixes)),'purple')
 templates = vmanage.updateFeatureTemplate(s,
       config["vmanage_address"],
       config["vmanage_port"],
       config["ssl_verify"],
       headers,
       prefixes,
       templatename,
       config["retries"],
       config["timeout"],
       verbose
      )
 return templates
       

main()
