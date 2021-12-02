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

config = {
        "vmanage_user": 'admin',
        "vmanage_password": 'admin',
        "vmanage_address": '192.168.0.230',
        "vmanage_port": 8443,
        "vmanage_user_defined_entries": [],
        "retries": 5,
        "timeout": 10,
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
      
    data_prefix_list = [{
    "prefixes" : zscloudapac_list,"data_prefix_list" : "zscloudapac_list"},
    {"prefixes" : zscloudemea_list, "data_prefix_list" : "zscloudemea_list"},
    {"prefixes" : zscloudamerica_list, "data_prefix_list" : "zscloudamerica_list"},
    {"prefixes" : zscalerapac_list,"data_prefix_list" : "zscalerapac_list"},
    {"prefixes" : zscaleremea_list, "data_prefix_list" : "zscaleremea_list"},
    {"prefixes" : zscaleramerica_list, "data_prefix_list" : "zscaleramerica_list"}
    ]
    lists = len(data_prefix_list)
        
    cprint("\n###################################", "green")
    cprint("Updating vManage Data Prefix Lists", "yellow")
    cprint("There are {} lists to update".format(lists), "yellow")
    cprint("###################################\n", "green")

    s,headers = getvManageSession()

    for x in data_prefix_list:
     #Iterate through Zscaler list update vManage Data Prefix lists
     
     cprint("\nUpdating Data Prefix for: {}".format(x["data_prefix_list"]), "Purple")
     cprint("There are {} prefixes in this data set".format(len(x["prefixes"])),"Green")
     
     pol_id = updateDataPrefix(s,x, headers)    
     
     cprint("Successfully updated Data Prefix List: {}".format(x["data_prefix_list"]), "green")
     lists=lists-1
     cprint("Number of Prefixes left to complete: {}".format(lists))
    
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
    pol_id = vmanage.updateDataPrefixList(s, 
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
    return pol_id

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
    

main()
