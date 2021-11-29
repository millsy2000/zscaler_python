import requests
import json
import vmanage
import time
from lib.cprint import cprint

config = {
        "vmanage_user": 'admin',
        "vmanage_password": 'admin',
        "vmanage_address": '192.168.0.230',
        "vmanage_port": 443,
        "vmanage_user_defined_entries": [],
        "retries": 5,
        "timeout": 30,
        "ssl_verify": False,
        "http_proxy": False,
        "https_proxy": False
         }

verbose = True
dry = False
zscloudapac_list = []
zscloudamerica_list = []
zscloudemea_list = []

def main() -> None:



    ipv6 = "Null"
    headers = {
        "Content-Type":"application/json",
        "Accept":"application/json"
    }
    if verbose:
        cprint("Setting content headers: {}".format(headers), "purple")

    if verbose:
        cprint("Retrieving Session Token", "purple")
    s, headers['X-XSRF-TOKEN'] = vmanage.getSession(config["vmanage_address"], 
        config["vmanage_user"], 
        config["vmanage_password"], 
        config["ssl_verify"]
    )
    if verbose:
        cprint("Session Token: {}".format(headers['X-XSRF-TOKEN']), "green")
        cprint("Retrieving Data Prefix List", "purple")
    
    
    if verbose:
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


      
    data_prefix_list = [{
       "prefixes" : zscloudapac_list,"data_prefix_list" : "zscloudapac_list"},
	{"prefixes" : zscloudemea_list, "data_prefix_list" : "zscloudemea_list"},
	{"prefixes" : zscloudamerica_list, "data_prefix_list" : "zscloudamerica_list"}]

    if verbose:
        cprint("Updating data prefix list", "purple")
    
    for x in data_prefix_list:
     if verbose:
      cprint("Updating Data Prefix for: {}".format(x["data_prefix_list"]), "Purple")
     pol_id = updateDataPrefix(s,x, headers)
     if verbose:
        cprint("Policy ID is : {}".format(pol_id))
     if len(pol_id) < 1:
        cprint("Referenced Policies not found", "red")
        exit()
     if verbose or dry:
      cprint("Activating Policy: {}".format(pol_id), "purple")
     updatevSmartPolicy(s,pol_id, headers)
     cprint("Waiting for previous Policy to apply", "Purple")
     time.sleep(15)


    if verbose:
        cprint("Successfully updated poicies.", "green")

def updateDataPrefix(s,zscaler_region, headers):
    ipv6 = "Null"
    #cprint("Updating Data Prefix For: {}".format(zscaler_region["data_prefix_list"]), "Purple")
    data_prefix_list = vmanage.getDataPrefixList(s, 
        config["vmanage_address"], 
        config["vmanage_port"], 
        zscaler_region["data_prefix_list"], 
        config["ssl_verify"],
        verbose
    )
    pol_id = vmanage.updateDataPrefixList(s, 
        config["vmanage_address"], 
        config["vmanage_port"], 
        data_prefix_list, 
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

main()
