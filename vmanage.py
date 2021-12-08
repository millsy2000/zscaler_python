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
import time
from lib.cprint import cprint
from lib import ipReg


def getSession(url: str, uid: str, pwd: str, verify: bool = True, verbose: bool = False, *args, **kwargs) -> tuple:  
    s = requests.session()
    if verbose:
        cprint("Initialising Session", 'purple')
        cprint("Logging in to https://{}/j_security_check".format(url), 'yellow')
    try:
        r = s.post("https://{}/j_security_check".format(url),data={"j_username":uid,"j_password":pwd}, verify=verify)
    except requests.exceptions.ConnectionError as e:
        cprint("Unable to establish session to vManage:\n  ", 'red', True)
        cprint(e,'yellow')
        exit()
    if verbose:
        cprint("Response: {}".format(r.text), 'green')
        cprint("Retrieving client XSRF token", 'purple')
    t = s.get("https://{}/dataservice/client/token".format(url))
    if verbose:
        cprint("Retrieving JSESSION ID", 'purple')
    j = s.cookies.get_dict()["JSESSIONID"]
    if verbose:
        cprint("JESSIONID: {}".format(j))
    if verbose:
        cprint("Response: {}".format(t.text), 'purple')
    t = t.text
    if b"<html>" in  r.content:
        cprint("vManage login failed", 'red')
        exit(-1)
    return s, t, j

def getDataPrefixList(s: requests.sessions.Session, url: str, port: int, list_name: str, verify: bool = True, verbose: bool = False, *args, **kwargs) -> str:
    if verbose:
        cprint("Retrieving data prefix list from: https://{}:{}/dataservice/template/policy/list/dataprefix".format(url, port), 'purple')
    r = s.get("https://{}:{}/dataservice/template/policy/list/dataprefix".format(url, port), verify = verify)
    if verbose:
        cprint("Response: {}".format(r.text), 'green')
    js = r.json()
    list_id = ""
    entries = js['data']
    if verbose:
     cprint("data response: {} ".format(entries), 'green')
    for entry in entries:
        if entry['name'] == list_name:
            list_id = entry["listId"]
            if verbose:
                cprint("list name matches configuration. listId: {}".format(list_id), 'purple')
    return list_id

def updateDataPrefixList(s: requests.sessions.Session, url: str, port: int, list_id: str, list_name: str, verify: bool, headers: dict, ipv4: list, ipv6: list, retries: int, timeout: int, user_defined_entries: list = [], verbose: bool = False, dry: bool = False, *args, **kwargs) -> list:

    data = {
         "name" : list_name,
         "entries" : [
         ],
         "isEdited" : True,
         "isMasterEdited" : False
    }
    if verbose:
        cprint("Creating data prefix list structure. ", "purple")
    for ip in ipv4:
        if verbose:
         cprint("Adding entry: {}".format(ip), "green")
        data["entries"].append({"ipPrefix":ip})
    
    
    if verbose:
        cprint("Processing user defined entries", "purple")
    for entry in user_defined_entries:
        if ipReg.isFQDN(entry):
            if verbose:
                cprint("FQDN Record: {}".format(entry), "green")
            records = getARecords(entry, config['dns_server'])
            if verbose:
                cprint("A Record(s): {}".format(records), "green")
            for record in records:
                if ipReg.isIPv4(record) and (record[-2] == "/" or record[-3] == "/"):
                    data["entries"].append({"ipPrefix":"{}".format(record)})
                    if verbose:
                        cprint("Adding CIDR Entry: {}".format(record), "purple")
                elif ipReg.isIPv4(record):
                    if verbose:
                        cprint("Adding /32 entry: {}/32".format(record), "purple")
                    data["entries"].append({"ipPrefix":"{}/32".format(record)})
            del records
        elif ipReg.isIPv4(entry):
            if verbose:
                cprint("Adding entry: {}".format(entry), "purple")
            data["entries"].append({"ipPrefix":"{}/32".format(entry) if '/' not in entry else entry})

    if verbose or dry:
        cprint("New Data Prefix List: {}".format(json.dumps(data, indent=2)), "green")

    if verbose:
        cprint("Putting new data prefix list data into vManage", "purple")
        #if verbose or dry:
        cprint("Put request to: https://{}:{}/dataservice/template/policy/list/dataprefix/{}".format(url, port, list_id), "purple")
    attempts = 0
    while attempts <= retries:
     try:
          r = s.put("https://{}:{}/dataservice/template/policy/list/dataprefix/{}".format(url, port, list_id), headers=headers, verify=verify, data=json.dumps(data))
          #if verbose:
          cprint("list/dataprefix Response: {}".format(r.json()),"green")
          time.sleep(2)
          masterTemplates=r.json()["masterTemplatesAffected"]
          r = s.get("https://{}:{}/dataservice/template/policy/list/dataprefix/{}".format(url, port, list_id), headers=headers, verify=verify)
          if verbose:
           cprint("Response: {}".format(r.text), "yellow")
          js = r.json()
          pol_id = js["activatedId"] if 'activatedId' in js.keys() else ""
          cprint("pol_id is {}".format(pol_id),"red")
          break
     except Exception as e:
          cprint("Exception: {} Waiting {} seconds to try again".format(e,timeout),"red")
          attempts = attempts+1
          cprint("Attempt number: {}".format(attempts),"red")
          time.sleep(timeout)
    return masterTemplates, pol_id
          
def activateTemplates(s: requests.sessions.Session, url: str, port: int, masterTemplates: list, verify: bool, headers: dict, timeout: int, retries: int, verbose: bool = False,  *args, **kwargs) -> str:
    attempts = 0
    while attempts <= retries:
     try:
        attach_post = {'deviceTemplateList': []}
        
        for x in masterTemplates:
         masterTemplate = x
         input_post = {"deviceIds" : [
                     ],
         "isEdited" : True,
         "isMasterEdited" : False,
         "templateId" : masterTemplate
         }

         attach_post_template = {'templateId': masterTemplate, 
         'device': [], 
         'isEdited': True, 
         'isMasterEdited': False
         }
 
         r=s.get("https://{}:{}/dataservice/template/device/config/attached/{}".format(url,port,x), headers=headers)
         for y in r.json()["data"]:
          input_post["deviceIds"].append(y["uuid"])
         r=s.post("https://{}:{}/dataservice/template/device/config/input/".format(url,port),headers=headers, data=json.dumps(input_post))
         for z in r.json()["data"]:
          z["csv-templateId"] = masterTemplate
          attach_post_template["device"].append(z)
         attach_post["deviceTemplateList"].append(attach_post_template)
        
        json_object = json.dumps(attach_post, indent=2)
        cprint("Attach Feature Data Is: {}".format(json_object),"yellow")
 
        r = s.post("https://{}:{}/dataservice/template/device/config/attachfeature".format(url,port), headers=headers, data=json.dumps(attach_post)) 
        attachid = r.json()["id"]
        time.sleep(3)
        break
     except Exception as e:
        cprint("Exception: {} Waiting {} seconds to try again".format(e,timeout),"red")
        attempts = attempts+1
        cprint("Attempt number: {}".format(attempts),"red")
        time.sleep(timeout)
        
    attempts = 0
    status = "in_progress"
    while attempts <= retries:
     try:
        while(status == "in_progress"):
         num_devices_left = 0
         r = s.get("https://{}:{}/dataservice/device/action/status/{}".format(url,port, attachid)).json()
         status = r["summary"]["status"]
         for x in r["data"]:
          if x["statusId"] == "in_progress":
           num_devices_left = num_devices_left + 1
         time.sleep(10)
         if status == "in_progress":
          cprint("Template activate still in progress, status is: {}".format(status),"yellow")
          cprint("Number of devices still being provisioned is: {}".format(num_devices_left),"yellow")
         if status == "done":
          cprint("Template activate complete, status is: {}".format(status),"green")
        time.sleep(1)
        if verbose:
            cprint("Response: {}".format(r.text), "yellow")

        if verbose or dry:
         cprint("Fetching activated ID from: https://{}:{}/dataservice/template/policy/list/dataprefix/{}".format(url, port, list_id), "purple")
        r = s.get("https://{}:{}/dataservice/template/policy/list/dataprefix/{}".format(url, port, list_id), headers=headers, verify=verify)
        if verbose:
         cprint("Response: {}".format(r.text), "yellow")
        js = r.json()
        pol_id = js["activatedId"] if 'activatedId' in js.keys() else ""
        cprint("pol_id is {}".format(pol_id),"red")
        break
     except Exception as e:
        cprint("Exception: {} Waiting {} seconds to try again".format(e,timeout),"red")
        attempts = attempts+1
        cprint("Attempt number: {}".format(attempts),"red")
        time.sleep(timeout)
    return pol_id

def activatePolicies(s: requests.sessions.Session, url: str, port: int, verify: bool, headers: dict, pol_id: str, retries: int, timeout: int, verbose: bool = False, dry: bool = False, *args, **kwargs) -> None:
    attempts = 1
    success = False
    while success == False and attempts <= retries:
        if verbose or dry:
            cprint("Posting to activate policy at: https://{}:{}/dataservice/template/policy/vsmart/activate/{}".format(url, port, pol_id), "purple")
        if dry:
            success = True
            return
        r = s.post("https://{}:{}/dataservice/template/policy/vsmart/activate/{}?confirm=true".format(url, port, pol_id), headers=headers, data="{}",verify=verify)
        if verbose:
            cprint("Response: {}".format(r.text))
        if r.status_code == 200:
            cprint("vSmart Activate Triggered", "green", True, True)
            success = True
        else:
            cprint(r.status_code, r.text)
            if attempts == retries:
                cprint("Exceeded attempts {} of {}".format(attempts, retries), "red")
                exit(-1)
            else:
                cprint("Trying again in {} seconds, attempt {} of {}".format(timeout, attempts, retries), "yellow")
            attempts += 1
            time.sleep(timeout)

