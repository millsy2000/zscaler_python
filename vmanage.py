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

def updateDataPrefixList(s: requests.sessions.Session, url: str, port: int, list_id: str, list_name: str, verify: bool, headers: dict, ipv4: list, ipv6: list, retries: int, timeout: int, user_defined_entries: list = [], verbose: bool = False, dry: bool = False, *args, **kwargs) -> str:
    data = {
        "name" :list_name,
        "entries": [
        ],
    }
    data1= {  
    "deviceIds": [
        "d406d5ba-bba2-411c-b13c-eda76ba0055a"
    ],
    "isEdited": "true",
    "isMasterEdited": "false",
    "templateId": "81e9830d-8801-4f80-a187-d77b08cbd6a7"
    }
    data2 = {
    "device": [
    {
      "csv-deviceIP": "7.7.7.108",
      "csv-deviceId": "d406d5ba-bba2-411c-b13c-eda76ba0055a",
      "csv-host-name": "vSmart"
    }
    ]
    }
    data3= {
    "deviceTemplateList": [
        {
            "templateId": "81e9830d-8801-4f80-a187-d77b08cbd6a7",
            "device": [
                {
                    "csv-status": "complete",
                    "csv-deviceId": "d406d5ba-bba2-411c-b13c-eda76ba0055a",
                    "csv-deviceIP": "7.7.7.108",
                    "csv-host-name": "vSmart",
                    "/0/vpn-instance/ip/route/0.0.0.0/0/next-hop/address": "10.10.1.1",
                    "//system/host-name": "vSmart",
                    "//system/system-ip": "7.7.7.108",
                    "//system/site-id": "1",
                    "csv-templateId": "81e9830d-8801-4f80-a187-d77b08cbd6a7"
                }
            ],
            "isEdited": "true",
            "isMasterEdited": "false"
        }
    ]
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

    success = False
    attempts = 1

    if verbose or dry:
        cprint("New Data Prefix List: {}".format(json.dumps(data, indent=2)), "green")

    if verbose:
        cprint("Putting new data prefix list data into vManage", "purple")
    while success == False and attempts <= retries:
        #if verbose or dry:
        cprint("Put request to: https://{}:{}/dataservice/template/policy/list/dataprefix/{}".format(url, port, list_id), "purple")
        if dry:
            success = True
            continue
        r = s.put("https://{}:{}/dataservice/template/policy/list/dataprefix/{}".format(url, port, list_id), headers=headers, verify=verify, data=json.dumps(data))
        cprint("response {}".format(r.json()),"red")
        processID = r.json()["processId"]
        cprint("ProcessID is: {}".format(processID),"yellow")
        r1 = s.post("https://{}:{}/dataservice/template/device/config/input/".format(url,port), headers=headers,verify=verify, data=json.dumps(data1))
        cprint("response1 {}".format(r1.json()),"green")
        time.sleep(2)
        r2 = s.post("https://{}:{}/dataservice/template/device/config/duplicateip".format(url,port), headers=headers,verify=verify, data=json.dumps(data2))
        cprint("response2 {}".format(r2.json()),"red")
        time.sleep(2)
        r3 = s.post("https://{}:{}/dataservice/template/device/config/attachfeature".format(url,port), headers=headers,verify=verify, data=json.dumps(data3))
        cprint("response3 {}".format(r3.json()),"green")
        time.sleep(30)
        r4 = s.put("https://{}:{}/dataservice/template/lock/{}".format(url,port,processID), headers=headers,verify=verify)
        cprint("response4 status {}".format(r4),"purple")
        time.sleep(2)
        if verbose:
            cprint("Response: {}".format(r.text), "yellow")
        if "error" in r.json().keys():
            cprint("\nError:\n ", "red")
            cprint(r.json()["error"]["message"], "yellow")
            print()
            cprint(r.json()["error"]["details"], "red")
            print()
            if attempts == retries:
                cprint("Exceeded attempts {} of {}".format(attempts, retries), "red")
                exit(-1)
            else:
                cprint("Trying again in {} seconds, attempt {} of {}".format(timeout, attempts, retries), "yellow")
            attempts += 1
            time.sleep(timeout)
        else:
            if verbose:
                cprint("Successfully loaded new data prefix list entries", "green")
            success = True
            continue

    if verbose or dry:
        cprint("Fetching activated ID from: https://{}:{}/dataservice/template/policy/list/dataprefix/{}".format(url, port, list_id), "purple")
    r = s.get("https://{}:{}/dataservice/template/policy/list/dataprefix/{}".format(url, port, list_id), headers=headers, verify=verify)
    if verbose:
        cprint("Response: {}".format(r.text), "yellow")
    js = r.json()
    pol_id = js["activatedId"] if 'activatedId' in js.keys() else ""
    cprint("pol_id is {}".format(pol_id),"red")
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

