#!/usr/bin/env python
import requests
import json
import argparse

###### User Variables

username = 'admin'
password = 'Arista'
server1 = 'https://192.168.255.50'
baseAPI = server1+'/api/v1/rest/'

###### Rest of script.
connect_timeout = 10
headers = {"Accept": "application/json",
           "Content-Type": "application/json"}
requests.packages.urllib3.disable_warnings()
session = requests.Session()

def login(url_prefix, username, password):
    authdata = {"userId": username, "password": password}
    response = session.post(url_prefix+'/web/login/authenticate.do', data=json.dumps(authdata),
                            headers=headers, timeout=connect_timeout,
                            verify=False)
    if response.json()['sessionId']:
        return response.json()['sessionId']

def logout(url_prefix):
    response = session.post(url_prefix+'/web/login/logout.do')
    return response.json()

def getActiveDevices(url_prefix):
    response = session.get(url_prefix+'/analytics/DatasetInfo/Devices')
    devices = response.json()
    activeDevices = []
    for item in devices['notifications']:
        for switch in item['updates']:
            if item['updates'][switch]['value']['status'] == 'active':
                activeDevices.append({item['updates'][switch]['key']: {'hostname': item['updates'][switch]['value']['hostname']}})
    return activeDevices

def getMACTable(url_prefix,device):
    deviceID = device.keys()[0]
    hostname = device[device.keys()[0]]['hostname']
    response = session.get(url_prefix+deviceID+'/Smash/bridging/status/smashFdbStatus')
    if response.json()['notifications']:
        localMACs = response.json()['notifications']
        macList = []
        for mac in localMACs:
            for macvalue in mac['updates']:
                macintf = mac['updates'][macvalue]['value']['intf']
                mactype = mac['updates'][macvalue]['value']['entryType']['Name']
                macAddr = mac['updates'][macvalue]['value']['key']['addr']
                macVLAN = mac['updates'][macvalue]['value']['key']['fid']['value']
                macOutput = {macvalue: {'intf': macintf, 'addr': macAddr, 'vlan': str(macVLAN), 'type': mactype, 'hostname': hostname}}
                macList.append(macOutput)
        return macList
    else:
        return

def getARPTable(url_prefix,device):
    deviceID = device.keys()[0]
    hostname = device[device.keys()[0]]['hostname']
    response = session.get(url_prefix + deviceID + '/Smash/arp/status/arpEntry')
    if response.json()['notifications']:
        localARPs = response.json()['notifications']
        arpList = []
        for arp in localARPs:
            for arpvalue in arp['updates']:
                arpAddr = arp['updates'][arpvalue]['value']['ethAddr']
                arpIP = arp['updates'][arpvalue]['value']['key']['addr']
                arpintf = arp['updates'][arpvalue]['value']['key']['intfId']
                arpOutput = {arpvalue: {'intf': arpintf, 'ipAddr': arpIP, 'macAddr': arpAddr, 'hostname': hostname}}
                arpList.append(arpOutput)
        return arpList
    else:
        return

def findMAC(macSearch):
    activeDevices = getActiveDevices(baseAPI)
    globalMacTable = []
    result = []
    for device in activeDevices:
        macTable = getMACTable(baseAPI, device)
        if macTable:
            globalMacTable.extend(macTable)
    for item in globalMacTable:
        for macKey in item:
            if item[macKey]['addr'] == macSearch:
                result.append(['Mac Address ' + macSearch + ' found on ' + item[macKey]['hostname'] + ' VLAN' +
                               item[macKey]['vlan']+' '+item[macKey]['intf']+' type '+item[macKey]['type']])
    return result

def findIP(ipSearch):
    activeDevices = getActiveDevices(baseAPI)
    globalARPTable = []
    result = []
    for device in activeDevices:
        arpTable = getARPTable(baseAPI, device)
        if arpTable:
            globalARPTable.extend(arpTable)
    for item in globalARPTable:
        for arpKey in item:
            if item[arpKey]['ipAddr'] == ipSearch:
                result.append(['IP Address ' + ipSearch + ' found on ' + item[arpKey]['hostname'] + ' with MAC ' +
                               item[arpKey]['macAddr']+' at '+item[arpKey]['intf'],item[arpKey]['macAddr']])
    return result

def parseArgs():
   parser = argparse.ArgumentParser( description='CVP MAC/IP Search' )
   parser.add_argument('--mac', help='Search for specific mac address, in 00:11:22:33:44:55 format.', type=str)
   parser.add_argument('--ip', help='Search for specific IP address (also finds MAC)', type=str)
   args = parser.parse_args()
   return args

def main():
    options = parseArgs()
    login(server1, username, password)
    if options.ip:
        ipSearch = options.ip
        ipOutput = findIP(ipSearch)
        for item in ipOutput:
            print item[0]
            if item[1]:
                macOutput = findMAC(item[1])
                for macadd in macOutput:
                    print macadd[0]
    elif options.mac:
        macSearch = options.mac
        macOutput = findMAC(macSearch)
        for macadd in macOutput:
            print macadd[0]
    logout(server1)

if __name__ == "__main__":
  main()
