#!/usr/bin/python2.7
#title           :OCI-Fortigate-HAscript.py
#description     :Fortigate Active/Passive HA worker node script.
#author          :Vikram Gogte
#email           :vgogte@fortinet.com
#date            :11/04/2017
#version         :0.1
#usage           :python2.7 OCI-Fortigate-HAscript.py
#notes           :The script will monitor Active Fortigate and failover to Passive Fortigate
#                :when ping to Active Fortigate Eth0 Interface fail and vice versa.
#                :This script will run on worker node in OCI environment.
#                :Read OCI-Fortigate-HAscript-Readme.md for more detailed information.
#                :
#python_version  :2.7
#==============================================================================

# Import the modules needed to run the script.
import json
import requests
import string
import time
import os

""" Example OCI Environment parameters. Set the parameters for user credentials and environment.

    Eg.
    Fortinet Oracle Identity Domain : Compute-586773911 or Compute-acme
    User : jack@acme.com
    Password : YourPassword
    Fortinet Oracle Account Endpoint : https://api-z61.compute.us6.oraclecloud.com/authenticate/
    Instance1 : Fortigate1
    Instance2 : Fortigate2
    Route1 : DefaultRoute1
    Route2 : DefaultRoute2
    FloatingPublicIP : PublicIP provided by OCI through IP Reservation.

"""
# Global OCI environment variables. Input OCI parameters before executing the script.
OCI_Identity_Domain = ""
OCI_User = ""
OCI_Password = ""
OCI_Endpoint = ""
Floating_Public_IP = ""

# Global Fortigate variables in OCI environment. InputParamaters before executing the script.
Instance1 = ""
Instance2 = ""
Route1 = ""
Route2 = ""

# Function to get routing information of a route.
def oci_get_ip_route(route,compute_cookie):

    uri = "https://api-z61.compute.us6.oraclecloud.com/network/v1/route/"+OCI_Identity_Domain+'/'+OCI_User+'/'+route
    headers={'Cookie':compute_cookie,'Accept':'application/oracle-compute-v3+json'}

    r = requests.get(uri,headers=headers)
    route_data=r.json()

    return route_data

# Function to update the adminDistance of the route in OCI in case of failover.
def oci_update_ip_route(route_data,route,distance,compute_cookie):

    uri = "https://api-z61.compute.us6.oraclecloud.com:443/network/v1/route"+route_data['name']
    headers={'Cookie':compute_cookie,'content-type': 'application/oracle-compute-v3+json','Accept':'application/oracle-compute-v3+json'}
    name = '/'+OCI_Identity_Domain+'/'+OCI_User+'/'+route

    payload = {
    "adminDistance": distance,
    "description": route_data['description'],
    "ipAddressPrefix": route_data['ipAddressPrefix'],
    "name": route_data['name'],
    "nextHopVnicSet": route_data['nextHopVnicSet'],
    "tags": [],
    "uri": route_data['uri']
    }

    r = requests.put(uri, data=json.dumps(payload), headers=headers)

    route_info=r.json()
    print "Route {} is assigned Admin Distance as {}.".format(route,route_info['adminDistance'])

# Function to get IP Associations of Public IP in OCI.
def oci_get_ip_associations(ip,compute_cookie):

    uri = "https://api-z61.compute.us6.oraclecloud.com/ip/association/"+OCI_Identity_Domain+'/'+OCI_User+'/'
    headers={'Cookie':compute_cookie,'Accept':'application/oracle-compute-v3+json'}

    r = requests.get(uri,headers=headers)
    data=r.json()

    for item in data['result']:
        if item['ip'] == ip:
            my_item = item
            break
    else:
        my_item= None

    ''' Return the Association for the Public IP
    '''
    print "Floating Public IP is associated to : {}".format(my_item['name'])
    return my_item['name'],my_item['parentpool']

# Function to delete IP Assocations in OCI.
def oci_delete_ip_association(ip_association,compute_cookie):

    uri = "https://api-z61.compute.us6.oraclecloud.com/ip/association"+ip_association
    headers={'Cookie':compute_cookie}

    r = requests.delete(uri,headers=headers)
    print "Delete IP association status: {}".format(r.status_code)

# Function to Assign IP association to Instance in case of failover condition.
def oci_assign_ip_association(instance_vcable,parent_pool,compute_cookie):

    uri = "https://api-z61.compute.us6.oraclecloud.com/ip/association/"
    headers={'Cookie':compute_cookie,'content-type': 'application/oracle-compute-v3+json','Accept':'application/oracle-compute-v3+json'}
    payload = {"parentpool": parent_pool, "vcable": instance_vcable}

    r = requests.post(uri, data=json.dumps(payload), headers=headers)

    assign_info=r.json()
    print "Floating Public IP Association is updated. Now IP Associated to {}".format(assign_info['name'])

    oci_get_ip_associations(Floating_Public_IP,compute_cookie)

# Function to get Vcable ID and Instance IP address on Eth0.
def oci_getvcable(instance,compute_cookie):

    uri = "https://api-z61.compute.us6.oraclecloud.com/instance/"+OCI_Identity_Domain+'/'+OCI_User+'/'+instance+'/'
    headers={'Cookie':compute_cookie,'Accept':'application/oracle-compute-v3+json'}
    r = requests.get(uri,headers=headers)
    data=r.json()

    print "Instance {} : Vcable_id : {}".format(instance,data['result'][0]['vcable_id'])
    print "Instance {} : Eth0 IP address : {}".format(instance,data['result'][0]['ip'])

    """return Vcable"""
    return data['result'][0]['vcable_id'],data['result'][0]['ip']

# Function to Authenticate user in OCI environment and set-cookie for calling REST API calls.
def oci_authenticate():

    uri = "https://api-z61.compute.us6.oraclecloud.com/authenticate/"
    payload = {'user':OCI_Identity_Domain+'/'+OCI_User,'password':OCI_Password}
    headers = {'content-type': 'application/oracle-compute-v3+json'}
    r = requests.post(uri, data=json.dumps(payload), headers=headers)
    return r.headers['Set-Cookie']

# Function to check the status of Active Fortigate by performing pings.
def ping_check(Active_Fortigate,Active_Fortigate_IP):

    response=os.system("ping -c 1 " + Active_Fortigate_IP +"> /dev/null")
    if response == 0:
        ping_status = "ok"
    else:
        ping_status = "error"

    return ping_status

# Function main(), all the script magic begins here.

def main():

    ''' Initiating the OCI Enviroment using the parameters.
    Call oci_authenticate() to authenticate with Oracle Cloud and set the
    Cookie for making REST API calls.
    '''
    compute_cookie = oci_authenticate()

    ''' Call oci_getvcable() to get vcable and nic0 ip address of instances.
    '''
    instance1_vcable,instance1_ip=oci_getvcable(Instance1,compute_cookie)
    instance2_vcable,instance2_ip=oci_getvcable(Instance2,compute_cookie)

    ''' Call oci_get_ip_associations to get information about Public IP associations.
    '''
    ip_association,parent_pool=oci_get_ip_associations(Floating_Public_IP,compute_cookie)

    ''' Set the Active Fortigate for initiatizing and also route in IP Network (eg. Default Route)
    '''

    Active_Fortigate = Instance1
    Active_Fortigate_IP = instance1_ip
    Active_Route = Route1

    TRUE = 1
    LOOP = 0
    error_count = 0
    while TRUE == 1:
        ping_status = ping_check(Active_Fortigate,Active_Fortigate_IP)
        if ping_status=='ok':
            print "Ping Check to Fortigate {} Eht0 IP {} is good.".format(Active_Fortigate,Active_Fortigate_IP)
            time.sleep(0.5)
        else:
            error_count = error_count + 1

            print "Ping Check to Fortigate {} Eht0 IP {} are Failing.".format(Active_Fortigate,Active_Fortigate_IP)
            ''' If the ping fails for 5 times, then switch the Public IP and Route Admin Distance on inside.'''
            if error_count >= 2:

                print "Ping checks to Active Fortigate failed. Failover triggered. Initiating Failover to Passive Fortigate."
                if Active_Fortigate == Instance1:
                    ''' If the Active Fortigate is Instance1, failover to Instance2 and set it as Active Fortigate.
                    '''
                    ip_association,parent_pool=oci_get_ip_associations(Floating_Public_IP,compute_cookie)
                    oci_delete_ip_association(ip_association,compute_cookie)
                    instance2_vcable,instance2_ip=oci_getvcable(Instance2,compute_cookie)
                    oci_assign_ip_association(instance2_vcable,parent_pool,compute_cookie)

                    route1_info = oci_get_ip_route(Route1,compute_cookie)
                    route2_info = oci_get_ip_route(Route2,compute_cookie)

                    oci_update_ip_route(route1_info,Route1,"2",compute_cookie)
                    oci_update_ip_route(route2_info,Route2,"0",compute_cookie)

                    error_count = 0
                    Active_Fortigate = Instance2
                    Active_Fortigate_IP = instance2_ip
                    print "After Failover, {} is now the Active Fortigate.".format(Active_Fortigate)

                else:
                    ''' If the Active Fortigate is Instance2, failover to Instance1 and set it as Active Fortigate.
                    '''

                    ip_association,parent_pool=oci_get_ip_associations(Floating_Public_IP,compute_cookie)
                    oci_delete_ip_association(ip_association,compute_cookie)
                    instance1_vcable,instance1_ip=oci_getvcable(Instance1,compute_cookie)
                    oci_assign_ip_association(instance1_vcable,parent_pool,compute_cookie)

                    route1_info = oci_get_ip_route(Route1,compute_cookie)
                    route2_info = oci_get_ip_route(Route2,compute_cookie)

                    oci_update_ip_route(route1_info,Route1,"0",compute_cookie)
                    oci_update_ip_route(route2_info,Route2,"2",compute_cookie)

                    error_count = 0
                    Active_Fortigate = Instance1
                    Active_Fortigate_IP = instance1_ip

                    print "After Failover, {} is now the Active Fortigate.".format(Active_Fortigate)


# Standard boilerplate to call the main() function to begin
# the program.
if __name__ == '__main__':
    main()


    
