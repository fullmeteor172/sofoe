from datetime import datetime
from enum import Enum
import http
from http import client
import json
import logging
import os
import re
import socket
import ssl
import time
from urllib.parse import urlparse
import requests

class Client_type(Enum):
    MOBILE = 1
    DESKTOP = 2
    
    def __str__(self):
        return self.name

class Request_type(Enum):
    POST = 1
    GET = 2
    
class Portal_action(Enum):
    LOGIN = 1
    LOGOUT = 2
    ACK = 3
    
class Server_response(Enum):
    LOGIN_SUCCESSFUL = 1
    LOGOUT_SUCCESSFUL = 2
    MAX_DEVICES_REACHED = 3
    INVALID_CREDENTIALS = 4
    
    def __str__(self):
        return self.name
        
class Global:
    username = None
    password = None
    
    client_type = None
    wan_state = None
    does_portal_exist = False
    portal_url = None
    time_of_last_login = None
    time_of_start = None
    time_of_last_ack = None
    last_server_message = None
    
    user_agent = None
    
    
class Utility:
    #Sets global vars of username and password from the .json file
    def get_creds_from_json(path_to_json: str):
        try:
            f = open(path_to_json, 'r')
            creds = json.loads(f.read())
            Global.username = creds['username']
            Global.password = creds['password']
        except Exception as e:
            logging.error(e)
            print('credentials.json could NOT be found')
            
    #Returns True if site is reached, else returns False
    def gstatic_connect_test():
        try:
            return 204 == requests.get('http://connectivitycheck.gstatic.com/generate_204',
                                timeout= 3).status_code
        except Exception:
            logging.debug('Gstatic connectivity check failed')
            return False
        
    #Returns True if site is reached, else returns False
    def msft_connect_test():
        try:
            response = requests.get(
                'http://www.msftconnecttest.com/connecttest.txt',
                timeout=4)
            data = response.text
            return data == 'Microsoft Connect Test'
        except Exception as e:
            logging.debug("Failed to comeplete msftconnect test")
            return False
        
    #If portal found returns its URL else returns False
    def find_captive_portal():
        #Tries connecting to msft connect
        try:
            response = requests.get(
                'http://www.msftconnecttest.com/connecttest.txt',
                timeout=4)
            data = response.text
            if response.status_code == 200:
                #A site was reached
                if response.text != 'Microsoft Connect Test':
                    #Was redirected to a captive portal
                    #Using regex to get the url of the portal
                    host_url = re.findall("https://.+(?=' )", data)[0]
                    logging.info(f'Portal found: {host_url}') 
                    Global.does_portal_exist = True
                    return host_url
                else:
                    logging.info('WAN was UP before portal could be found')
                    return False
        except Exception:
            logging.debug('Failed to reach msft-connect or a portal')
            Global.does_portal_exist = False
            return False
    
    #Returns headers for POST and GET requests
    def header_generator(uni_host: str, payload_length: int, request_type: Request_type):
        url_parse = urlparse(uni_host)
        headers = {
        'Host': f'{url_parse.hostname}:{url_parse.port}',
        'User-Agent': Global.user_agent,
        'Accept': ' */*',
        'Accept-Language': ' en-US,en;q=0.5',
        'Accept-Encoding': ' gzip, deflate, br',
        'Content-Type': ' application/x-www-form-urlencoded',
        'DNT': ' 1',
        'Connection': ' keep-alive',
        'Referer': uni_host,
        'Sec-Fetch-Dest': ' empty',
        'Sec-Fetch-Mode': ' cors',
        'Sec-Fetch-Site': ' same-origin',
        'Sec-GPC': ' 1'
        }

        if request_type == Request_type.POST:
            headers['Content-Length'] = str(payload_length)
            headers['Origin'] = uni_host
        
        return headers
    
    def get_product_type():
        if Global.client_type == Client_type.MOBILE:
            return 2
        else:
            return 0
    
    #Returns payload string for sophos POST request
    def payload_generator(portal_action: Portal_action):
        epoch_time = int(time.time()*1000)
        mode = None
        creds_field = f'username={Global.username}'
        
        if portal_action == Portal_action.LOGIN:
            mode = '191'
            creds_field += f'&password={Global.password}'
        
        elif portal_action == Portal_action.LOGOUT:
            mode = '193'

        elif portal_action == Portal_action.ACK:
            mode = '192'

        product_type = Utility.get_product_type()
        
        payload = f'mode={mode}&{creds_field}&a={epoch_time}&producttype={product_type}'
        return payload
    
    #Method to log changes of the WAN State
    def is_wan_up():
        current_wan_state = Utility.gstatic_connect_test()
        
        #Logging Logic
        if current_wan_state != Global.wan_state:
            #There was a change in state
            Global.wan_state = current_wan_state
            if current_wan_state:
                logging.info('WAN is UP')
            else:
                logging.warning('WAN is DOWN')
                
        return current_wan_state
    
    def print_logo(scriptState: str):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""
--------------v3.10---------------
   _____ ____  __________  ______
  / ___// __ \/ ____/ __ \/ ____/
  \__ \/ / / / /_  / / / / __/   
 ___/ / /_/ / __/ / /_/ / /___   
/____/\____/_/    \____/_____/
----------{scriptState}----------
       F*ck captive portals""")
    
    def print_states():
        print('      ~ Ctrl + C to Stop! ~')
        print(f'\n\nUsername:\t{Global.username}')
        print(f'Client Type:\t{Global.client_type}')
        print(f'Internet Up:\t{Global.wan_state}')
        print(f'Portals Msg:\t{Global.last_server_message}')
        
        print(f'Portal Found:\t{Global.does_portal_exist}')
        print(f'Portal URL:\t{Global.portal_url}')
        print(f'Logged In At:\t{Global.time_of_last_login}')
        print(f'Running Since:\t{Global.time_of_start}')
        
        if Global.client_type == Client_type.DESKTOP:
            print(f'Last Ack At:\t{Global.time_of_last_ack}')
        
    def change_client_type():
        if Global.client_type == Client_type.MOBILE or Global.client_type == None:
            Global.client_type = Client_type.DESKTOP
            Global.user_agent = 'Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1'
        else:
            Global.client_type = Client_type.MOBILE
            Global.user_agent = 'Mozilla/5.0 (Android 13; Mobile; rv:68.0) Gecko/68.0 Firefox/104.0'
        
        logging.info(f'Client type changed to {Global.client_type}')

def get_req(uni_host: str):
    #Initialization Stuff
    host_name = urlparse(uni_host).hostname
    host_port = urlparse(uni_host).port
    conn = http.client.HTTPSConnection(
                                    host_name,
                                    host_port,
                                    context=ssl._create_unverified_context(),
                                    timeout = 4
                                    )

    response = None
    headers = Utility.header_generator(uni_host, 0, Request_type.GET)
    url_tail = f'/live?{Utility.payload_generator(Portal_action.ACK)}'
    payload = ''
    #Request stuff
    try:
        conn.request("GET", url_tail, payload, headers)
    except socket.timeout as st:
        logging.warning('GET request to server timed out')
        
    except client.HTTPException as e:
        logging.warning("GET request returned error")
    else:
        response = conn.getresponse()
    finally:
        if response != None: parse_server_response(response)
        conn.close()
        return response

def post_req(uni_host: str, portal_action: Portal_action):
    
    #Initialization Stuff
    host_name = urlparse(uni_host).hostname
    host_port = urlparse(uni_host).port
    conn = http.client.HTTPSConnection(
                                    host_name,
                                    host_port,
                                    context=ssl._create_unverified_context(),
                                    timeout = 4
                                    )

    payload = Utility.payload_generator(portal_action)
    response = None
    if portal_action == Portal_action.LOGIN:
        actstr = 'login'
    else:
        actstr = 'logout'

    headers = Utility.header_generator(uni_host, len(payload), Request_type.POST)
    
    #Request stuff
    try:
        conn.request('POST', f'/{actstr}.xml', payload, headers)
    except socket.timeout as st:
        logging.warning('POST request to server timed out')
        
    except client.HTTPException as e:
        logging.warning("POST request returned error")
    else:
        response = conn.getresponse()
    finally:
        if response != None: parse_server_response(response)
        conn.close()
        return response

def parse_server_response(response):
    data = response.read().decode('UTF-8')
    
    if re.search("Y.+}", data) != None:
        logging.info('Logged In Succesfully')
        Global.last_server_message = Server_response.LOGIN_SUCCESSFUL
        Global.time_of_last_login = datetime.now()
        
    elif re.search(";v.+t]", data) != None:
        logging.info('Logged Out Successfully')
        Global.last_server_message = Server_response.LOGOUT_SUCCESSFUL
    
    elif re.search("<l.+e><ack><!.+k]]", data) != None:
        logging.debug('Server Acknowledgement Successful')
        Global.time_of_last_ack = datetime.now()
        
    elif re.search("Invalid.+admin", data) != None:
        logging.info('Invalid Credentials')
        Global.last_server_message = Server_response.INVALID_CREDENTIALS
        print('\n\n!! Invalid Credentials, Check credentials.json and run again. !!')
        exit()
    
    elif re.search("Y.+max.+limit", data) != None:
        Global.last_server_message = Server_response.MAX_DEVICES_REACHED
        logging.debug('Max Devices Reached')
        


def main():
    try:
        program_loop()
    except KeyboardInterrupt:
        pause_menu()

def program_loop():
    exit_flag = False
    loop_counter = 0 #Needed for sending ack req for DESKTOP Client mode
    while not exit_flag:
        loop_counter += 1
        Utility.print_logo('-- RUNNING! --')
        Utility.print_states()
        time.sleep(3)
        if not Utility.is_wan_up():
            #When internet is down look for a portal
            portal_url = Utility.find_captive_portal()
            if portal_url != False:
                #A portal was found
                Global.portal_url = portal_url
                
                #Attempt to auto-login
                try:
                    post_req(uni_host=portal_url, portal_action=Portal_action.LOGIN)
                except Exception as e:
                    logging.error(e)
        else:
            #When WAN is up
            if Global.client_type == Client_type.DESKTOP and loop_counter >= 10 and Global.portal_url != None:
                try:
                    get_req(Global.portal_url)
                    loop_counter = 0
                except Exception as e:
                    logging.error(e)
                
                
                
def pause_menu():
    Utility.print_logo('-- STOPPED! --')
    
    print(f'\nPortals Msg:\t{Global.last_server_message}')
    print(f'Client type:\t{Global.client_type}')
    print('\n\nAvailable Options:')
    disable_logout_option = (Global.portal_url == None)
    if not disable_logout_option:
        print('[ 1 ] Logout and Exit')
        print('[ 2 ] Just Logout')
    else:
        print('[ ! ] Logout options temporarily unavailable')
        print('[ ! ] No portal found to logout from')
    print('[ 3 ] Just Exit')
    print('[ 4 ] Resume Script')
    print('[ 5 ] Change Client type')
    
    try:
        user_input = int(input('\nYour choice: '))
    except ValueError as e:
        pause_menu()
    
    if user_input == 1 and (not disable_logout_option):
        post_req(Global.portal_url, Portal_action.LOGOUT)
        Utility.is_wan_up()
        exit()
    elif user_input == 2 and (not disable_logout_option):
        post_req(Global.portal_url, Portal_action.LOGOUT)
        Utility.is_wan_up()
        pause_menu()
    elif user_input == 3:
        exit()
    elif user_input == 4:
        main()
    elif user_input == 5 and (not disable_logout_option):
        post_req(Global.portal_url, Portal_action.LOGOUT)
        Utility.change_client_type()
        post_req(Global.portal_url, Portal_action.LOGIN)
        pause_menu()
        
    elif user_input == 5 and disable_logout_option:
        Utility.change_client_type()
        pause_menu()
    else:
        pause_menu()

if __name__ == '__main__':
    Global.time_of_start = datetime.now()
    logging.basicConfig(level=logging.INFO,
                        filename='app.log',
                        format='%(asctime)s -\t%(levelname)s\t%(message)s')
    logging.info('Script Started')
    Utility.get_creds_from_json('credentials.json')
    Utility.change_client_type()
    main()