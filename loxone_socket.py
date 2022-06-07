#Loxone Websocket Demo (developed on Python 3.7.7, Thonny)
#This is a demo program to establish a websocket connection to the loxone miniserver
#Referencing https://www.loxone.com/dede/wp-content/uploads/sites/2/2020/05/1100_Communicating-with-the-Miniserver.pdf
#This is a quite crappy documentation
#Here's the summary for a Miniserver Ver.1
#Due to security requirements, the communication between Miniserver and client needs to be encrypted
#In order to allow random clients to connect, a fixed shared secret cannot be used. However, as en encryption
#mechanism AES was chosen, which is a symmetric cryptographic method meaning the keys are the same on receiving
#and sending end. To overcome this, the client will define which AES key/iv to use and let the Miniserver know.
#To do so, the Miniserver provides its public RSA key to allow an assymetric encryption to be used for sending
#the AES key/iv pair. RSA limits the size of the payload - that's why it is not an option to only use RSA
#Furthermore, to authenticate, nowadays a token is used instead of user/password for each request.
#So, generally you could say we are:
# 1) Defining the AES Key and IV on the client side (in this program)
# 2) Retrieving the RSA public key and encrypting the AES Key with it
# 3) Send the AES Key/IV to the Miniserver in a key exchange
# 4) Request an authentication token (as we assume that we don't have one yet)
# 4a) Hash the User and Password to pass to the Miniserver to get the token
# 4b) Encrypt the Command using the AES Key and IV
# 5) wait for something to happen (maybe you now press some key in your home...)

#Imports
import requests   #lib for GET, POST, PUT etc.
import websockets #lib for websockets
import asyncio    #Asynchronous operation is necessary to deal with websockets
import signal
import time
import sys, getopt
import logging
logger = logging.getLogger(__name__)

#Install pyCryptoDome NOT pyCrypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5

import base64    #necessary to encode in Base64
import secrets   #helpful to produce hashes and random bytes
import binascii  #hexlify/unhexlify allows to get HEX-Strings out of bytes-variables
import json      #working with JSON
import hashlib   #Hashing
import hmac      #Key-Hashing
import urllib    #necessary to encode URI-compliant
import logging
from settings import Env  #your settings.py
from nested_lookup import nested_lookup # install nested-lookup --> great for the dict with all UUIDs

#Local imports
from home_libs import loxone as lox
from home_libs import influxConnector as influx
from home_libs import weatherservice as ws
from home_libs import loxcontroller as loxCtrl

#Some Configuration/Definition --> Edit as needed

#Fixed values (for demo purpose only) - should be replaced by randomly generated (page 7, step 4 & 5)
aes_key = str("6A586E3272357538782F413F4428472B4B6250655368566B5970337336763979")
aes_iv = str("782F413F442A472D4B6150645367566B")

# Configuration 

#Creat .env-File with the following settings
#LOX_USER = "user1"
#LOX_PASSWORD = "passwordxyz"
#LOX_IP = "192.168.1.1"
#LOX_PORT = "80"
#LOX_INFLUX_IP='192.168.1.2'
#LOX_INFLUX_PORT=8086
#LOX_INFLUX_DB_NAME='loxone'
#LOX_LAT=1.1234
#LOX_LON=1.1234
#API Key for OpenWeatherMap
#LOX_WEATHER_APP_ID="ApiKey"

env = Env("LOX_")

myUser = env.user
myPassword = env.password
myIP = env.ip
myPort = env.port
myInfluxIp = env.influx_ip
myInfluxPort = env.influx_port
myInfluxDbName = env.influx_db_name
myLat = env.lat
myLon = env.lon
myWeatherApiKey = env.weather_app_id

myUUID = "093302e1-02b4-603c-ffa4ege000d80cfd" #A UUID of your choosing --> you can use the one supplied as well
myIdentifier = "lox_test_script" #an identifier of your chosing
myPermission = 2 #2 for short period, 4 for long period

rsa_pub_key = None #possibility to set the key for debugging, e.g. "-----BEGIN PUBLIC KEY-----\nMxxxvddfDCBiQKBgQCvuJAG7r0FdysdfsdfBl/dDbxyu1h0KQdsf7cmm7mhnNPCevRVjRB+nlK5lljt1yMqJtoQszZqCuqP8ZKKOL1gsp7F0E+xgZjOpsNRcLxglGImS6ii0oTiyDgAlS78+mZrYwvow3d05eQlhz6PzqhAh9ZHQIDAQAB\n-----END PUBLIC KEY-----"

#How often to write values to influx DB [s]
DB_REFRESH_TIME = 30

#How oftern should weather data be refreshed [s]
WEATHER_DATA_REFRESH_TIME=300

#How often should values be written to Loxone [s]
LOXONE_WRITE_TIME=30

#How often is the controller refreshed [s]
CONTROLLER_REFRESH_RATE=30

#How often a keepalive message is sent [s]
KEEP_ALIVE_REFRESH_TIME = 120

#Add names of values/controls to log
# Check your loxip/data/LoxAPP3.json to get the names
# Each it in list consist of:
#   Value name to log
#   Whether the value should be writen with default value at end of script
#   Default value
logValueNames = [['Z2.1Pos', False, 0], ['Z2.2Pos', False, 0],
                 ['Z3.1Pos', False, 0], ['Z3.2Pos', False, 0],
                 ['Z4Pos', False, 0],
                 ['ST1', False, 0], ['ST1.2', False, 0],
                 ['ST2.1', False, 0], ['ST2T', False, 0], ['ST2.3', False, 0],
                 ['ST3', False, 0], ['ST3T', False, 0], ['ST3.2', False, 0],
                 ['ST4', False, 0], ['ST4T', False, 0],
                 ['R2-AcMod', False, 0], ['R2-Cooling', True, 0],
                 ['R2-Heating', True, 0], ['R2-Vent', True, 0],
                 ['R2-AcTempTgt', False, 0],
                 ['R3-AcMod', False, 0], ['R3-Cooling', True, 0],
                 ['R3-Heating', True, 0], ['R3-Vent', True, 0],
                 ['R3-AcTempTgt', False, 0],
                 ['R4-AcMod', False, 0], ['R4-Cooling', True, 0],
                 ['R4-Heating', True, 0], ['R4-Vent', True, 0],
                 ['R4-AcTempTgt', False, 0],
                 ['U1PresentMem', True, 0], ['U2PresentMem', True, 0],
                 ['R3-CurAuto', True, 0], ['R4-CurAuto', True, 0],
                 ['SunShining', True, 0]]

ctrlValueNames = [['Z2.1ReqPosAutoSet', False, 0], ['Z2.2ReqPosAutoSet', False, 0],
                 ['Z3.1ReqPosAutoSet', False, 0], ['Z3.2ReqPosAutoSet', False, 0],
                 ['Z4ReqPosAutoSet', False, 0],
                 ['CloudsSet', False, 0], ['HumiditySet', False, 0], ['PressureSet', False, 0],
                 ['RainSet', False, 0], ['SnowSet', False, 0], ['TempSet', False, 0],
                 ['TempFeelSet', False, 0],['WeatherIdSet', False, 0],['WindDirSet', False, 0],
                 ['WindSpeedSet', False, 0]]

weatherDataToLoxDict = {'clouds': 'CloudsSet', 'humid': 'HumiditySet', 'press': 'PressureSet',
                        'rain': 'RainSet', 'snow': 'SnowSet', 'temp': 'TempSet',
                        'tempFeel': 'TempFeelSet', 'weatherId': 'WeatherIdSet', 'wd': 'WindDirSet',
                        'ws': 'WindSpeedSet' }

#Global variables
running = True
writeToDb = True
writeToLox = True
logLevel = logging.INFO


def sigusrHandler(signalNumber, frame):
    logger.info("End requested")
    global running
    running = False

def parseCmdArgs():
    global logLevel
    global writeToDb
    global writeToLox
    
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hl:w:s:",["loglvl=","writedb=","setlox="])
    except getopt.GetoptError:
        print ('loxone_socket.py -l <logLevel> -w <writeDb> -s <writeToLoxone>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('loxone_socket.py -l <logLevel> -w <writeDb> -s <writeToLoxone>')
            sys.exit()
        elif opt in ("-l", "--loglvl"):
            if arg == '0':
                logLevel = logging.ERROR
            elif arg == '1':
                logLevel = logging.INFO
            elif arg == '2':
                logLevel = logging.DEBUG
        elif opt in ("-w", "--writedb"):
            if arg == '1':
                writeToDb = True
            else:
                writeToDb = False
        elif opt in ("-s", "--setlox"):
            if arg == '1':
                writeToLox = True
            else:
                writeToLox = False

#Websocket connection to Loxone
async def webSocketLx():
    global testCommand
    #Encrypt the AES Key and IV with RSA (page 7, step 6)
    sessionkey = await create_sessionkey(aes_key, aes_iv)
    logger.debug("Session key: {}".format(sessionkey))
    firstRun = True
    
    #start websocket connection (page 7, step 3 - protocol does not need to be specified apparently)
    async with websockets.connect("ws://{}:{}/ws/rfc6455".format(myIP, myPort)) as myWs:
        try:
            #Send Session Key (page 8, step 7)
            await myWs.send("jdev/sys/keyexchange/{}".format(sessionkey))
            await myWs.recv()
            response = await myWs.recv()
            sessionkey_answer = json.loads(response)["LL"]["value"]
            
            #Now a ramdom salt of 2 bytes is added (page 8, step 8)
            aes_salt = binascii.hexlify(secrets.token_bytes(2)).decode()
            
            #Now prepare the token collection command with command encryption
            #Objective is to: Request a JSON Web Token “jdev/sys/getjwt/{hash}/{user}/{permission}/{uuid}/{info}”
            #--> This request must be encrypted
            # page 8, step 9b
            
            #Sending encrypted commands over the websocket (page 27, step 1)
            # Get the JSON web token (page 22, 23)
            getTokenCommand = "salt/{}/jdev/sys/getjwt/{}/{}/{}/{}/{}".format(aes_salt, await hashUserPw(myUser, myPassword), myUser, myPermission, myUUID, myIdentifier)
            logger.debug("Get Token Command to be encrypted: {}".format(getTokenCommand))
            
            #Now encrypt the command with AES (page 21 step 1 & 2)
            encrypted_command = await aes_enc(getTokenCommand, aes_key, aes_iv)
            message_to_ws = "jdev/sys/enc/{}".format(encrypted_command) # page 21, step 3
            logger.debug("Message to be sent: {}".format(message_to_ws))
            
            #Send message to get a JSON webtoken
            await myWs.send(message_to_ws)
            await myWs.recv()
            logger.debug("Answer to the Token-Command: {}".format(await myWs.recv())) #And if you get back a 200 the connection is established
            
            #Get the structure file from the Miniserver (page 18)
            await myWs.send("data/LoxAPP3.json")
            header = lox.Header(await myWs.recv())
            logger.debug(header.msg_type)
            logger.debug(await myWs.recv())
            structure_file = await myWs.recv()
            struct_dict = json.loads(structure_file)
            logger.debug("Structure File: {}".format(json.dumps(structure_file)))
            valueStore = lox.ValueLogger([it[0] for it in logValueNames], struct_dict)
            ctrlValStore = lox.ValueLogger([it[0] for it in ctrlValueNames], struct_dict)
            weather = ws.WeatherService(myLat, myLon, myWeatherApiKey, WEATHER_DATA_REFRESH_TIME)
            influxConnector = influx.Connector(myInfluxIp, myInfluxPort, myInfluxDbName, "values")
            myController = loxCtrl.Controller()
            
            await myWs.send("jdev/sps/enablebinstatusupdate")
            start = time.time()
            ctrlStart = time.time()
            writeStart = time.time()
            keepAliveStart = time.time()
            while running:
                #Parse incomming messages
                header = lox.Header(await myWs.recv())
                logger.debug("Msg len {}".format(header.msg_len))
                if header.msg_len > 0:
                    message = await myWs.recv()
                if header.msg_type == 'text':
                    logger.debug("Text message: {}".format(message))
                elif header.msg_type == 'bin':
                    logger.debug("Binary message: {}".format(message))
                elif header.msg_type == 'value':
                    statesDict = lox.ValueState.parseTable(message)
                    for uuid in statesDict:
                        valueStore.setValue(uuid, float(statesDict[uuid]))
                        if logger.isEnabledFor(logging.DEBUG):
                            nameLookup = nested_lookup(uuid, struct_dict, with_keys = True)
                            name = 'Unknown'
                            if uuid in nameLookup:
                              name = nameLookup[uuid][0]['name']
                            logger.debug("Value {}({}): {}".format(name,uuid, statesDict[uuid]))
                elif header.msg_type == 'text_event':
                    if logger.isEnabledFor(logging.DEBUG):
                        textsDict = lox.TextState.parseTable(message)
                        logger.debug(textsDict)
                        for uuid in textsDict:
                            nameLookup = nested_lookup(uuid, struct_dict, with_keys = True)
                            name = 'Unknown'
                            if uuid in nameLookup:
                                name = nameLookup[uuid][0]['name']
                            logger.debug("Text {}({}): {}".format(name,uuid, textsDict[uuid]))
                elif header.msg_type == 'daytimer':
                    logger.debug("Daytimer message: {}".format(message))
                elif header.msg_type == 'out-of-service':
                    logger.debug("Out-of-service message: {}".format(message))
                elif header.msg_type == 'still_alive':
                    logger.debug("Still alive message")
                elif header.msg_type == 'weather':
                    logger.debug("Weather message: {}".format(message))
                else:
                    logger.error("Unknown message: {}".format(message))
                    
                #Writing data to DB
                if valueStore.hasNewData() and (time.time() - start) >= DB_REFRESH_TIME:
                    #Logger has new data and DB_REFRESH_TIME has passed
                    #valueStore.printData()
                    loxoneData = valueStore.getDataWithNames()
                    valueStore.flushData()
                    if writeToDb:
                        weatherData = weather.getData()
                        loxoneData.update(weatherData)
                        writeData = ctrlValStore.getDataWithNames()
                        loxoneData.update(writeData)
                        influxConnector.submitData(loxoneData)
                    start = time.time()
                    
                #Keep alive messages
                if (time.time() - keepAliveStart) >= KEEP_ALIVE_REFRESH_TIME:
                    logger.debug("Sending keep alive")
                    await myWs.send("keepalive")
                    keepAliveStart = time.time()
                    
                #Refresh the controller
                if (time.time() - ctrlStart) >= CONTROLLER_REFRESH_RATE:
                    ctrlStart = time.time()
                    #Create data for controller
                    loxoneData = valueStore.getDataWithNames()
                    weatherData = weather.getData()
                    loxoneData.update(weatherData)
                    writeData = ctrlValStore.getDataWithNames()
                    loxoneData.update(writeData)
                    ctrlData = myController.update(loxoneData)
                    for item in ctrlData:
                        ctrlValStore.setValueByName(item, ctrlData[item])
                    #Write also weather data to ctrlValStore
                    for item in weatherData:
                        if item in weatherDataToLoxDict:
                            ctrlValStore.setValueByName(weatherDataToLoxDict[item], weatherData[item])
                    
                #Writing data to Loxone
                if ctrlValStore.hasNewData() and (time.time() - writeStart) >= LOXONE_WRITE_TIME:
                    #Time to write new data to Loxone
                    #ctrlValStore.printData()
                    writeData = ctrlValStore.getDataWithUuids(changedOnly=(not firstRun))
                    firtsRun = False
                    ctrlValStore.flushData()
                    if writeToLox:
                        #send commands to Loxone
                        for cmd in writeData:
                            setDataCommand = "jdev/sps/io/{}/{}".format(cmd, writeData[cmd])
                            logger.debug("Sending data to {}: {}".format(cmd, setDataCommand))
                            #Send message
                            await myWs.send(setDataCommand)
                            await myWs.recv()
                            logger.debug("Answer to the command: {}".format(await myWs.recv()))
                    writeStart = time.time()
            #Script is ending, write default values to db
            if writeToDb:
                for item in logValueNames:
                    if item[1]:
                        valueStore.setValueByName(item[0], item[2])
                if valueStore.hasNewData():
                    loxoneData = valueStore.getDataWithNames()
                    valueStore.flushData()
                    weatherData = weather.getData()
                    loxoneData.update(weatherData)
                    influxConnector.submitData(loxoneData)
        except websockets.ConnectionClosed:
            logger.info('Connection closed')
            pass


# Function to RSA encrypt the AES key and iv
async def create_sessionkey(aes_key, aes_iv):
    payload = aes_key + ":" + aes_iv
    payload_bytes = payload.encode()
    #RSA Encrypt the String containing the AES Key and IV
    #https://8gwifi.org/rsafunctions.jsp
    #RSA/ECB/PKCS1Padding
    pub_key = RSA.importKey(rsa_pub_key)
    encryptor = PKCS1_v1_5.new(pub_key)
    sessionkey = encryptor.encrypt(payload_bytes)
    #https://www.base64encode.org/ to compare
    return base64.standard_b64encode(sessionkey).decode()
    
    
# AES encrypt with the shared AES Key and IV    
async def aes_enc(text, aes_key, aes_iv):
    key = binascii.unhexlify(aes_key)
    iv = binascii.unhexlify(aes_iv)
    logger.debug("Key: {} IV: {}".format(key, iv))
    encoder = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted_msg = encoder.encrypt(await pad(text.encode()))
    b64encoded = base64.standard_b64encode(encrypted_msg)
    return urllib.parse.quote(b64encoded, safe="") #Return url-Encrypted
 

# ZeroBytePadding to AES block size (16 byte) to allow encryption 
async def pad(byte_msg):
    return byte_msg + b"\0" * (AES.block_size - len(byte_msg) % AES.block_size) #ZeroBytePadding / Zero Padding


# Key-Hash the User and Password HMAC-SHA1 (page 22)
async def hashUserPw(user, password):
    # Get the key to be used for the HMAC-Hashing and the Salt to be used for the SHA1 hashing
    response = requests.get("http://{}:{}/jdev/sys/getkey2/{}".format(myIP, myPort, user))
    logger.debug(response.text)
    userKey = response.json()["LL"]["value"]["key"]
    userSalt = response.json()["LL"]["value"]["salt"]
    pwHash = await hash_Password(password, userSalt)
    logger.debug("PW Hash: {}".format(pwHash))
    userHash = await digest_hmac_sha1("{}:{}".format(user, pwHash), userKey)
    #The userHash shall be left like it is
    return userHash
    

# Hash the Password plain and simple: SHA1 (page 22)
async def hash_Password(password, userSalt):
    #check if result is this: https://passwordsgenerator.net/sha1-hash-generator/
    tobehashed = password + ":" + userSalt
    logger.debug("To be hashed: {}".format(tobehashed))
    hash = hashlib.sha1(tobehashed.encode())
    #according to the Loxone Doc, the password Hash shall be upper case
    hashstring = hash.hexdigest()
    logger.debug("Hashed: {}".format(hashstring.upper()))
    return hashstring.upper()
    

# HMAC-SHA1 hash something with a given key
async def digest_hmac_sha1(message, key):
    #https://gist.github.com/heskyji/5167567b64cb92a910a3
    #compare: https://www.liavaag.org/English/SHA-Generator/HMAC/  -- key type: text, output: hex
    logger.debug("hmac sha1 input: {}".format(message))
    hex_key = binascii.unhexlify(key)
    logger.debug("Hex Key: {}".format(hex_key))
    message = bytes(message, 'UTF-8')
    
    digester = hmac.new(hex_key, message, hashlib.sha1)
    signature1 = digester.digest()
    
    signature2 = binascii.hexlify(signature1)    
    logger.debug("hmac-sha1 output: {}".format(signature2.decode()))
    #return a hex string
    return signature2.decode()

Log_Format = "%(levelname)s %(asctime)s - %(message)s"

if __name__ == '__main__':
    parseCmdArgs()
    print("Starting script: LogLevel: {} WriteToDb: {} WriteToLoxone: {}".format(logLevel, writeToDb, writeToLox))
    logging.basicConfig(filename = "logfile.log",
                    filemode = "w",
                    format = Log_Format, 
                    level = logLevel)
    if hasattr(signal, 'SIGUSR1'):
        signal.signal(signal.SIGUSR1, sigusrHandler)
    rsa_pub_key = lox.prepareRsaKey(myIP, myPort) #Retrieve the public RSA key of the miniserver (page 7, step 2)
    while running:
        time.sleep(10)
        print("Starting socket thread")
        logger.info("Starting socket thread")
        asyncio.get_event_loop().run_until_complete(webSocketLx()) #Start the eventloop (async) with the function webSocketLx
    

