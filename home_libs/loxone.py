from bitstring import ConstBitStream #install bistring --> necessary to deal with Bit-Messages
import requests
import logging
logger = logging.getLogger(__name__)

# Get the RSA public key from the miniserver and format it so that it is compliant with a .PEM file 
def prepareRsaKey(ip, port):
    response = requests.get("http://{}:{}/jdev/sys/getPublicKey".format(ip, port))
    rsa_key_malformed = response.json()["LL"]["value"]
    rsa_key_malformed = rsa_key_malformed.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN PUBLIC KEY-----\n")
    rsa_key_wellformed = rsa_key_malformed.replace("-----END CERTIFICATE-----", "\n-----END PUBLIC KEY-----")
    logger.info("RSA Public Key: {}".format(rsa_key_wellformed))
    return rsa_key_wellformed

#Description of a Loxone Header message (page 14)
class Header:
#    typedef struct {
#      BYTE cBinType; // fix 0x03 --> fixed marking a header, raise exception if not there
#      BYTE cIdentifier; // 8-Bit Unsigned Integer (little endian) --> Kind of message following the header
#            0: Text  1: Binary  2,3,4: Event Tables  5: out-of-service   6: Keep-alive  7: Wheather
#      BYTE cInfo; // Info
#      BYTE cReserved; // reserved
#      UINT nLen; // 32-Bit Unsigned Integer (little endian)
    msg_type = None
    exact2Follow = False

    def __init__(self, header_msg: bytes):
        #First byte
        if header_msg[0:1] != bytes.fromhex('03'):
            raise ValueError("This is not a header message")
        self.msg_type = self.__setIdentifier(header_msg[1:2])
        self.exact2Follow = self.__setExact2Follow(header_msg[2:3])
        #Bytes 4-8 could be decoded some other time --> would allow prediction of load times
        
        
    def __setIdentifier(self, secondByte: bytes):
        switch_dict = {
            b'\x00': 'text', #"Text-Message"
            b'\x01': 'bin', #"Binary File"
            b'\x02': 'value', #"Event-Table of Value-States
            b'\x03': 'text_event', # Event-Table of Text-States
            b'\x04': 'daytimer', #Event-Table of Daytimer-States
            b'\x05': 'out-of-service', #e.g. Firmware-Upgrade - no following message at all. Connection closes
            b'\x06': 'still_alive', #response to keepalive-message
            b'\x07': 'weather' # Event-Table of Wheather-States
            }
        return switch_dict.get(secondByte, "invalid")
    
    def __setExact2Follow(self, thirdByte: bytes):
        bitstream = ConstBitStream(thirdByte)
        bitstream.pos = 0
        if bitstream.read('bin:1') == '1':
            return True
        else:
            return False

# Base Class for State Messages
class State:
    
    @staticmethod
    def decodeUUID(uuid: bytes) -> str:

        #Decode UUID
        bitstream = ConstBitStream(uuid)
        data1, data2, data3, data41, data42, data43, data44, data45, data46, data47, data48 = bitstream.unpack('uintle:32, uintle:16, uintle:16, uint:8, uint:8, uint:8, uint:8, uint:8, uint:8, uint:8, uint:8')
        uuid = "{:08x}-{:04x}-{:04x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(data1, data2, data3, data41, data42, data43, data44, data45, data46, data47, data48)
        return uuid
   
    def setUUID(self, uuid: bytes):
        self.uuid  = "" #UUID as String

        self.uuid = State.decodeUUID(uuid)
   
class ValueState(State):
    #Consists of UUID (16 byte) and Value 64-Bit Float (little endian) value
    # Each State-Entry in the table is consequently 24 byte long
    #
    #     Binary-Structure of a UUID
    # typedef struct _UUID {
    #  unsigned long Data1; // 32-Bit Unsigned Integer (little endian)
    #  unsigned short Data2; // 16-Bit Unsigned Integer (little endian)
    #  unsigned short Data3; // 16-Bit Unsigned Integer (little endian)
    #  unsigned char Data4[8]; // 8-Bit Uint8Array [8] (little endian)
    #Example from the structure-file in json however:
    # UUID: "12c3abc1-024e-1135-ffff7ba5fa36c093","name":"Gästezimmer UG Süd"
    # The strings are the hex representations of the numbers
    
    def __init__(self, valueStateMsg: bytes):
        #for BitStream: https://bitstring.readthedocs.io/en/latest/constbitstream.html?highlight=read#bitstring.ConstBitStream.read
        self.value = 0  #Value as Float
        State.__init__(self)
        self.setUUID(valueStateMsg[0:16])
        
        #Decode Value
        bitstream = ConstBitStream(valueStateMsg[16:24])
        value_list = bitstream.unpack('floatle:64')
        self.value = "{:g}".format(value_list[0])          
        
    @classmethod #cls is a "keyword" for the class itself. Hence, parseTable is not bound to an instance  
    def parseTable(cls, eventTable: bytes) -> dict:
        # take a longer message and split it and create ValueState-Instances
        # Return a dict with UUIDs and values
        instances = list()

        for i in range(0, len(eventTable), 24):
            instances.append( cls(eventTable[i:i+24]) ) # cls() creates an instance of the class itself
            
        values = dict()
        for inst in instances:
            values[inst.uuid] = inst.value
            
        return values


# Text State - derived from LoxState
class TextState(State):
    #instance variables: uuid, uuid_icon, text
    #page 17/16 in Loxone Guide
    #typedef​ ​struct​ { ​// starts at multiple of 4
    #   PUUID​ ​uuid​; // 128-Bit uuid
    #   PUUID​ ​uuidIcon​; // 128-Bit uuid of icon
    # ​  unsigned long ​textLength;  // 32-Bit Unsigned Integer (little endian)
    #      // text follows here
    # } ​PACKED​ ​EvDataText​;
    
    def __init__(self, message):
        State.__init__(self)
        # extract UUID
        self.setUUID(message[0:16])
        # extract icon UUID
        self.uuid_icon = State.decodeUUID(message[16:32])
        # calculate Text length
        bitstream = ConstBitStream(message[32:36])
        self.textLen = bitstream.unpack('uintle:32')[0]
        # extract Text
        self.text = message[36:36+self.textLen].decode('utf8','strict')

    @classmethod #cls is a "keyword" for the class itself. Hence, parseTable is not bound to an instance  
    def parseTable(cls, eventTable: bytes) -> dict:
        # take a longer message and split it and create ValueState-Instances
        # Return a dict with UUIDs and values
        instances = list()
        
        i = 0
        while i < len(eventTable):
            startI = i
            i+=32 #Skip UUID and icon UUID
            bitstream = ConstBitStream(eventTable[i:i+4])
            textLen = bitstream.unpack('uintle:32')[0]
            i += 4 + textLen #Skip textLen and text itself
            if (i % 4) != 0:
              i += 4 - i % 4 #Skip padding
            instances.append( cls(eventTable[startI:i]) ) # cls() creates an instance of the class itself
            
        values = dict()
        for inst in instances:
            values[inst.uuid] = inst.text
            
        return values

class ValueLogger:
    def __init__(self, valueNames: list, struct_dict):
        self.valueUuids = dict()
        self.newData = False
        
        #find UUIDs of values of interest
        for valueName in valueNames:
            found = False
            for uuid in struct_dict['controls']:
                if struct_dict['controls'][uuid]['name'] == valueName:
                    found = True
                    self.valueUuids[uuid] = [valueName,0]
            if not found:
                logger.error("UUID for {} not found".format(valueName))
    
    def printData(self):
        print("-------------------------------------------------")
        for uuid in self.valueUuids:
            print("{}: {}".format(self.valueUuids[uuid][0], self.valueUuids[uuid][1]))
        print("-------------------------------------------------")
    
    def getData(self):
        ret = dict()
        for uuid in self.valueUuids:
            ret[self.valueUuids[uuid][0]] = self.valueUuids[uuid][1]
        return ret
            
    def setValue(self, setUuid, setVal):
        for uuid in self.valueUuids:
            if uuid == setUuid:
                self.valueUuids[uuid][1] = setVal
                self.newData = True
                return True
        return False
    
    def hasNewData(self):
        return self.newData
    
    def flushData(self):
        self.newData = False