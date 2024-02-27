#!/usr/bin/env python3
import socket
import select
import binascii
import struct
import argparse
import can
from logging import debug,info,warning,error
import logging
import time
import os

ECAN_CLIENT_UDP_PORT=1902
ECAN_GATEWAY_UDP_PORT=1901
ECAN_GATEWAY_CAN1_TCP_PORT=8881
ECAN_GATEWAY_CAN2_TCP_PORT=8882
CONF_NUM_PAGE0=0
CONF_NUM_PAGE1=2
CONF_NUM_PAGE2=1

class GatewayCANChannelConfiguration:
    def fromTOML(doc):
        obj=GatewayCANChannelConfiguration()
        obj.mystery1=doc['mystery1']
        obj.emptyCacheWhenConnected=doc['emptyCacheWhenConnected']
        obj.numberOfCANBUSPacketsToBuffer=doc['numberOfCANBUSPacketsToBuffer']
        obj.timeoutBetween2Packets=doc['timeoutBetween2Packets']
        obj.bitrateThousand=doc['bitrateThousand']
        obj.tbs1=doc['tbs1']
        obj.tbs2=doc['tbs2']
        obj.prescaler=doc['prescaler']
        obj.remoteIp=doc['remoteIp']
        obj.remotePort=doc['remotePort']
        obj.localPort=doc['localPort']
        obj.mysteryByte=doc['mysteryByte']
        obj.operationMode=doc['operationMode']
        obj.mystery2=bytes.fromhex(doc['mystery2'])
        obj.connectionTimeout=doc['connectionTimeout']
        obj.mystery3=bytes.fromhex(doc['mystery3'])
        obj.registrationMessage=doc['registrationMessage']
        obj.mystery4=doc['mystery4']
        obj.keepAliveMessage=doc['keepAliveMessage']
        
        return obj
    
    def totoml(self):
        import tomlkit
        canTable = tomlkit.table()
        canTable.add('mystery1', self.mystery1)
        canTable.add('emptyCacheWhenConnected', self.emptyCacheWhenConnected)
        canTable.add('numberOfCANBUSPacketsToBuffer', self.numberOfCANBUSPacketsToBuffer)
        canTable['numberOfCANBUSPacketsToBuffer'].comment("Acumulate this many canbus packets before sending them over the TCP side")
        canTable.add('timeoutBetween2Packets', self.timeoutBetween2Packets)
        
        canTable.add('bitrateThousand', self.bitrateThousand)
        canTable.add('tbs1', self.tbs1)
        canTable['tbs1'].comment("time segment1 must be computed to fit the baud rate according to clock 7.2Mhz; Range 0-15")
        canTable.add('tbs2', self.tbs2)
        canTable['tbs2'].comment("time segment2; Range 0-7")
        canTable.add('prescaler', self.prescaler)
        canTable['prescaler'].comment("Baud rate prescaler: Range 0-65535")
        
        canTable.add('remoteIp', self.remoteIp)
        canTable.add('remotePort', self.remotePort)
        canTable.add('localPort', self.localPort)
        canTable.add('mysteryByte', self.mysteryByte)
        canTable.add('operationMode', self.operationMode) #0=TCP Server,1=TCP Client, 2=UDP SErver 3=UDP Client
        canTable.add('mystery2', bytes.hex(self.mystery2))
        canTable.add('connectionTimeout', self.connectionTimeout)
        canTable.add('mystery3', bytes.hex(self.mystery3))
        canTable.add('registrationMessage', self.registrationMessage)
        canTable.add('mystery4', self.mystery4)
        canTable.add('keepAliveMessage', self.keepAliveMessage)
        return canTable
    
    def __eq__(self, other):
        if self.mystery1!=other.mystery1: return False
        if self.emptyCacheWhenConnected!=other.emptyCacheWhenConnected: return False
        if self.numberOfCANBUSPacketsToBuffer!=other.numberOfCANBUSPacketsToBuffer: return False
        if self.timeoutBetween2Packets!=other.timeoutBetween2Packets: return False
        if self.bitrateThousand!=other.bitrateThousand: return False
        if self.tbs1!=other.tbs1: return False
        if self.tbs2!=other.tbs2: return False
        if self.prescaler!=other.prescaler: return False
        if self.remoteIp!=other.remoteIp: return False
        if self.remotePort!=other.remotePort: return False
        if self.localPort!=other.localPort: return False
        if self.mysteryByte!=other.mysteryByte: return False
        if self.operationMode!=other.operationMode: return False
        if self.mystery2!=other.mystery2: return False
        if self.connectionTimeout!=other.connectionTimeout: return False
        if self.mystery3!=other.mystery3: return False
        if self.registrationMessage!=other.registrationMessage: return False
        if self.keepAliveMessage!=other.keepAliveMessage: return False
        return True


class GatewayConfiguration:
    def __init__(self):
        self.can1=GatewayCANChannelConfiguration()
        self.can2=GatewayCANChannelConfiguration()

    def fromTOML(tomlString):
        doc=tomlkit.parse(tomlString)
        obj=GatewayConfiguration()
        obj.mystery0=binascii.unhexlify(doc['mystery0'])

        obj.macadress=doc['macadress']
        obj.serialNumber=doc['serialNumber']
        obj.firmwareVersion=doc['firmwareVersion']
        obj.deviceModel=doc['devicemodel']
        
        obj.deviceName=doc['deviceName']
        obj.localStaticIp=doc['localStaticIp']
        obj.gateway=doc['gateway']
        obj.netmask=doc['netmask']
        obj.dns=doc['dns']
        
        obj.reportCycle=doc['reportCycle']
        obj.reportTargetIp=doc['reportTargetIp']
        obj.reportTargetPort=doc['reportTargetPort']
        obj.reconnectionTimeout=doc['reconnectionTimeout']
        obj.noCANDataAutoReboot=doc['noCANDataAutoReboot']

        obj.can1=GatewayCANChannelConfiguration.fromTOML(doc['can1'])
        obj.can2=GatewayCANChannelConfiguration.fromTOML(doc['can2'])
        return obj


    def totoml(self):
        import tomlkit
        doc = tomlkit.document()
        doc.add(tomlkit.comment("ECAN-E01 Configuration file in TOML format. Generated by the command: <CMD HERE>"))
        doc.add(tomlkit.nl())
        doc.add('mystery0', bytes.hex(self.mystery0))
        doc.add(tomlkit.nl())

        doc.add('macadress', self.macadress)
        doc['macadress'].comment("Read only")

        doc['serialNumber']=self.serialNumber
        doc['serialNumber'].comment("Read only")

        doc['firmwareVersion']=self.firmwareVersion
        doc['firmwareVersion'].comment("Read only")

        doc.add('devicemodel', self.deviceModel)
        doc['devicemodel'].comment("Read only")
        doc.add(tomlkit.nl())
        
        doc.add('deviceName', self.deviceName)
        doc.add('localStaticIp', self.localStaticIp)
        doc.add('gateway', self.gateway)
        doc.add('netmask', self.netmask)
        doc.add('dns', self.dns)
        
        doc.add(tomlkit.nl())
        doc.add(tomlkit.comment("This section relates to the behaviour when the gateway first starts."))
        doc.add('reportCycle', self.reportCycle)
        doc.add('reportTargetIp', self.reportTargetIp)
        doc.add('reportTargetPort', self.reportTargetPort)
        doc.add('reconnectionTimeout', self.reconnectionTimeout)
        doc.add('noCANDataAutoReboot', self.noCANDataAutoReboot)
        doc['noCANDataAutoReboot'].comment("Number of seconds without CANBus traffic for device to reboot")

        doc.add('can1', self.can1.totoml())
        doc.add('can2', self.can2.totoml())

        return tomlkit.dumps(doc)
    
    def __eq__(self, other):
        if self.mystery0!=other.mystery0: return False
        if self.macadress!=other.macadress : return False
        if self.serialNumber!=other.serialNumber : return False
        if self.firmwareVersion!=other.firmwareVersion : return False
        if self.deviceModel!=other.deviceModel : return False
        if self.deviceName!=other.deviceName : return False
        if self.localStaticIp!=other.localStaticIp : return False
        if self.gateway!=other.gateway : return False
        if self.netmask!=other.netmask : return False
        if self.dns!=other.dns : return False
        
        if self.reportCycle!=other.reportCycle : return False
        if self.reportTargetIp!=other.reportTargetIp : return False
        if self.reportTargetPort!=other.reportTargetPort : return False
        if self.reconnectionTimeout!=other.reconnectionTimeout : return False
        if self.noCANDataAutoReboot!=other.noCANDataAutoReboot : return False
        
        if self.can1!=other.can1 : return False
        if self.can2!=other.can2 : return False
        return True


def modbusCrc(msg:str) -> int:
    crc = 0xFFFF
    for n in range(len(msg)):
        crc ^= msg[n]
        for i in range(8):
            if crc & 1:
                crc >>= 1
                crc ^= 0xA001
            else:
                crc >>= 1
    return crc

def parseMacAddressFromGateway(dataFromGateway):
    debug('parseMacAddressFromGateway : %s',binascii.hexlify(dataFromGateway))
    (magic,action)=struct.unpack('BB', dataFromGateway[0:2])
    if(magic==0xFD and action==0x06):
        (macbytes,mystery)=struct.unpack('6s2s', dataFromGateway[2:])
        return macbytes
    return None

def getBasicInfoFromGateway(udpSocket, gatewayIpAndPort):
    debug('getBasicInfoFromGateway %s', str(gatewayIpAndPort))
    QUERY_PAYLOAD=b'www.cdebyte.comwww.cdebyte.com' #Magic bytes that trigger a response
    udpSocket.sendto(QUERY_PAYLOAD, gatewayIpAndPort)

    data, ipAndPort = udpSocket.recvfrom(32)
    debug('got UDP response from %s', str(ipAndPort));
    macAddress=parseMacAddressFromGateway(data)
    return (ipAndPort[0], macAddress)

def getNetworkInterfaces():
    allNetworkInterfaces=os.listdir('/sys/class/net/')
    return filter(lambda x: not x.startswith('can') and x!='lo', allNetworkInterfaces)
    
def discoverGatewayByName(nameToSearch, netinterface):
    debug(f'discoverGatewayByName nameToSearch={nameToSearch}')
    if netinterface is None:
        netinterfaceToSearch=getNetworkInterfaces()
    else:
        netinterfaceToSearch=[netinterface]
        
    for n in netinterfaceToSearch:
        gatewayIpAndMac=discoverECanGateways(n)
        if gatewayIpAndMac:
            gatewayName=getGatewayName(gatewayIpAndMac[0])
            debug(f'gatewayName={gatewayName}')
            if(nameToSearch==gatewayName):
                return gatewayIpAndMac
    return (None, None)
    
def discoverOneECanGatewaysAllInterfaces():
    for n in getNetworkInterfaces():
        ipAndMac=discoverECanGateways(n)
        if ipAndMac:
            return ipAndMac
    return None

def createUDPSocket():
    udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    udpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    udpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udpSocket.bind(('<broadcast>', ECAN_CLIENT_UDP_PORT))
    udpSocket.settimeout(10)
    return udpSocket;

def discoverECanGateways(interfaceName):
    if(interfaceName is None):
        return discoverOneECanGatewaysAllInterfaces()
    
    debug('Searching for ECAN-E01 gateway on interface %s', interfaceName)
    udpSocket = createUDPSocket()
    udpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bytes(interfaceName, 'ascii'))
    try:
        ipAndMac=getBasicInfoFromGateway(udpSocket, ('<broadcast>', ECAN_GATEWAY_UDP_PORT))
        udpSocket.close()
    except :
        udpSocket.close()
        return None

    return ipAndMac

def udpConnectTo(deviceIpAddr):
    udpSocket = createUDPSocket()
    #udpSocket.settimeout(None)
    gatewayIpAndPort=(deviceIpAddr, ECAN_GATEWAY_UDP_PORT)
    (_,gatewayMacAddress) = getBasicInfoFromGateway(udpSocket, gatewayIpAndPort)
    return (udpSocket,gatewayIpAndPort, gatewayMacAddress)

class ProprietaryConfigFileReader:
    MAINCONFIG_BYTES_SIZE=240
    CANCHANNEL_BYTE_SIZE=424
    CONFIG_ZERO_STRUCT_FORMAT='<2s32s11sBBBBBB11s26s4s4s4s4sB129sHHH';
    CONFIG_ONE_STRUCT_FORMAT='<BBBBHBBI128sBB2sIIH4s132sH132s'
    
    def ipBytesToStr(ipBytes):
        return socket.inet_ntoa(ipBytes)

    def strToIPBytes(ipString):
        return socket.inet_aton(ipString)
    
    def parseConfigurationZero(configurationBytes, config):
        debug('parseConfigurationZero %s', binascii.hexlify(configurationBytes))
        parts=struct.unpack(ProprietaryConfigFileReader.CONFIG_ZERO_STRUCT_FORMAT, configurationBytes)
        #import pdb; pdb.set_trace()
        config.mystery0=parts[0]
        config.deviceModel=parts[1].decode('ascii').rstrip('\x00')
        config.firmwareVersion=parts[2].decode('ascii').rstrip('\x00')
        config.macadress='%02X:%02X:%02X:%02X:%02X:%02X' % parts[3:9]
        config.deviceName=parts[9].decode('ascii').rstrip('\x00')
        config.serialNumber=parts[10].decode('ascii').rstrip('\x00')

        config.localStaticIp=ProprietaryConfigFileReader.ipBytesToStr(parts[11])
        config.gateway=ProprietaryConfigFileReader.ipBytesToStr(parts[12])
        config.netmask=ProprietaryConfigFileReader.ipBytesToStr(parts[13])
        config.dns=ProprietaryConfigFileReader.ipBytesToStr(parts[14])

        config.reportCycle=parts[15]
        config.reportTargetIp=parts[16].decode('ascii').rstrip('\x00')
        config.reportTargetPort=parts[17]
        config.reconnectionTimeout=parts[18]
        config.noCANDataAutoReboot=parts[19]
    
    def buildConfigurationZero(config):
        macadressBytes=binascii.unhexlify(config.macadress.replace(':',''))
        outBytes=bytearray().zfill(240)
        struct.pack_into(ProprietaryConfigFileReader.CONFIG_ZERO_STRUCT_FORMAT, outBytes, 0,
            config.mystery0, 
            config.deviceModel.encode('ascii'), 
            config.firmwareVersion.encode('ascii'), 
            macadressBytes[0],
            macadressBytes[1],
            macadressBytes[2],
            macadressBytes[3],
            macadressBytes[4],
            macadressBytes[5],
            config.deviceName.encode('ascii'), 
            config.serialNumber.encode('ascii'), 
            ProprietaryConfigFileReader.strToIPBytes(config.localStaticIp), 
            ProprietaryConfigFileReader.strToIPBytes(config.gateway),
            ProprietaryConfigFileReader.strToIPBytes(config.netmask),
            ProprietaryConfigFileReader.strToIPBytes(config.dns),
            config.reportCycle,
            config.reportTargetIp.encode('ascii'),
            config.reportTargetPort,
            config.reconnectionTimeout,
            config.noCANDataAutoReboot
            )
        return bytes(outBytes)

    def parseConfigurationCANChannel(configurationCANChannelBytes, canConfig):
        debug('configurationCANChannelBytes %s', binascii.hexlify(configurationCANChannelBytes))
        parts=struct.unpack(ProprietaryConfigFileReader.CONFIG_ONE_STRUCT_FORMAT, configurationCANChannelBytes)
        canConfig.mystery1=parts[0]
        canConfig.emptyCacheWhenConnected=parts[1]
        canConfig.numberOfCANBUSPacketsToBuffer=parts[2] #Range 1-39
        canConfig.timeoutBetween2Packets=parts[3] #Range 12-255
        canConfig.bitrateThousand=parts[4]
        canConfig.tbs1=parts[5]
        canConfig.tbs2=parts[6]
        canConfig.prescaler=parts[7]
        canConfig.remoteIp=parts[8].decode('ascii').rstrip('\x00')
        canConfig.mysteryByte=parts[9]
        canConfig.operationMode=parts[10]
        canConfig.mystery2=parts[11]
        canConfig.remotePort=parts[12]
        canConfig.localPort=parts[13]
        canConfig.connectionTimeout=parts[14]
        canConfig.mystery3=parts[15]
        canConfig.registrationMessage=parts[16].decode('ascii').partition('\x00')[0]
        canConfig.mystery4=parts[17]
        canConfig.keepAliveMessage=parts[18].decode('ascii').rstrip('\x00')

    def buildConfigurationCANChannel(canConfig):
        outBytes=bytearray().zfill(424)
        struct.pack_into(ProprietaryConfigFileReader.CONFIG_ONE_STRUCT_FORMAT, outBytes, 0,
            canConfig.mystery1,
            canConfig.emptyCacheWhenConnected,
            canConfig.numberOfCANBUSPacketsToBuffer,
            canConfig.timeoutBetween2Packets,
            canConfig.bitrateThousand,
            canConfig.tbs1,
            canConfig.tbs2,
            canConfig.prescaler,
            canConfig.remoteIp.encode('ascii'),
            canConfig.mysteryByte,
            canConfig.operationMode,
            canConfig.mystery2,
            canConfig.remotePort,
            canConfig.localPort,
            canConfig.connectionTimeout,
            canConfig.mystery3,
            canConfig.registrationMessage.encode('ascii'),
            canConfig.mystery4,
            canConfig.keepAliveMessage.encode('ascii')
        )
        return bytes(outBytes);
    
    def parseBinaryConfigurationFile(inputfilepath):
        with open(inputfilepath, mode='rb') as inputfile:
            filemagic1,filemagic2=struct.unpack('>II', inputfile.read(struct.calcsize(fmt)))
            if(filemagic1!=0x09 or filemagic2!=0xF2):
                raise Exception('Unknown file format')
            
            config=GatewayConfiguration()
            ProprietaryConfigFileReader.parseConfigurationZero(inputfile.read(ProprietaryConfigFileReader.MAINCONFIG_BYTES_SIZE), config)
            inputfile.read(6) #Unknown, in file only
            ProprietaryConfigFileReader.parseConfigurationCANChannel(inputfile.read(ProprietaryConfigFileReader.CANCHANNEL_BYTE_SIZE), config.can1)
            inputfile.read(6) #Unknown, in file only
            ProprietaryConfigFileReader.parseConfigurationCANChannel(inputfile.read(ProprietaryConfigFileReader.CANCHANNEL_BYTE_SIZE), config.can2)
            return config
    
    def convertGatewayConfigurationToBlob(inputConfig):
        pass

def getConfigurationPage(udpSocket, gatewayMacAddress, gatewayIpAndPort, configurationPage):
    debug('Reading device configuration page %d', configurationPage)
    basicConfigurationCmd=bytearray(b'\xfe\x00')
    basicConfigurationCmd.extend(gatewayMacAddress)
    basicConfigurationCmd.extend(struct.pack('>H', configurationPage))

    expectedResponseLen=252 if configurationPage==0 else 436
    (responseBytes, addr) = sendBytesWaitForResponse(udpSocket, gatewayIpAndPort, basicConfigurationCmd, expectedResponseLen)
    magic, action, macAddress, configurationSection, rxChecksum=struct.unpack('<BB6s2sH', responseBytes[0:12])
    
    configBytes=responseBytes[12:]
    computedChecksum=modbusCrc(configBytes)
    if(computedChecksum!=rxChecksum):
        warning("FAILED checksum computedChecksum %04X rxChecksum=%04X", computedChecksum, rxChecksum)

    return configBytes;

def getGatewayName(deviceIpAddr):
    (udpSocket,gatewayIpAndPort, gatewayMacAddress)=udpConnectTo(deviceIpAddr)
    configuration0Bytes=getConfigurationPage(udpSocket, gatewayMacAddress, gatewayIpAndPort, 0)
    config=GatewayConfiguration()
    ProprietaryConfigFileReader.parseConfigurationZero(configuration0Bytes, config)
    udpSocket.close()
    return config.deviceName

def readConfiguration(deviceIpAddr):
    (udpSocket,gatewayIpAndPort, gatewayMacAddress)=udpConnectTo(deviceIpAddr)
    configuration0Bytes=getConfigurationPage(udpSocket, gatewayMacAddress, gatewayIpAndPort, CONF_NUM_PAGE0)
    config=GatewayConfiguration()
    ProprietaryConfigFileReader.parseConfigurationZero(configuration0Bytes, config)

    inConfiguration1Bytes=getConfigurationPage(udpSocket, gatewayMacAddress, gatewayIpAndPort, CONF_NUM_PAGE1)
    inConfiguration2Bytes=getConfigurationPage(udpSocket, gatewayMacAddress, gatewayIpAndPort, CONF_NUM_PAGE2)

    ProprietaryConfigFileReader.parseConfigurationCANChannel(inConfiguration1Bytes, config.can1)
    ProprietaryConfigFileReader.parseConfigurationCANChannel(inConfiguration2Bytes, config.can2)

    udpSocket.close()
    return config

def writeConfiguration(deviceIpAddr, configObj):
    (udpSocket,gatewayIpAndPort, gatewayMacAddress)=udpConnectTo(deviceIpAddr)
    outConfiguration0Bytes=ProprietaryConfigFileReader.buildConfigurationZero(configObj)
    writeConfigurationPage(udpSocket, gatewayIpAndPort, gatewayMacAddress, 0, outConfiguration0Bytes)
    outConfiguration1Bytes=ProprietaryConfigFileReader.buildConfigurationCANChannel(configObj.can1)
    writeConfigurationPage(udpSocket, gatewayIpAndPort, gatewayMacAddress, CONF_NUM_PAGE1, outConfiguration1Bytes)
    outConfiguration2Bytes=ProprietaryConfigFileReader.buildConfigurationCANChannel(configObj.can2)
    writeConfigurationPage(udpSocket, gatewayIpAndPort, gatewayMacAddress, CONF_NUM_PAGE2, outConfiguration2Bytes)

def sendBytesWaitForResponse(udpSocket, ipAndPort, cmdBytes, expectedResponseLen):
    debug(f'cmdBytes len {len(cmdBytes)}')
    debug('cmdBytes %s', binascii.hexlify(cmdBytes))
    udpSocket.sendto(cmdBytes, ipAndPort)

    while True:
        responseBytes, addr = udpSocket.recvfrom(512)
        debug(f'responseBytes len {len(responseBytes)} from {addr}')
        debug('responseBytes %s', binascii.hexlify(responseBytes))
        if(len(responseBytes)!=expectedResponseLen):
            warning(f'Ignoring out of order response. We are waiting for {expectedResponseLen} bytes')
        else:
            return (responseBytes, addr)

def writeConfigurationPage(udpSocket, gatewayIpAndPort, gatewayMacAddress, configurationPage, configBytes):
    debug('Writing configuration page %d', configurationPage)
    writeConfigurationPageCmd=bytearray(b'\xfe\x01')
    writeConfigurationPageCmd.extend(gatewayMacAddress)
    writeConfigurationPageCmd.extend(struct.pack('>H', configurationPage))
    computedChecksum=modbusCrc(configBytes)
    writeConfigurationPageCmd.extend(struct.pack('H', computedChecksum))
    writeConfigurationPageCmd.extend(configBytes)

    (responseBytes, addr) = sendBytesWaitForResponse(udpSocket, gatewayIpAndPort, writeConfigurationPageCmd, 12)
    if(len(responseBytes)!=12):
        warning(f'exptected responseBytes to be 12 bytes long. was {len(responseBytes)} long')
    

def rebootGateway(deviceIpAddr):
    (udpSocket,gatewayIpAndPort, gatewayMacAddress)=udpConnectTo(deviceIpAddr)
    
    rebootCmd=bytearray(b'\xfe\x03')
    rebootCmd.extend(gatewayMacAddress)
    info('Rebooting %s',deviceIpAddr);
    (rebootResponse, addr) = sendBytesWaitForResponse(udpSocket, gatewayIpAndPort, rebootCmd, 10)

    expectedRebootResponse=bytearray(b'\xfd\x03')
    expectedRebootResponse.extend(gatewayMacAddress)
    expectedRebootResponse.extend(b'\x09\x00')
    if rebootResponse!=expectedRebootResponse:
        error('Unexpected reboot response', binascii.hexlify(rebootResponse))
    info('Received the reboot confirmation from gateway')
    udpSocket.close()
    info('Upon startup, the gateway will attempt to grap a DHCP address, if it fails to do so, it will fallback to the static IP 192.168.4.101')

def convertCANBusFrameToGatewayFormat(CANBusFrame):
    flagbyte=0
    flagbyte|=0b10000000 if(CANBusFrame.is_extended_id) else 0
    flagbyte|=0b01000000 if(CANBusFrame.is_remote_frame) else 0
    flagbyte|=0b00001111 & CANBusFrame.dlc

    proprietaryFormat=bytearray()
    proprietaryFormat.extend(flagbyte.to_bytes(1, 'big'))
    proprietaryFormat.extend(CANBusFrame.arbitration_id.to_bytes(4, 'big'))
    proprietaryFormat.extend(CANBusFrame.data.ljust(8, b'\0'))
    debug("Conversion to Proprietary format yields: %s", proprietaryFormat.hex())
    return proprietaryFormat
    #return b'\x88\x12\x34\x56\x78\x11\x22\x33\x44\x55\x66\x77\x88'

def convertGatewayFormatToCANBusFrame(gatewayFormatBytes):
    is_extended_id=gatewayFormatBytes[0] & 0b10000000
    payloadLen=gatewayFormatBytes[0] & 0b00001111
    debug("gatewayFormatBytes[0]=%d payloadLen=%d", gatewayFormatBytes[0], payloadLen)
    arbitration_id=int.from_bytes(gatewayFormatBytes[1:5], 'big')
    msg=can.Message(is_extended_id=is_extended_id, arbitration_id=arbitration_id,data=gatewayFormatBytes[5:5+payloadLen])
    debug("gateway format to canbus yields message: %s", msg)
    return msg

def createTCPSocketToGateway(gatewayAddress, gatewayPort):
    sockettogateway=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockettogateway.settimeout(10)
    sockettogateway.connect((gatewayAddress, gatewayPort))
    sockettogateway.setblocking(False)
    return sockettogateway
    
def doBridge(canInterfaceName, gatewayAddress, gatewayPort):
    info("Starting bridge on virtual can device %s and gateway %s port %d", canInterfaceName, gatewayAddress, gatewayPort)
    sockettogateway=createTCPSocketToGateway(gatewayAddress, gatewayPort)
    
    try:
        bus = can.interface.Bus(bustype='socketcan', channel=canInterfaceName)
        BOTH_SOCKETS=[sockettogateway,bus]
        while(True):
            readyTriplet=select.select(BOTH_SOCKETS, [], [], None)
            #print(readyTriplet)
            for readySocket in readyTriplet[0]:
                if(sockettogateway==readySocket):
                    DATA_FRAME_LEN=13
                    gatewayFormatFrame=sockettogateway.recv(DATA_FRAME_LEN)
                    if(len(gatewayFormatFrame)>0):
                        while(len(gatewayFormatFrame)<DATA_FRAME_LEN):
                            gatewayFormatFrame+=sockettogateway.recv(DATA_FRAME_LEN-len(gatewayFormatFrame))
                    debug("Got a data frame from the gateway: %s", str(binascii.hexlify(gatewayFormatFrame)))
                    if(len(gatewayFormatFrame)==DATA_FRAME_LEN):
                        msg=convertGatewayFormatToCANBusFrame(gatewayFormatFrame)
                        bus.send(msg)
                    else:
                        raise Exception("Incompleted gateway message received")
                else:
                    CANBusFrame=bus.recv(0)
                    if(CANBusFrame is None):
                        debug(f"No data to read on the canbus side.")
                    elif(CANBusFrame.arbitration_id==0):
                        pass
                    else:
                        debug("Got %s from canbus", CANBusFrame)
                        gatewayCompatibleBytes=convertCANBusFrameToGatewayFormat(CANBusFrame)
                        sockettogateway.send(gatewayCompatibleBytes)

        bus.shutdown()
    except OSError as e:
        if(e.errno==19):
            error("No such network interface {canInterfaceName}. Maybe you need to configure it with these commands:")
            print("sudo modprobe vcan");
            print(f"sudo ip link add dev {canInterfaceName} type vcan bitrate 250000 mtu 16")
            print(f"sudo ip link set up {canInterfaceName}")
        else:
            print(e)
        
    sockettogateway.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
                    prog='ecane01-cli',
                    description='CLI app to the ECAN-E01 CANBus over ethernet gateway.\nEXAMPLE: ./ecane01-cli.py bridge -i 192.168.4.101 -p 8881 -c vcan0',
                    epilog='Use at your own risk')
    parser.add_argument('-d', '--devicename',  help='Name of the ECAN device')
    parser.add_argument('-n', '--netinterface',  help='Network interface to search for the CANBus gateway')
    parser.add_argument('-c', '--canbus',  default='vcan0', help='The CANBus interface to use locally Default: vcan0')
    parser.add_argument('-i', '--ipaddress', help='IP address of the CANBus gateway')
    parser.add_argument('-p', '--port', type=int, default=ECAN_GATEWAY_CAN1_TCP_PORT, help='TCP port of the CANBus gateway')
    parser.add_argument('-f', '--inputfile', help='TOML Configuration file to be used as input')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbose output')
    parser.add_argument('action', choices=['scan','reboot','readconf','writeconf','bridge', 'capture', 'test'])
    args = parser.parse_args()
    if(args.verbose==0):
        logging.basicConfig(level=logging.ERROR)
    elif(args.verbose==1):
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.DEBUG, style='{', datefmt='%Y-%m-%d %H:%M:%S', format='{asctime} {levelname} {filename}:{lineno}: {message}')

    debug(args)
    
    if args.action=='scan':
        (ip,mac)=discoverECanGateways(args.netinterface)
        if ip:
            deviceName=getGatewayName(ip)
            print("{}\t{}\t{}".format(mac.hex(':'),ip, deviceName))
        else:
            error('Gateway not found')
            exit(1)
    elif args.action=='readconf':
        if(args.inputfile):
            print(ProprietaryConfigFileReader.parseBinaryConfigurationFile(args.inputfile).totoml())
        elif(args.ipaddress):
            print(readConfiguration(args.ipaddress).totoml())
        elif(args.devicename):
            (ip, _)=discoverGatewayByName(args.devicename, args.netinterface)
            if ip is None:
                error("No ECAN device found on the network")
            else:
                print(readConfiguration(ip).totoml())
            exit(1)
    elif args.action=='writeconf':
        if(args.ipaddress and args.inputfile):
            with open(args.inputfile, 'r') as f:
                tomlContent=f.read()
                configRead=GatewayConfiguration.fromTOML(tomlContent)
                writeConfiguration(args.ipaddress, configRead)
                rebootGateway(args.ipaddress) #Configuration takes effect only on reboot?
        else:
            error("You must specify the -i and -f flag for writeconf")
            exit(1)
            
        
    elif args.action=='reboot':
        if(args.ipaddress):
            rebootGateway(args.ipaddress)
        else:
            error("You must specify the gateway address with the -i flag")
            exit(1)            
    elif args.action=='bridge':
        if(args.devicename and args.canbus and args.port):
            (ip, _)=discoverGatewayByName(args.devicename, args.netinterface)
            if ip is None:
                error("No ECAN device found on the network")
            else:
                doBridge(args.canbus, ip, args.port)
            exit(1)
        elif(args.canbus and args.ipaddress and args.port):
            doBridge(args.canbus, args.ipaddress, args.port)
        else:
            error("You must specify the gateway address with the -i flag and its port with the -p flag. The canbus can be specified with -c")
            exit(1)
    elif args.action=='capture':
        if(args.ipaddress and args.port):
            doCapture(args.ipaddress, args.port)
        else:
            error("You must specify the gateway address with the -i flag and its port with the -p flag")
            exit(1)
    elif args.action=='test':
        (udpSocket,gatewayIpAndPort, gatewayMacAddress)=udpConnectTo(args.ipaddress)
        configuration0Bytes=getConfigurationPage(udpSocket, gatewayMacAddress, gatewayIpAndPort, 0)
        config=GatewayConfiguration()
        ProprietaryConfigFileReader.parseConfigurationZero(configuration0Bytes, config)
