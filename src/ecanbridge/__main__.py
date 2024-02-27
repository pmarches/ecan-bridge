import argparse
from logging import debug,info,warning,error
import logging
from ecanbridge import ecan

parser = argparse.ArgumentParser(
                prog='ecane01-cli',
                description='CLI app to the ECAN-E01 CANBus over ethernet gateway.\nEXAMPLE: ./ecane01-cli.py bridge -i 192.168.4.101 -p 8881 -c vcan0',
                epilog='Use at your own risk')
parser.add_argument('-d', '--devicename',  help='Name of the ECAN device')
parser.add_argument('-n', '--netinterface',  help='Network interface to search for the CANBus gateway')
parser.add_argument('-c', '--canbus',  default='vcan0', help='The CANBus interface to use locally Default: vcan0')
parser.add_argument('-i', '--ipaddress', help='IP address of the CANBus gateway')
parser.add_argument('-p', '--port', type=int, default=ecan.ECAN_GATEWAY_CAN1_TCP_PORT, help='TCP port of the CANBus gateway')
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
    (ip,mac)=ecan.discoverECanGateways(args.netinterface)
    if ip:
        deviceName=ecan.getGatewayName(ip)
        print("{}\t{}\t{}".format(mac.hex(':'),ip, deviceName))
    else:
        error('Gateway not found')
        exit(1)
elif args.action=='readconf':
    if(args.inputfile):
        print(ecan.ProprietaryConfigFileReader.parseBinaryConfigurationFile(args.inputfile).totoml())
    elif(args.ipaddress):
        print(ecan.readConfiguration(args.ipaddress).totoml())
    elif(args.devicename):
        (ip, _)=ecan.discoverGatewayByName(args.devicename, args.netinterface)
        if ip is None:
            error("No ECAN device found on the network")
        else:
            print(ecan.readConfiguration(ip).totoml())
        exit(1)
elif args.action=='writeconf':
    if(args.ipaddress and args.inputfile):
        with open(args.inputfile, 'r') as f:
            tomlContent=f.read()
            configRead=ecan.GatewayConfiguration.fromTOML(tomlContent)
            ecan.writeConfiguration(args.ipaddress, configRead)
            ecan.rebootGateway(args.ipaddress) #Configuration takes effect only on reboot?
    else:
        error("You must specify the -i and -f flag for writeconf")
        exit(1)
        
    
elif args.action=='reboot':
    if(args.ipaddress):
        ecan.rebootGateway(args.ipaddress)
    else:
        error("You must specify the gateway address with the -i flag")
        exit(1)            
elif args.action=='bridge':
    if(args.devicename and args.canbus and args.port):
        (ip, _)=ecan.discoverGatewayByName(args.devicename, args.netinterface)
        if ip is None:
            error("No ECAN device found on the network")
        else:
            ecan.doBridge(args.canbus, ip, args.port)
        exit(1)
    elif(args.canbus and args.ipaddress and args.port):
        ecan.doBridge(args.canbus, args.ipaddress, args.port)
    else:
        error("You must specify the gateway address with the -i flag and its port with the -p flag. The canbus can be specified with -c")
        exit(1)
elif args.action=='capture':
    if(args.ipaddress and args.port):
        ecan.doCapture(args.ipaddress, args.port)
    else:
        error("You must specify the gateway address with the -i flag and its port with the -p flag")
        exit(1)
elif args.action=='test':
    (udpSocket,gatewayIpAndPort, gatewayMacAddress)=udpConnectTo(args.ipaddress)
    configuration0Bytes=ecan.getConfigurationPage(udpSocket, gatewayMacAddress, gatewayIpAndPort, 0)
    config=ecan.GatewayConfiguration()
    ecan.ProprietaryConfigFileReader.parseConfigurationZero(configuration0Bytes, config)
