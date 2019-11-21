from flask import Flask
from flask import json
import pcapy
from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactDecoder import ImpactPacket
from impacket.ImpactDecoder import IP6
from impacket.ImpactDecoder import IPDecoder
from impacket.ImpactDecoder import ICMP6
from impacket.ImpactDecoder import eap
from impacket.ImpactDecoder import dhcp
from multiprocessing import Queue
from math import log
from datetime import datetime
import threading
import ipwhois
import struct
import getmac
import sys
import socket
import fcntl
import netifaces


svc = Flask(__name__)


class LogObject(object):
    m_Log   = [str()] * 10240
    m_Size  = 10240
    m_Head  = 0
    m_Tail  = 0


    def AddLogLine(self, line):
        self.m_Log[self.m_Tail % self.m_Size] = line
        self.m_Head = self.m_Head if self.m_Tail < self.m_Size else self.m_Head + 1
        self.m_Tail += 1


    def GetLogLine(self, line):
        return True, self.m_Log[line % self.m_Size]


    def SetLogSize(self, size):
        self.m_Size = size
        self.m_Log = [str()] * self.m_Size
        self.m_Head = 0
        self.m_Tail = 0
        return True, "Log size: %s" % str(size)


    def ClearLog(self):
        self.SetLogSize(self.m_Size)
        return True, 'Log Cleared'


    def GetLog(self):
        return True, [(self.m_Log[i]) for i in [(k % self.m_Size) for k in range(self.m_Head, self.m_Tail)]]


class CaptureContextObject(LogObject):
    m_Captures = {}
    m_Threads  = {}
    m_Commands = {}

    m_Cache = {}
    m_PrintStdout = True

    def __init__(self):
        self.m_Cache['Whois'] = {}


    def PrettySize(n,pow=0,b=1024,u='B',pre=['']+[p+'i'for p in'KMGTPEZY']):
        pow,n=min(int(log(max(n*b**pow,1),b)),len(pre)-1),n*b**pow
        return "%%.%if %%s%%s"%abs(pow%(-pow-1))%(n/b**float(pow),pre[pow],u)


    def GetMAC(self, p):
        return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (p[0], p[1], p[2], p[3], p[4], p[5])


    def GetIPv4Address(self, interface):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface[:15].encode())
        )[20:24])


    def GetIPv6Address(self, interface):
        return netifaces.ifaddresses(interface)[netifaces.AF_INET6][0]['addr']


    def GetDHCPRequestType(self, r):
        DHCPTypes = {
                1 : "DHCPDISCOVER",
                2 : "DHCPOFFER",
                3 : "DHCPREQUEST",
                4 : "DHCPDECLINE",
                5 : "DHCPACK",
                6 : "DHCPNAK",
                7 : "DHCPRELEASE",
                8 : "DHCPINFORM",
                9 : "DHCPFORCERENEW",
                10: "DHCPLEASEQUERY",
                11: "DHCPLEASEUNASSIGNED",
                12: "DHCPLEASEUNKNOWN",
                13: "DHCPLEASEACTIVE",
                14: "DHCPBULKLEASEQUERY",
                15: "DHCPLEASEQUERYDONE",
                16: "DHCPACTIVELEASEQUERY",
                17: "DHCPLEASEQUERYSTATUS",
                18: "DHCPTLS"
        }

        return DHCPTypes.get(r)


    def Whois(self, ip):
        try:
            if ip not in self.m_Cache['Whois']:
                wobj = ipwhois.IPWhois(ip)
                self.m_Cache['Whois'][ip] = wobj.lookup_whois()

            return True, self.m_Cache['Whois'][ip]

        except:
            pass

        return False, '%s not found.' % ip


    def GetIPDescription(self, ip):
        try:
            if type(self.m_Cache['Whois'][ip]['nets'][0]['description']) == str:
                return self.m_Cache['Whois'][ip]['nets'][0]['description'] 
        except:
            pass

        return ""


    def Start(self, interface):
        if interface not in self.m_Commands:
            self.m_Commands[interface] = Queue()

        if interface not in self.m_Cache:
            self.m_Cache[interface] = {}
            self.m_Cache[interface]['IPv4_Addr']    = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
            self.m_Cache[interface]['IPv6_Addr']    = netifaces.ifaddresses(interface)[netifaces.AF_INET6][0]['addr']
            self.m_Cache[interface]['HW_Addr']      = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
            self.m_Cache[interface]['EAPOL']        = []
            self.m_Cache[interface]['Machines']     = {}
            self.m_Cache[interface]['Contacts']     = {}
            self.m_Cache[interface]['DHCP']         = {}
            self.m_Cache[interface]['IPv4']         = {}
            self.m_Cache[interface]['IPv6']         = {}
            print(self.m_Cache[interface])


        def AddMachine(machine):
            nonlocal interface
            if machine is not self.m_Cache[interface]['HW_Addr'] and machine not in self.m_Cache[interface]['Machines']:
                self.m_Cache[interface]['Machines'][machine] = {'RX' : 0, 'TX' : 0 }


        def RXMachine(machine, packet_size):
            if machine in self.m_Cache[interface]['Machines']:
                self.m_Cache[interface]['Machines'][machine]['RX'] += packet_size


        def TXMachine(machine, packet_size):
            if machine in self.m_Cache[interface]['Machines']:
                self.m_Cache[interface]['Machines'][machine]['TX'] += packet_size


        def AddIP(ip, version='IPv4'):
            nonlocal interface
            if ip not in self.m_Cache[interface][version]:
                self.m_Cache[interface][version][ip] = getmac.get_mac_address(ip=ip)


        def AddContact(ip, contact):
            nonlocal interface
            if ip not in self.m_Cache[interface]['Contacts']:
                self.m_Cache[interface]['Contacts'][ip] = []
            if contact not in self.m_Cache[interface]['Contacts'][ip]:
                self.m_Cache[interface]['Contacts'][ip].append(contact)


        def CaptureCB(interface):
            
            if interface not in self.m_Captures:
                self.m_Captures[interface] = pcapy.open_live(interface, 65536, 1, 0)
                decoder = EthDecoder()

                logline = "[START]"
                while 1:
                    self.AddLogLine("[" + str(datetime.now()) + "]" + logline)

                    if self.m_PrintStdout:
                        svc.logger.info(logline)

                    (header, payload) = self.m_Captures[interface].next()
                    packet_size = len(payload)
                    packet = decoder.decode(payload)

                    logline = interface.rjust(6) + " : " + CaptureContextObject.PrettySize(packet_size).ljust(7) + " "

                    source_mac      = self.GetMAC(packet.get_ether_dhost())
                    destination_mac = self.GetMAC(packet.get_ether_shost())

                    AddMachine(source_mac)
                    AddMachine(destination_mac)

                    TXMachine(source_mac, packet_size)
                    RXMachine(destination_mac, packet_size)

                    logline +=  source_mac + " => " + destination_mac.ljust(18)

                    if type(packet.child()) == eap.EAPOL:
                        if packet.child().packet_type == eap.EAPOL.EAPOL_KEY:
                            if source_mac not in self.m_Cache[interface]['EAPOL']:
                                self.m_Cache[interface]['EAPOL'].append(source_mac)
                            logline += "[EAPOL] " + source_mac
                        continue


                    if type(packet.child()) == ImpactPacket.ARP:
                        logline += "[ARP]"
                        continue


                    version = 'IPv6' if type(packet.child()) == IP6.IP6 else 'IPv4' 

                    if type(packet.child()) == ImpactPacket.IP or type(packet.child()) == IP6.IP6:
                        ip = packet.child()

                        logline += "[" + version + "]"

                        source_ip      = ip.get_ip_src() if version is 'IPv4' else ip.get_ip_src().as_string()
                        destination_ip = ip.get_ip_dst() if version is 'IPv4' else ip.get_ip_dst().as_string()

                        AddIP(source_ip, version)
                        AddIP(destination_ip, version)
                        AddContact(source_ip, destination_ip)

                        self.Whois(source_ip)
                        self.Whois(destination_ip)

                        sourceName = self.GetIPDescription(source_ip)
                        destinationName = self.GetIPDescription(destination_ip)

                        logline += source_ip.rjust(25)
                        logline += " => "
                        logline += destination_ip.ljust(25)

                        if type(ip.child()) == ImpactPacket.UDP:
                            logline += "[UDP]"
                            udp = ip.child()
                            sport = udp.get_uh_sport()
                            dport = udp.get_uh_dport()
                            logline += str(sport).rjust(6) + " => " + str(dport).ljust(6)
                            if dport in (67, 68) and sport in (67, 68):
                                d = dhcp.BootpPacket(udp.child().get_packet())
                                off = len(d.getData())
                                if udp.child().get_packet()[off:off+4] == dhcp.DhcpPacket.MAGIC_NUMBER.to_bytes(4, 'big'):
                                    requestType = self.GetDHCPRequestType(udp.child().get_packet()[off+6])
                                    logline += "[" + requestType + "]"
                                    self.m_Cache[interface]['DHCP'][source_mac] = requestType

                        if type(ip.child()) == ImpactPacket.TCP:
                            logline += "[TCP]"
                            tcp = ip.child()
                            logline += str(tcp.get_th_sport()).rjust(6) + " => " + str(tcp.get_th_dport()).ljust(6)
                        if type(ip.child()) == ImpactPacket.ICMP:
                            logline += "[ICMP]"
                            icmp = ip.child()
                            logline += "[" + icmp.get_type_name(icmp.get_icmp_type()) + "]"
                            continue
                        if type(ip.child()) == ICMP6.ICMP6:
                            logline += "[ICMP6]"
                            continue
                        if type(ip.child()) == ImpactPacket.IGMP:
                            logline += "[IGMP]"
                            continue

                        if len(sourceName):
                            logline += " <= (" + sourceName + ")"
                            
                        if len(destinationName):
                            logline += " => (" + destinationName + ")"


                    if not self.m_Commands[interface].empty():
                        del self.m_Commands[interface]
                        del self.m_Captures[interface]
                        del self.m_Threads[interface]
                        break

        if interface not in self.m_Threads:
            self.m_Threads[interface] = threading.Thread(target=CaptureCB, args=(interface,))
            self.m_Threads[interface].start()


    def Machines(self, interface):
        if interface in self.m_Cache:
            return True, [(k) for k,_ in self.m_Cache[interface]['Machines'].items()]
        return False, '% not found.' % interface


    def SentReceived(self, machine, io='TX'):
        for interface in self.m_Cache:
            if 'Machines' in self.m_Cache[interface] and machine in self.m_Cache[interface]['Machines']:
                return True, CaptureContextObject.PrettySize(self.m_Cache[interface]['Machines'][machine][io])
        return False, '%s not found.' % machine


    def IP(self, machine, version='IPv4'):
        for interface in self.m_Cache:
            if version in self.m_Cache[interface]:
                for ip in self.m_Cache[interface][version]:
                    if self.m_Cache[interface][version][ip] == machine:
                        return True, ip
        return False, '%s %s not found.' % (machine, version)


    def Contacts(self, interface, ip):
        if interface not in self.m_Cache:
            return False, 'Interface %s not found.' % interface
        if ip not in self.m_Cache[interface]['Contacts']:
            return False, 'IP %s not found.' % ip
        return True, self.m_Cache[interface]['Contacts'][ip]


    def Names(self, interface, ip):
        status, contacts = self.Contacts(interface, ip)
        if status:
            n = []
            for contact in contacts:
                try:
                    s, w = self.Whois(contact)
                    if not s:
                        continue
                    name = w['nets'][0]['name']
                    org  = w['asn_description']
                    country = w['asn_country_code']
                    n.append("%s, %s, %s" % (name, org, country))
                except:
                    pass

            svc.logger.info(contacts)
            svc.logger.info(n)
            if len(n):
                return True, list(set(n))
        else:
            return False, contacts

        return False, 'None found.' 


    def DHCP(self, interface):
        if interface not in self.m_Cache:
            return False, '%s not found.' % interface
        return True, self.m_Cache[interface]['DHCP']


    def EAPOL(self, interface):
        if interface not in self.m_Cache:
            return False, '%s not found.' % interface
        return True, list(self.m_Cache[interface]['EAPOL'])


    def Save(self):
        return True, self.m_Cache


    def Stop(self, interface):
        if interface in self.m_Threads:
            if interface not in self.m_Commands:
                self.m_Commands[interface] = Queue()

            self.m_Commands[interface].put("Stop")
            self.m_Captures[interface].set_timeout(1)
            self.m_Threads[interface].join()
            return True, 'Stopped %s' % interface

        return False, 'Interface not started: %s' % interface


    def Restart(self):
        restartQ = [(k) for k in self.m_Threads]
        for interface in restartQ:
            self.Stop(interface)

        self.m_Cache = {}
        self.m_Cache['Whois'] = {}

        for interface in restartQ:
            self.Start(interface)

        return True, 'Restarted: %s' % restartQ


    def Running(self):
        return True, [(k) for k in self.m_Threads]


CaptureContext = None


def StandardResponse(status, message):
    return svc.response_class(
        status   = 200 if status is True else 500,
        response = json.dumps(message),
        mimetype =' application/json'
    )


@svc.route('/interfaces')
def interfaces():
    """Obtain list of network interface"""
    return StandardResponse(200, str(pcapy.findalldevs()))


@svc.route('/machines/<string:interface>')
def machines(interface):
    """Obtain list of unique machine addresses"""
    status, message = CaptureContext.Machines(interface)
    return StandardResponse(status, message)


@svc.route('/getipv4/<string:machine>')
def getipv4(machine):
    """Obtain machine address IPv4, where possible"""
    status, message = CaptureContext.IP(machine)
    return StandardResponse(status, message)


@svc.route('/getipv6/<string:machine>')
def getipv6(machine):
    """Obtain machine address IPv6, where possible"""
    status, message = CaptureContext.IP(machine, version='IPv6')
    return StandardResponse(status, message)


@svc.route('/sent/<string:machine>')
def sent(machine):
    """Obtain total bytes transmitted from machine"""
    status, message = CaptureContext.SentReceived(machine,io='TX')
    return StandardResponse(status, message)


@svc.route('/received/<string:machine>')
def received(machine):
    """Obtain total bytes recieved by machine"""
    status, message = CaptureContext.SentReceived(machine,io='RX')
    return StandardResponse(status, message)


@svc.route('/dhcp/<string:interface>')
def dhcps(interface):
    """Obtain a list of machines that had made DHCP requests"""
    status, message = CaptureContext.DHCP(interface)
    return StandardResponse(status, message)


@svc.route('/eapol/<string:interface>')
def eapol(interface):
    """Obtain list of machine addresses that made EAPOL requests"""
    status, message = CaptureContext.EAPOL(interface)
    return StandardResponse(status, message)

    
@svc.route('/contacts/<string:interface>/<string:ip>')
def contacts(interface, ip):
    """Obtain a list known contacts associated with IP"""
    status, message = CaptureContext.Contacts(interface, ip)
    return StandardResponse(status, message)


@svc.route('/names/<string:interface>/<string:ip>')
def names(interface, ip):
    """Obtain a list of names of contacts made by an IP"""
    status, message = CaptureContext.Names(interface, ip)
    return StandardResponse(status, message)


@svc.route('/whois/<string:ip>')
def whois(ip):
    """Obtain whois entry of IP"""
    status, message = CaptureContext.Whois(ip)
    return StandardResponse(status, message)


@svc.route('/start/<string:interface>')
def start(interface):
    """Start Interface Capture"""
    if interface in pcapy.findalldevs():
        CaptureContext.Start(interface)
        return StandardResponse(True, '%s started.' % interface)
    else:
        return StandardResponse(False, '%s not found.' % interface)


@svc.route('/stop/<string:interface>')
def stop(interface):
    """Stop Interface Capture"""
    status, message = CaptureContext.Stop(interface)
    return StandardResponse(status, message)


@svc.route('/restart')
def restart():
    """Restart service"""
    status, message = CaptureContext.Restart()
    return StandardResponse(status, message)


@svc.route('/running')
def running():
    """Obtain a list of running interface"""
    status, message = CaptureContext.Running()
    return StandardResponse(status, message)


@svc.route('/save')
def save():
    """Save internal state as JSON"""
    status, message = CaptureContext.Save()
    svc.logger.info(message)
    return StandardResponse(status, message)


@svc.route('/log/size/<int:size>')
def logsize(size):
    """Configure the log size."""
    status, message = CaptureContext.SetLogSize(size)
    return StandardResponse(status, message)


@svc.route('/log/get')
def logget():
    status, message = CaptureContext.GetLog()
    return StandardResponse(status, message)


@svc.route('/log/clear')
def logclear():
    status, message = CaptureContext.ClearLog()
    return StandardResponse(status, message)


if __name__ == '__main__':
    CaptureContext = CaptureContextObject()
    svc.run(host='0.0.0.0', port=5000, threaded=True, debug=True)
    CaptureContext = CaptureContextObject()

