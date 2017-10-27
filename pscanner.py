#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import time
import sys

def udpOrTcpScan():

  scanType = sys.argv[1]
  #print scanType
  isFile = sys.argv[2]
  # this is a scan that loads the ip hosts addresses from file, you have a choice of tcp or udp port scans
  if isFile == 'file':
      #print addr
      #ip = addr.strip()
      if len(sys.argv) != 6:
        print "Usage - ./pscanner.py [tcp or udp] file [fileName Containing host addresses line separated] [First Port] [Last Port]"
        print "Example - ./pscanner.py tcp file iplist.txt 22 54"
        print "Example will TCP port scan ports 1 through 100 on the list of hosts from the file"
      
      start = int(sys.argv[4])
      end = int(sys.argv[5])
      filename = str(sys.argv[3])
      file = open(filename,'r')
      for addr in file:
        print addr.strip() + ':'
        for port in range(start,end+1):
          ip = addr.strip()
          if scanType == 'udp':
            ans = sr1(IP(dst=ip)/UDP(dport=port),timeout=5,verbose =0)
            time.sleep(1)
            if ans == None:
              print port
            else:
              pass
          elif scanType == 'tcp':
            ans = sr1(IP(dst=ip)/TCP(dport=port),timeout=5,verbose =0)
            time.sleep(1)
            if ans == None:
              pass
            else:
              if int(ans[TCP].flags) == 18:
                print port
              else:
                pass
  # not a file scan, it can be a range, specific host, and port start and end are required
  else:
    if len(sys.argv) != 5:
      print "Usage - ./pscanner.py [tcp or udp] [Target-IP/Target-IP-Range] [First Port] [Last Port]"
      print "Example - ./pscanner.py tcp 192.168.207.121 22 54"
      print "Example will TCP port scan ports 22 through 54 on 192.168.207.121"
      
      print "Example - ./pscanner.py udp 192.168.207.121-122 22 54"
      print "Example will UDP port scan ports 22 through 54 on host range 192.168.207.121 through 192.168.207.122"

      print "Example - ./pscanner.py tcp 192.168.207.121/24 22 54"
      print "Example will TCP port scan ports 22 through 54 on subnet /24 192.168.207.121/24 Note: Only /24 is supported in this subnet mode"
      sys.exit()
    else:
      ip = sys.argv[2]
      start = int(sys.argv[3])
      end = int(sys.argv[4])
      
      isRange = sys.argv[2].split('-')
      isSubnet = sys.argv[2].split('/')
      if len(isRange) == 2:
        hostStart = isRange[0].split('.')
        #print hostStart
        prefix = hostStart[0]+'.'+hostStart[1]+'.'+hostStart[2]+'.'
        #print prefix
        hostStart = int(hostStart[3])
        #print hostStart
        hostEnd   = int(isRange[1])
        #print hostEnd
        for host in range(hostStart,hostEnd+1):
          #print host
          hostString = prefix + str(host)
          print hostString
          for port in range(start,end+1):
            #print scanType
            if scanType == 'udp':
              #print "in scanType udp really"
              ans = sr1(IP(dst=hostString)/UDP(dport=port),timeout=5,verbose =0)
              time.sleep(1)
              if ans == None:
                print port
              else:
                pass
            elif scanType == 'tcp':
              ans = sr1(IP(dst=hostString)/TCP(dport=port),timeout=5,verbose =0)
              time.sleep(1)
              if ans == None:
                pass
              else:
                if int(ans[TCP].flags) == 18:
                  print port
                else:
                  pass
      elif len(isSubnet) == 2:
        #print isSubnet[1]
        if int(isSubnet[1]) != 24:
          print 'currently this tool only allows /24 subnets, sorry for the inconvenience!'
          sys.exit()
        hostStart = isSubnet[0].split('.')
        #print hostStart
        prefix = hostStart[0]+'.'+hostStart[1]+'.'+hostStart[2]+'.'
        #print prefix
        hostStart = int(hostStart[3])
        #print hostStart
        hostEnd   = 254
        #print hostEnd
        for host in range(hostStart,hostEnd+1):
          #print host
          hostString = prefix + str(host)
          print hostString
          for port in range(start,end+1):
            if scanType == 'udp':
              #print "in scanType udp really"
              ans = sr1(IP(dst=hostString)/UDP(dport=port),timeout=5,verbose =0)
              time.sleep(1)
              if ans == None:
                print port
              else:
                pass
            elif scanType == 'tcp':
              ans = sr1(IP(dst=hostString)/TCP(dport=port),timeout=5,verbose =0)
              time.sleep(1)
              if ans == None:
                pass
              else:
                if int(ans[TCP].flags) == 18:
                  print port
                else:
                  pass
      else:
        for port in range(start,end+1):
          if scanType == 'udp': 
            ans = sr1(IP(dst=ip)/UDP(dport=port),timeout=5,verbose =0)
            time.sleep(1)
            if ans == None:
              print port
            else:
              pass
          if scanType == 'tcp': 
            ans = sr1(IP(dst=ip)/TCP(dport=port),timeout=1,verbose =0)
            if ans == None:
              pass
            else:
              if int(ans[TCP].flags) == 18:
                print port
              else:
                pass

def icmpScan():
  isFile = sys.argv[2]
  if isFile == 'file':
    if len(sys.argv) != 4:
      print "Usage - ./pscanner.py icmp file [filename]"
      print "Example - ./pscanner.py icmp file iplist.txt"
      print "Example will perform an ICMP ping scan of the IP addresses listed in iplist.txt"
      sys.exit()
    filename = str(sys.argv[3])
    #print filename
    file = open(filename,'r')
    for addr in file:
      #print addr
      ans=sr1(IP(dst=addr.strip())/ICMP(),timeout=1,verbose=0)
      if ans == None:
        pass
      else:
        print addr.strip()
  else:
    if len(sys.argv) != 3:
      print "Usage - ./pscanner.py icmp [Target-IP or Target-IP-Range]"
      print "Example - ./pscanner.py icmp 192.168.207.121-122"
      print "Example will perform ICMP port discovery scan on range from 192.168.207.121 through 192.168.207.122"
      sys.exit()
    else:     
      isRange = sys.argv[2].split('-')
      isSubnet = sys.argv[2].split('/')
      if len(isRange) == 2:
        hostStart = isRange[0].split('.')
        #print hostStart
        prefix = hostStart[0]+'.'+hostStart[1]+'.'+hostStart[2]+'.'
        #print prefix
        hostStart = int(hostStart[3])
        #print hostStart
        hostEnd   = int(isRange[1])
        #print hostEnd
        for host in range(hostStart,hostEnd+1):
          #print host
          hostString = prefix + str(host)
          print hostString
          #print addr
          ans=sr1(IP(dst=hostString.strip())/ICMP(),timeout=1,verbose=0)
          if ans == None:
            pass
          else:
            print hostString.strip()
      elif len(isSubnet) == 2:
        #print isSubnet[1]
        if int(isSubnet[1]) != 24:
          print 'currently this tool only allows /24 subnets, sorry for the inconvenience!'
          sys.exit()
        hostStart = isSubnet[0].split('.')
        #print hostStart
        prefix = hostStart[0]+'.'+hostStart[1]+'.'+hostStart[2]+'.'
        #print prefix
        hostStart = int(hostStart[3])
        #print hostStart
        hostEnd   = 254
        #print hostEnd
        for host in range(hostStart,hostEnd+1):
          #print host
          hostString = prefix + str(host)
          print hostString
          #print addr
          ans=sr1(IP(dst=hostString.strip())/ICMP(),timeout=1,verbose=0)
          if ans == None:
            pass
          else:
            print hostString.strip()
      else:
        if len(sys.argv) != 3:
          print host
          print "Usage - ./pscanner.py icmp [hostAddress]"
          print "Example - ./pscanner.py icmp 192.168.207.121"
          print "Example will perform an ICMP ping scan on the specified IP address"
          sys.exit()
        host = sys.argv[2]
        #print addr
        ans=sr1(IP(dst=host.strip())/ICMP(),timeout=1,verbose=0)
        if ans == None:
          pass
        else:
          print host.strip()

def tracerouteScan():
  if len(sys.argv) != 4:
    print "Usage - ./pscanner.py traceroute [Target-From-IP] [Target-To-IP]"
    print "Example - ./pscanner.py traceroute 192.168.207.122 www.google.com"
    print "Example will traceroute from a origin ip to a target ip or qualified domain name"
    sys.exit()
  else:
    source = sys.argv[2]
    target = sys.argv[3]
    result, unans = traceroute(target,l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname=source)))

def helpSection():
  print "Welcome to My Port Scanner you can do the following commands with this multi purpose port Scanner: \n"

  print "The next 3 lines describes how to tcp/udp port scanning reading from a file (line separated), specify port range"
  print "Usage - ./pscanner.py [tcp or udp] file [fileName Containing host addresses line separated] [First Port] [Last Port]"
  print "Example - ./pscanner.py tcp file iplist.txt 22 54"
  print "Example will TCP port scan ports 1 through 100 on the list of hosts from the file \n"

  print "The next 7 lines describes how to tcp/udp port scanning specific host, host range, ports range"
  print "Usage - ./pscanner.py [tcp or udp] [Target-IP/Target-IP-Range] [First Port] [Last Port]"
  print "Example - ./pscanner.py tcp 192.168.207.121 22 54"
  print "Example will TCP port scan ports 22 through 54 on 192.168.207.121 \n"
    
  print "Example - ./pscanner.py udp 192.168.207.121-122 22 54"
  print "Example will UDP port scan ports 22 through 54 on host range 192.168.207.121 through 192.168.207.122 \n"

  print "Example - ./pscanner.py tcp 192.168.207.121/24 22 54"
  print "Example will TCP port scan ports 22 through 54 on subnet /24 192.168.207.121/24 Note: Only /24 is supported in this subnet mode \n"

  print "The next 3 lines describes how to perform host discovery using icmp, reading from a file (line sparated)"
  print "Usage - ./pscanner.py icmp file [filename]"
  print "Example - ./pscanner.py icmp file iplist.txt"
  print "Example will perform an ICMP ping scan of the IP addresses listed in iplist.txt \n"

  print "The next 3 lines describes how to perform host discovery using icmp,host range"
  print "Usage - ./pscanner.py icmp [Target-IP or Target-IP-Range]"
  print "Example - ./pscanner.py icmp 192.168.207.121-122"
  print "Example will perform ICMP port discovery scan on range from 192.168.207.121 through 192.168.207.122 \n"

  print "The next 3 lines describes how to perform host discovery using icmp,specific host"
  print "Usage - ./pscanner.py icmp [hostAddress]"
  print "Example - ./pscanner.py icmp 192.168.207.121"
  print "Example will perform an ICMP ping scan on the specified IP address \n"

  print "The next 3 lines describes how to perform a traceroute from origin host to target host"
  print "Usage - ./pscanner.py traceroute [Target-From-IP] [Target-To-IP]"
  print "Example - ./pscanner.py traceroute 192.168.207.122 www.google.com"
  print "Example will traceroute from a origin ip to a target ip or qualified domain name \n"

scanType = sys.argv[1]
if scanType == 'udp':
  print "you chose udp scan"
  udpOrTcpScan()
elif scanType == 'tcp':
  print "you chose tcp scan"
  udpOrTcpScan()
elif scanType == 'icmp':
  print "you chose icmp scan"
  icmpScan()
elif scanType == 'traceroute':
  print "you chose traceroute scan"
  tracerouteScan() 
elif scanType == 'help':
  print "you chose HELP section"
  helpSection() 


