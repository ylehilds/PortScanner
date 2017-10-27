# PortScanner
Port Scanner Assignment


   Welcome to My Port Scanner you can do the following commands with this multi purpose port Scanner:

  The next 3 lines describes how to tcp/udp port scanning reading from a file (line separated), specify port range
  Usage - ./pscanner.py [tcp or udp] file [fileName Containing host addresses line separated] [First Port] [Last Port]
  Example - ./pscanner.py tcp file iplist.txt 22 54
  Example will TCP port scan ports 1 through 100 on the list of hosts from the file

  The next 7 lines describes how to tcp/udp port scanning specific host, host range, ports range
  Usage - ./pscanner.py [tcp or udp] [Target-IP/Target-IP-Range] [First Port] [Last Port]
  Example - ./pscanner.py tcp 192.168.207.121 22 54
  Example will TCP port scan ports 22 through 54 on 192.168.207.121

  Example - ./pscanner.py udp 192.168.207.121-122 22 54
  Example will UDP port scan ports 22 through 54 on host range 192.168.207.121 through 192.168.207.122

  Example - ./pscanner.py tcp 192.168.207.121/24 22 54
  Example will TCP port scan ports 22 through 54 on subnet /24 192.168.207.121/24 Note: Only /24 is supported in this subnet mode

  The next 3 lines describes how to perform host discovery using icmp, reading from a file (line sparated)
  Usage - ./pscanner.py icmp file [filename]
  Example - ./pscanner.py icmp file iplist.txt
  Example will perform an ICMP ping scan of the IP addresses listed in iplist.txt

  The next 3 lines describes how to perform host discovery using icmp,host range
  Usage - ./pscanner.py icmp [Target-IP or Target-IP-Range]
  Example - ./pscanner.py icmp 192.168.207.121-122
  Example will perform ICMP port discovery scan on range from 192.168.207.121 through 192.168.207.122

  The next 3 lines describes how to perform host discovery using icmp,specific host
  Usage - ./pscanner.py icmp [hostAddress]
  Example - ./pscanner.py icmp 192.168.207.121
  Example will perform an ICMP ping scan on the specified IP address

  The next 3 lines describes how to perform a traceroute from origin host to target host
  Usage - ./pscanner.py traceroute [Target-From-IP] [Target-To-IP]
  Example - ./pscanner.py traceroute 192.168.207.122 www.google.com
  Example will traceroute from a origin ip to a target ip or qualified domain name

  You can get all these help section using python by running the following command from a terminal: `./pscanner.py help`
