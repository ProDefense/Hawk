<h1 align="center">
<br>
<img src='https://uploads-ssl.webflow.com/648e4ba94fdf34ba5288e0c3/65d950ef50097152325d639e_hawk%20small.png' height="375" border="2px solid #555">
<br>
Hawk
</h1>

Hawk is a lightweight Golang tool designed to monitor the `sshd`, `sudo` and `su` services for passwords on Linux systems. It reads the content of the proc directory to capture events, and ptrace to trace syscalls related to password-based authentication.

## Blog Post
https://www.prodefense.io/blog/hawks-prey-snatching-ssh-credentials

## Features

- Monitors SSH, SUDO and SU commands for passwords
- Reads memory from sshd, sudo and sudo syscalls without writing to traced processes
- Exfiltrates passwords via HTTP/S requests to a specified web server
- Inspired by [3snake](https://github.com/blendin/3snake)

## Build

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o hawk
```

## Usage

1. Adjust the HTTP Server location in the main.go file.
2. Build Hawk using the provided command.
3. Run Hawk with ./hawk.

## Limitations

- Linux systems with ptrace enabled
- `/proc` filesystem must be mounted

## Disclaimer

This tool is intended for ethical and educational purposes only. Unauthorized use is prohibited. Use at your own risk.

## Credits

Hawk is inspired by the work of [blendin](https://github.com/blendin) and their tool [3snake](https://github.com/blendin/3snake).
