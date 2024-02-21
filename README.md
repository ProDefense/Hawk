# Hawk

Hawk is a lightweight Golang tool designed to monitor the `sshd` and `su` services for passwords on Linux systems. It utilizes netlink sockets to capture proc events and ptrace to trace system calls related to password-based authentication.

## Features

- Monitors SSH and SU commands for passwords
- Reads memory from sshd and sudo system calls without writing to traced processes
- Exfiltrates passwords via HTTP GET requests to a specified web server
- Inspired by [3snake](https://github.com/blendin/3snake)

## Build

```bash
go build -o hawk
```

## Usage

1. Adjust the HTTP Server location in the exfil.go file.
2. Build Hawk using the provided command.
3. Run Hawk with ./hawk.

## Limitations

- Linux systems with ptrace enabled
- `/proc` filesystem must be mounted

## Disclaimer

This tool is intended for ethical and educational purposes only. Unauthorized use is prohibited. Use at your own risk.

## Credits

Hawk is inspired by the work of [blendin](https://github.com/blendin) and their tool [3snake](https://github.com/blendin/3snake).
