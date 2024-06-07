<h1>Trassh</h1>
Trassh is ssh session sniffer written in rustlang which uses ptrace for sniffing the ongoing SSH session on victim machine.

<h2>Working</h2>
Trassh identifies the PID of SSHD and attached. Creating the certain tracer options to detect child_fork() and attached to it. The tracer reads data from CPU registers to determine the syscall being made or not. read() syscalls from fd (6) is used to accept inputs such as username and password. Knowing this we can identify exact syscall handles by user inputs. By this we can decode username and password.

## Installation and Usage
Uses the sudo privilege keep that in mind.
```bash
:$ git clone https://github.com/0x00snape/Trassh.git
:$ cd Trassh
:$ cargo build --release
:$ sudo ./trassh
```
## License
This project is licensed under [MIT](https://github.com/0x00snape/Trassh/blob/main/LICENSE)
