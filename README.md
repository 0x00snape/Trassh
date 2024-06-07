<h1>Trassh</h1>
Trassh is ssh session sniffer which sniffs the ongoing SSH session on victim machine.

<h2>Working</h2>
Trassh identifies the PID of SSHD and attached. Creating the certain tracer options to detect child_fork() and attached to it. The tracer reads data from CPU registers to determine the syscall being made or not. read() syscalls from fd (6) is used to accept inputs such as username and password. Knowing this we can identify exact syscall handles by user inputs. By this we can decode username and password.
