mod modules;

fn main() {
    
    let pid = modules::getPID();
    
    if pid != sysinfo::Pid::from(0) {
        println!("{}{:?} process running in PID:{}", "\t".repeat(5), env!("CARGO_PKG_NAME"), std::process::id());      
        println!("{}PID of SSHD:{}", "\t".repeat(6),pid);
        
        let child_pid = modules::checkTHREAD(pid);
        println!("{}PID of Child:{}\n", "\t".repeat(6), child_pid);

        // Child lookup in syscall
        modules::debugTHREAD(child_pid);

    } else {
        println!("{}SSHD is not active.", "\t".repeat(6));
        std::process::exit(0);
    }

}
