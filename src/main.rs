mod modules;

fn main() {

    // Restart self with sudo if needed
    sudo::escalate_if_needed().unwrap();

    // Check and Get SSHD PID 
    let pid = modules::getPID();
    
    println!("{}{:?} process running in PID:{}", "\t".repeat(5), env!("CARGO_PKG_NAME"), std::process::id());      
    println!("{}PID of SSHD:{}", "\t".repeat(6),pid);
        
    let child_pid = modules::checkTHREAD(pid);
    println!("{}PID of Child:{}\n", "\t".repeat(6), child_pid);

    // Child lookup in syscall
    modules::debugTHREAD(child_pid);

}
