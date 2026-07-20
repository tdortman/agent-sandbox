use std::io::Write;

#[test]
fn read_proc_mem_reads_requested_bytes_from_a_file() {
    let path = std::env::temp_dir().join(format!("agent-sandbox-sysutil-{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create memory file");
    file.write_all(b"0123456789").expect("write memory file");

    let mut bytes = [0_u8; 4];
    agent_sandbox_sysutil::read_proc_mem(&path, 3, &mut bytes).expect("read memory range");
    std::fs::remove_file(path).expect("remove memory file");

    assert_eq!(&bytes, b"3456");
}

#[test]
fn process_vm_readv_into_handles_empty_buffers_without_a_syscall() {
    let mut bytes = [];
    assert_eq!(
        agent_sandbox_sysutil::process_vm_readv_into(std::process::id(), 0, &mut bytes),
        Some(0)
    );
}
