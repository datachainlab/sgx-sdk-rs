use sgx_types::*;

static ENCLAVE_FILE: &str = "../bin/enclave.signed.so";

extern "C" {
    fn ecall_sample(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        input: *const u8,
        input_len: usize,
        output: *mut u8,
        output_buf_len: usize,
        output_len: *mut usize,
    ) -> sgx_status_t;
}

fn main() {
    println!("=== SGX Prohibited Instructions Trap Test ===");

    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && (args[1] == "--help" || args[1] == "-h") {
        println!("Usage: {} [instruction]", args[0]);
        println!();
        println!("Available instructions:");
        println!("  cpuid     - Execute CPUID instruction");
        println!("  syscall   - Execute SYSCALL instruction");
        println!("  sysenter  - Execute SYSENTER instruction");
        println!("  int80     - Execute INT 0x80 instruction");
        println!();
        println!("Without arguments, executes normal 'Hello World' test");
        return;
    }

    let input_string = if args.len() > 1 {
        args[1].clone()
    } else {
        "Hello World".to_string()
    };

    println!("[*] Input argument: {input_string}");

    // Create enclave based on SGX_MODE
    let debug = 1; // Use 1 for debug mode
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };

    #[cfg(sgx_sim)]
    let enclave = {
        println!("[*] Running in SGX simulation mode with prohibited instruction handling");
        match sgx_urts::simulate::create_enclave_with_prohibited_instruction_handling(
            ENCLAVE_FILE,
            debug,
            &mut misc_attr,
        ) {
            Ok(r) => {
                println!("[+] Enclave initialization succeeded {:?}", r.geteid());
                r
            }
            Err(x) => {
                eprintln!("[-] Enclave initialization failed: {}", x.as_str());
                return;
            }
        }
    };

    #[cfg(not(sgx_sim))]
    let enclave = {
        println!("[*] Running in SGX hardware mode");
        let mut launch_token = [0u8; 1024];
        let mut launch_token_updated = 0;
        match sgx_urts::SgxEnclave::create(
            ENCLAVE_FILE,
            debug,
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr,
        ) {
            Ok(r) => {
                println!("[+] Enclave initialization succeeded {:?}", r.geteid());
                r
            }
            Err(x) => {
                eprintln!("[-] Enclave initialization failed: {}", x.as_str());
                return;
            }
        }
    };

    let mut output_buf = vec![0u8; 256];
    let mut output_len: usize = 0;

    println!("[*] About to call ecall_sample...");
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        ecall_sample(
            enclave.geteid(),
            &mut retval,
            input_string.as_ptr(),
            input_string.len(),
            output_buf.as_mut_ptr(),
            output_buf.len(),
            &mut output_len,
        )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {
            if retval == sgx_status_t::SGX_SUCCESS {
                let output_string = String::from_utf8_lossy(&output_buf[..output_len]);
                println!("[+] ECall succeeded");
                println!("    Input:  {input_string}");
                println!("    Output: {output_string}");

                match input_string.as_str() {
                    "cpuid" | "syscall" | "sysenter" | "int80" => {
                        println!("[!] WARNING: Prohibited instruction was trapped but execution continued");
                    }
                    _ => {
                        println!("[+] Normal execution completed");
                    }
                }
            } else {
                eprintln!("[-] ECall returned error: {retval:?}");
            }
        }
        _ => {
            eprintln!("[-] ECall failed: {result:?}");
        }
    }
}
