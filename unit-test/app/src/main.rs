// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#[cfg(sgx_sim)]
use libc::{sigaction, siginfo_t, SA_NODEFER, SA_RESTART, SA_SIGINFO, SIGILL};
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::env;
#[cfg(sgx_sim)]
use std::mem;
#[cfg(sgx_sim)]
use std::ptr;
use std::slice;
use std::str;
use std::sync::atomic::{AtomicU32, Ordering};

static ENCLAVE_FILE: &str = "enclave.signed.so";

// Static variable to track trapped instructions
#[cfg(sgx_sim)]
static PROHIBITED_INSTRUCTION_COUNT: AtomicU32 = AtomicU32::new(0);

extern "C" {
    fn test_main_entrance(eid: sgx_enclave_id_t, retval: *mut size_t) -> sgx_status_t;
}

// Helper function to write log messages to stderr
#[cfg(sgx_sim)]
fn log_to_stderr(msg: &str) {
    unsafe {
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
    }
}

// SIGILL handler for UD2 traps
#[cfg(sgx_sim)]
extern "C" fn sigill_handler(_sig: libc::c_int, _info: *mut siginfo_t, context: *mut libc::c_void) {
    // Extract RIP from context
    let rip = unsafe {
        let uc = context as *mut libc::ucontext_t;
        let gregs = &(*uc).uc_mcontext.gregs;
        gregs[libc::REG_RIP as usize]
    };

    log_to_stderr(&format!(
        "[Unit Test] SIGILL handler called at RIP {rip:#x}\n"
    ));

    // Check if it's UD2 (0x0F 0x0B)
    let instruction_ptr = rip as *const u8;
    let first_byte = unsafe { *instruction_ptr };
    let second_byte = unsafe { *(instruction_ptr.add(1)) };

    if first_byte == 0x0F && second_byte == 0x0B {
        // UD2 detected - this is one of our patched prohibited instructions
        log_to_stderr(&format!(
            "[Unit Test] Prohibited instruction detected at RIP {rip:#x}\n"
        ));

        // Skip UD2 instruction (2 bytes)
        unsafe {
            let uc = context as *mut libc::ucontext_t;
            let gregs = &mut (*uc).uc_mcontext.gregs;
            gregs[libc::REG_RIP as usize] += 2;
        }

        // Increment counter
        let count = PROHIBITED_INSTRUCTION_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
        log_to_stderr(&format!(
            "[Unit Test] Prohibited instruction count: {count}\n"
        ));
    } else {
        log_to_stderr(&format!(
            "[Unit Test] Non-UD2 instruction: {first_byte:#x} {second_byte:#x}\n"
        ));
    }
}

/// Install SIGILL handler for unit tests
#[cfg(sgx_sim)]
fn install_sigill_handler() -> Result<(), String> {
    // Install our handler
    let mut sa: sigaction = unsafe { mem::zeroed() };
    sa.sa_sigaction = sigill_handler as usize;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;
    unsafe {
        libc::sigemptyset(&mut sa.sa_mask);

        if sigaction(SIGILL, &sa, ptr::null_mut()) != 0 {
            return Err("Failed to install SIGILL handler".to_string());
        }
    }

    println!("[Unit Test] SIGILL handler installed successfully");
    Ok(())
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ocall_print_string(str_ptr: *const u8, str_len: usize) {
    if let Ok(s) = str::from_utf8(slice::from_raw_parts(str_ptr, str_len)) {
        print!("{s}");
    }
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let debug = env::var("SGX_DEBUG").unwrap_or_default() == "1";
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };

    #[cfg(sgx_sim)]
    {
        println!(
            "[*] Running unit tests in SGX simulation mode with prohibited instruction handling"
        );

        // Install SIGILL handler before creating enclave
        if let Err(e) = install_sigill_handler() {
            panic!("Failed to install SIGILL handler: {e}");
        }

        // Use the patched enclave creation function
        sgx_urts::simulate::create_patched_enclave(ENCLAVE_FILE, debug.into(), &mut misc_attr)
    }

    #[cfg(not(sgx_sim))]
    {
        println!("[*] Running unit tests in SGX hardware mode");
        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;
        SgxEnclave::create(
            ENCLAVE_FILE,
            debug.into(),
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr,
        )
    }
}

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sgx_urts=debug".parse().unwrap()),
        )
        .init();

    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    let mut retval = 0usize;

    let result = unsafe { test_main_entrance(enclave.geteid(), &mut retval) };

    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }

    println!("[+] unit_test ended with {retval} tests passed!");

    // Verify trap counts if in simulation mode
    #[cfg(sgx_sim)]
    {
        println!("\n[*] Verifying trap counts...");
        let trap_count = PROHIBITED_INSTRUCTION_COUNT.load(Ordering::SeqCst);

        // We expect exactly 4 traps: one each for CPUID, SYSCALL, SYSENTER, and INT 0x80
        const EXPECTED_TRAP_COUNT: u32 = 4;

        println!("[*] Total prohibited instruction traps: {trap_count}");
        println!("[*] Expected trap count: {EXPECTED_TRAP_COUNT}");

        // Check for exact match
        if trap_count == EXPECTED_TRAP_COUNT {
            println!("[+] Prohibited instructions were successfully trapped (exact match)!");
        } else if trap_count == 0 {
            println!("[-] No prohibited instructions were trapped!");
            enclave.destroy();
            eprintln!("\n[-] CRITICAL: Prohibited instruction trapping failed! Aborting.");
            std::process::exit(1);
        } else {
            println!("[-] Trap count mismatch!");
            println!("    Expected: {EXPECTED_TRAP_COUNT}, but got: {trap_count}");
            enclave.destroy();
            eprintln!(
                "\n[-] CRITICAL: Incorrect number of prohibited instruction traps! Aborting."
            );
            std::process::exit(1);
        }
    }

    enclave.destroy();
}
