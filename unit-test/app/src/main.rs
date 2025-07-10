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

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::slice;
use std::str;
use std::sync::atomic::{AtomicU32, Ordering};

static ENCLAVE_FILE: &str = "enclave.signed.so";

// Static variables to track trapped instructions
#[cfg(sgx_sim)]
static CPUID_TRAP_COUNT: AtomicU32 = AtomicU32::new(0);
#[cfg(sgx_sim)]
static SYSCALL_TRAP_COUNT: AtomicU32 = AtomicU32::new(0);
#[cfg(sgx_sim)]
static SYSENTER_TRAP_COUNT: AtomicU32 = AtomicU32::new(0);
#[cfg(sgx_sim)]
static INT80_TRAP_COUNT: AtomicU32 = AtomicU32::new(0);

extern "C" {
    fn test_main_entrance(eid: sgx_enclave_id_t, retval: *mut size_t) -> sgx_status_t;
}

// Callback function for SIGTRAP handler
#[cfg(sgx_sim)]
fn sigtrap_callback(_sig: libc::c_int, _info: *mut libc::siginfo_t, context: *mut libc::c_void) {
    unsafe {
        let uc = context as *mut libc::ucontext_t;
        let gregs = &(*uc).uc_mcontext.gregs;
        let rip = gregs[16]; // REG_RIP = 16 on x86_64

        // RIP points after INT3+identifier, so we need to check RIP-1 for the identifier
        let identifier = *((rip - 1) as *const u8);
        match identifier {
            0x01 => {
                let count = CPUID_TRAP_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
                let msg = format!("[App Callback] CPUID trapped, count: {count}\n");
                libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
            }
            0x02 => {
                let count = SYSCALL_TRAP_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
                let msg = format!("[App Callback] SYSCALL trapped, count: {count}\n");
                libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
            }
            0x03 => {
                let count = SYSENTER_TRAP_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
                let msg = format!("[App Callback] SYSENTER trapped, count: {count}\n");
                libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
            }
            0x04 => {
                let count = INT80_TRAP_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
                let msg = format!("[App Callback] INT 0x80 trapped, count: {count}\n");
                libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
            }
            _ => {}
        }
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ocall_print_string(str_ptr: *const u8, str_len: usize) {
    if let Ok(s) = str::from_utf8(slice::from_raw_parts(str_ptr, str_len)) {
        print!("{s}");
    }
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };

    #[cfg(sgx_sim)]
    {
        println!(
            "[*] Running unit tests in SGX simulation mode with prohibited instruction handling"
        );
        // Use extended version with chaining disabled for unit tests to avoid conflicts
        sgx_urts::simulate::create_enclave_with_prohibited_instruction_handling_ex(
            ENCLAVE_FILE,
            debug,
            &mut misc_attr,
            false,                  // disable chaining to avoid conflicts with SGX simulator
            Some(sigtrap_callback), // provide callback to track traps
        )
    }

    #[cfg(not(sgx_sim))]
    {
        println!("[*] Running unit tests in SGX hardware mode");
        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;
        SgxEnclave::create(
            ENCLAVE_FILE,
            debug,
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
        let cpuid_count = CPUID_TRAP_COUNT.load(Ordering::SeqCst);
        let syscall_count = SYSCALL_TRAP_COUNT.load(Ordering::SeqCst);
        let sysenter_count = SYSENTER_TRAP_COUNT.load(Ordering::SeqCst);
        let int80_count = INT80_TRAP_COUNT.load(Ordering::SeqCst);

        println!("[*] CPUID traps: {cpuid_count}");
        println!("[*] SYSCALL traps: {syscall_count}");
        println!("[*] SYSENTER traps: {sysenter_count}");
        println!("[*] INT 0x80 traps: {int80_count}");

        // Check that each instruction was trapped at least once
        if cpuid_count > 0 && syscall_count > 0 && sysenter_count > 0 && int80_count > 0 {
            println!("[+] All prohibited instructions were successfully trapped!");
        } else {
            println!("[-] Some instructions were not trapped!");
            if cpuid_count == 0 {
                println!("    [!] CPUID was not trapped");
            }
            if syscall_count == 0 {
                println!("    [!] SYSCALL was not trapped");
            }
            if sysenter_count == 0 {
                println!("    [!] SYSENTER was not trapped");
            }
            if int80_count == 0 {
                println!("    [!] INT 0x80 was not trapped");
            }

            enclave.destroy();
            eprintln!("\n[-] CRITICAL: Prohibited instruction trapping failed! Aborting.");
            std::process::exit(1);
        }
    }

    enclave.destroy();
}
