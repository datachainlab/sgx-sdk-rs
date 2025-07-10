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
// under the License.

use crate::SgxEnclave;
use libc::{sigaction, siginfo_t, SA_NODEFER, SA_RESTART, SA_SIGINFO, SIGTRAP};
use object::{Object, ObjectSection, SectionKind};
use sgx_types::*;
use std::mem;
use std::ptr;
use std::sync::Mutex;
use tracing::{debug, info};

// Store the original SIGTRAP handler that was installed before ours
static ORIGINAL_SIGTRAP_HANDLER: Mutex<Option<sigaction>> = Mutex::new(None);

// Instruction identifiers
const INST_ID_CPUID: u8 = 0x01;
const INST_ID_SYSCALL: u8 = 0x02;
const INST_ID_SYSENTER: u8 = 0x03;
const INST_ID_INT80: u8 = 0x04;

// User-defined callback type
pub type SigtrapCallback = fn(sig: libc::c_int, info: *mut siginfo_t, context: *mut libc::c_void);

// Store handler configuration
struct HandlerConfig {
    chain: bool,
    callback: Option<SigtrapCallback>,
}

static HANDLER_CONFIG: Mutex<Option<HandlerConfig>> = Mutex::new(None);

/// Patch prohibited instructions in enclave binary
pub fn patch_enclave_binary(binary_data: &[u8]) -> Result<Vec<u8>, String> {
    info!("Loading and patching enclave binary");

    // Create a mutable copy
    let mut patched_binary = binary_data.to_vec();

    // Parse the binary
    let obj =
        object::File::parse(binary_data).map_err(|e| format!("Failed to parse binary: {e}"))?;

    let mut cpuid_patches = Vec::new();
    let mut syscall_patches = Vec::new();
    let mut sysenter_patches = Vec::new();
    let mut int80_patches = Vec::new();

    // Scan executable sections
    for sect in obj.sections() {
        if sect.kind() != SectionKind::Text {
            continue;
        }

        let name = sect.name().unwrap_or("<unnamed>");

        if let Some((off, size)) = sect.file_range() {
            let start = off as usize;
            let end = (off + size) as usize;

            debug!("Scanning section '{}' [{:#x}..{:#x}]", name, start, end);

            // Search for prohibited instruction patterns
            for i in start..end.saturating_sub(1) {
                // CPUID: 0F A2
                if patched_binary[i] == 0x0F && patched_binary[i + 1] == 0xA2 {
                    debug!("Found CPUID at offset {:#x}", i);
                    cpuid_patches.push(i);
                }
                // SYSCALL: 0F 05
                else if patched_binary[i] == 0x0F && patched_binary[i + 1] == 0x05 {
                    debug!("Found SYSCALL at offset {:#x}", i);
                    syscall_patches.push(i);
                }
                // SYSENTER: 0F 34
                else if patched_binary[i] == 0x0F && patched_binary[i + 1] == 0x34 {
                    debug!("Found SYSENTER at offset {:#x}", i);
                    sysenter_patches.push(i);
                }
                // INT 0x80: CD 80
                else if patched_binary[i] == 0xCD && patched_binary[i + 1] == 0x80 {
                    debug!("Found INT 0x80 at offset {:#x}", i);
                    int80_patches.push(i);
                }
            }
        }
    }

    info!("Found instructions to patch:");
    info!("  CPUID: {}", cpuid_patches.len());
    info!("  SYSCALL: {}", syscall_patches.len());
    info!("  SYSENTER: {}", sysenter_patches.len());
    info!("  INT 0x80: {}", int80_patches.len());

    // Apply patches
    for &i in &cpuid_patches {
        patched_binary[i] = 0xCC; // INT3
        patched_binary[i + 1] = INST_ID_CPUID; // Identifier
        debug!("Patched CPUID at {:#x} -> INT3 + 0x01", i);
    }

    for &i in &syscall_patches {
        patched_binary[i] = 0xCC; // INT3
        patched_binary[i + 1] = INST_ID_SYSCALL; // Identifier
        debug!("Patched SYSCALL at {:#x} -> INT3 + 0x02", i);
    }

    for &i in &sysenter_patches {
        patched_binary[i] = 0xCC; // INT3
        patched_binary[i + 1] = INST_ID_SYSENTER; // Identifier
        debug!("Patched SYSENTER at {:#x} -> INT3 + 0x03", i);
    }

    for &i in &int80_patches {
        patched_binary[i] = 0xCC; // INT3
        patched_binary[i + 1] = INST_ID_INT80; // Identifier
        debug!("Patched INT 0x80 at {:#x} -> INT3 + 0x04", i);
    }

    info!("Patching completed");
    Ok(patched_binary)
}

// Helper function to write log messages to stderr
fn log_to_stderr(msg: &str) {
    unsafe {
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
    }
}

// SIGTRAP handler for INT3 traps
extern "C" fn sigtrap_chain_handler(
    sig: libc::c_int,
    info: *mut siginfo_t,
    context: *mut libc::c_void,
) {
    // Extract RIP from context
    let rip = unsafe {
        let uc = context as *mut libc::ucontext_t;
        let gregs = &(*uc).uc_mcontext.gregs;
        gregs[libc::REG_RIP as usize]
    };

    log_to_stderr(&format!(
        "[SGX-URTS TRAP] SIGTRAP handler called at RIP {rip:#x}\n"
    ));

    // INT3 advances RIP by 1, so check RIP-1
    let instruction_ptr = (rip - 1) as *const u8;

    // Check if it's INT3 (0xCC)
    let instruction = unsafe { *instruction_ptr };
    if instruction == 0xCC {
        // INT3 detected, read identifier byte
        let identifier = unsafe { *(rip as *const u8) };
        let instruction_name = match identifier {
            INST_ID_CPUID => "CPUID",
            INST_ID_SYSCALL => "SYSCALL",
            INST_ID_SYSENTER => "SYSENTER",
            INST_ID_INT80 => "INT 0x80",
            _ => "UNKNOWN",
        };

        log_to_stderr(&format!(
            "[SGX-URTS TRAP] Prohibited instruction detected: {instruction_name} (identifier: {identifier:#x})\n"
        ));

        // Skip identifier byte
        unsafe {
            let uc = context as *mut libc::ucontext_t;
            let gregs = &mut (*uc).uc_mcontext.gregs;
            gregs[libc::REG_RIP as usize] += 1;
        }
    } else {
        log_to_stderr(&format!(
            "[SGX-URTS TRAP] Non-INT3 instruction at RIP-1: {instruction:#x}\n"
        ));
    }

    // Call user callback if set
    if let Ok(guard) = HANDLER_CONFIG.lock() {
        if let Some(ref config) = *guard {
            if let Some(callback) = config.callback {
                callback(sig, info, context);
            }

            // Delegate to original handler if chaining is enabled
            if config.chain {
                delegate_to_original_handler(sig, info, context);
            }
        }
    }
}

// Helper to delegate to original handler
fn delegate_to_original_handler(
    sig: libc::c_int,
    info: *mut siginfo_t,
    context: *mut libc::c_void,
) {
    log_to_stderr("[SGX-URTS TRAP] Delegating to original handler\n");

    if let Ok(guard) = ORIGINAL_SIGTRAP_HANDLER.lock() {
        if let Some(ref original_handler) = *guard {
            if original_handler.sa_flags & SA_SIGINFO as libc::c_int != 0
                && original_handler.sa_sigaction != 0
            {
                log_to_stderr(&format!(
                    "[SGX-URTS TRAP] Calling original handler at {:p}\n",
                    original_handler.sa_sigaction as *const ()
                ));
                unsafe {
                    let handler: extern "C" fn(libc::c_int, *mut siginfo_t, *mut libc::c_void) =
                        mem::transmute(original_handler.sa_sigaction);
                    handler(sig, info, context);
                }
            }
        }
    }
}

/// Install SIGTRAP handler with optional chaining and callback
///
/// # Arguments
/// * `chain` - If true, calls the original handler after processing. If false, handles the signal exclusively.
/// * `callback` - Optional user-defined callback to be called after processing the signal.
pub fn install_sigtrap_handler(
    chain: bool,
    callback: Option<SigtrapCallback>,
) -> Result<(), String> {
    // Get current SIGTRAP handler
    let mut current_handler: sigaction = unsafe { mem::zeroed() };
    unsafe {
        if sigaction(SIGTRAP, ptr::null(), &mut current_handler) != 0 {
            return Err("Failed to get current SIGTRAP handler".to_string());
        }
    }

    // Save existing handler
    if current_handler.sa_sigaction != 0 {
        if let Ok(mut guard) = ORIGINAL_SIGTRAP_HANDLER.lock() {
            *guard = Some(current_handler);
            debug!(
                "Saved original SIGTRAP handler at {:p}",
                current_handler.sa_sigaction as *const ()
            );
        } else {
            return Err("Failed to lock ORIGINAL_SIGTRAP_HANDLER".to_string());
        }
    }

    // Install our handler
    let mut sa: sigaction = unsafe { mem::zeroed() };
    sa.sa_sigaction = sigtrap_chain_handler as usize;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;
    unsafe {
        libc::sigemptyset(&mut sa.sa_mask);

        if sigaction(SIGTRAP, &sa, ptr::null_mut()) != 0 {
            return Err("Failed to install SIGTRAP handler".to_string());
        }
    }

    // Set handler configuration
    if let Ok(mut guard) = HANDLER_CONFIG.lock() {
        *guard = Some(HandlerConfig { chain, callback });
    } else {
        return Err("Failed to lock HANDLER_CONFIG".to_string());
    }

    let mode = if chain { "chaining" } else { "exclusive" };
    let callback_str = if callback.is_some() {
        " with callback"
    } else {
        ""
    };
    info!(
        "SIGTRAP handler installed successfully (mode: {}{})",
        mode, callback_str
    );
    Ok(())
}

/// Uninstall SIGTRAP handler and restore the original handler
///
/// This function restores the original SIGTRAP handler that was saved when
/// install_sigtrap_handler was called. If no original handler was saved,
/// it sets the handler to SIG_DFL.
pub fn uninstall_sigtrap_handler() -> Result<(), String> {
    // Clear handler configuration
    if let Ok(mut guard) = HANDLER_CONFIG.lock() {
        *guard = None;
    } else {
        return Err("Failed to lock HANDLER_CONFIG".to_string());
    }

    // Lock and get the original handler
    let original_handler = if let Ok(mut guard) = ORIGINAL_SIGTRAP_HANDLER.lock() {
        guard.take()
    } else {
        return Err("Failed to lock ORIGINAL_SIGTRAP_HANDLER".to_string());
    };

    // Restore the original handler or set to default
    unsafe {
        if let Some(handler) = original_handler {
            // Restore the original handler
            if sigaction(SIGTRAP, &handler, ptr::null_mut()) != 0 {
                return Err("Failed to restore original SIGTRAP handler".to_string());
            }
            debug!(
                "Restored original SIGTRAP handler at {:p}",
                handler.sa_sigaction as *const ()
            );
        } else {
            // No original handler was saved, set to default
            let mut sa: sigaction = mem::zeroed();
            sa.sa_sigaction = libc::SIG_DFL;
            sa.sa_flags = 0;
            libc::sigemptyset(&mut sa.sa_mask);

            if sigaction(SIGTRAP, &sa, ptr::null_mut()) != 0 {
                return Err("Failed to set SIGTRAP handler to default".to_string());
            }
            debug!("Set SIGTRAP handler to default (SIG_DFL)");
        }
    }

    info!("SIGTRAP handler uninstalled successfully");
    Ok(())
}

/// Patch enclave binary and create enclave with automatic prohibited instruction handling
pub fn create_enclave_with_prohibited_instruction_handling(
    enclave_file: &str,
    debug: i32,
    misc_attr: &mut sgx_misc_attribute_t,
) -> SgxResult<SgxEnclave> {
    create_enclave_with_prohibited_instruction_handling_ex(
        enclave_file,
        debug,
        misc_attr,
        true,
        None,
    )
}

/// Patch enclave binary buffer and create enclave with automatic prohibited instruction handling
pub fn create_enclave_from_buffer_with_prohibited_instruction_handling(
    enclave_buffer: &[u8],
    debug: i32,
    misc_attr: &mut sgx_misc_attribute_t,
) -> SgxResult<SgxEnclave> {
    create_enclave_from_buffer_with_prohibited_instruction_handling_ex(
        enclave_buffer,
        debug,
        misc_attr,
        true,
        None,
    )
}

/// Patch enclave binary and create enclave with automatic prohibited instruction handling (extended version)
///
/// # Arguments
/// * `enclave_file` - Path to the enclave binary file
/// * `debug` - Debug mode flag
/// * `misc_attr` - Misc attributes for enclave creation
/// * `chain` - If true, chains to the original SIGTRAP handler
/// * `callback` - Optional user-defined callback for SIGTRAP handling
pub fn create_enclave_with_prohibited_instruction_handling_ex(
    enclave_file: &str,
    debug: i32,
    misc_attr: &mut sgx_misc_attribute_t,
    chain: bool,
    callback: Option<SigtrapCallback>,
) -> SgxResult<SgxEnclave> {
    // Read enclave binary
    let binary_data =
        std::fs::read(enclave_file).map_err(|_| sgx_status_t::SGX_ERROR_INVALID_ENCLAVE)?;

    // Use the buffer version
    create_enclave_from_buffer_with_prohibited_instruction_handling_ex(
        &binary_data,
        debug,
        misc_attr,
        chain,
        callback,
    )
}

/// Patch enclave binary buffer and create enclave with automatic prohibited instruction handling (extended version)
///
/// # Arguments
/// * `enclave_buffer` - Buffer containing the enclave binary
/// * `debug` - Debug mode flag
/// * `misc_attr` - Misc attributes for enclave creation
/// * `chain` - If true, chains to the original SIGTRAP handler
/// * `callback` - Optional user-defined callback for SIGTRAP handling
pub fn create_enclave_from_buffer_with_prohibited_instruction_handling_ex(
    enclave_buffer: &[u8],
    debug: i32,
    misc_attr: &mut sgx_misc_attribute_t,
    chain: bool,
    callback: Option<SigtrapCallback>,
) -> SgxResult<SgxEnclave> {
    // Patch prohibited instructions
    let patched_binary = patch_enclave_binary(enclave_buffer)
        .map_err(|_| sgx_status_t::SGX_ERROR_INVALID_ENCLAVE)?;

    // Create enclave from patched binary
    let enclave =
        SgxEnclave::create_from_buffer(&patched_binary, debug, misc_attr, 0, &[ptr::null(); 32])?;

    // Install SIGTRAP handler with specified chaining and callback
    install_sigtrap_handler(chain, callback).map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?;

    Ok(enclave)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;

    // Global mutex to ensure signal handler tests run sequentially.
    // This prevents race conditions as signal handlers are process-wide resources
    // and tests modify shared global state (ORIGINAL_SIGTRAP_HANDLER, HANDLER_CONFIG).
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_install_and_uninstall_sigtrap_handler() {
        let _guard = TEST_MUTEX.lock().unwrap();

        // Test basic install and uninstall
        let result = install_sigtrap_handler(false, None);
        assert!(result.is_ok());

        let result = uninstall_sigtrap_handler();
        assert!(result.is_ok());

        // Test that uninstalling without installing doesn't crash
        // This should succeed but set the handler to default
        let result = uninstall_sigtrap_handler();
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_install_uninstall_cycles() {
        let _guard = TEST_MUTEX.lock().unwrap();

        // Test that we can install and uninstall the handler multiple times
        for i in 0..3 {
            let chain = i % 2 == 0;
            let result = install_sigtrap_handler(chain, None);
            assert!(result.is_ok(), "Failed to install handler on iteration {i}");

            let result = uninstall_sigtrap_handler();
            assert!(
                result.is_ok(),
                "Failed to uninstall handler on iteration {i}"
            );
        }
    }

    #[test]
    fn test_sigtrap_handler_with_callback() {
        let _guard = TEST_MUTEX.lock().unwrap();

        use std::sync::atomic::AtomicUsize;

        static CALLBACK_CALLED: AtomicUsize = AtomicUsize::new(0);

        fn test_callback(_sig: libc::c_int, _info: *mut siginfo_t, _context: *mut libc::c_void) {
            CALLBACK_CALLED.fetch_add(1, Ordering::SeqCst);
        }

        // Reset the counter
        CALLBACK_CALLED.store(0, Ordering::SeqCst);

        // Install handler with callback
        let result = install_sigtrap_handler(false, Some(test_callback));
        assert!(result.is_ok());

        // Generate a SIGTRAP signal to test the callback
        unsafe {
            libc::raise(SIGTRAP);
        }

        // Check that callback was called
        assert!(
            CALLBACK_CALLED.load(Ordering::SeqCst) > 0,
            "Callback was not called"
        );

        // Uninstall handler
        let result = uninstall_sigtrap_handler();
        assert!(result.is_ok());
    }

    #[test]
    fn test_handler_chaining() {
        let _guard = TEST_MUTEX.lock().unwrap();

        use std::sync::atomic::AtomicUsize;

        static ORIGINAL_HANDLER_CALLED: AtomicUsize = AtomicUsize::new(0);
        static OUR_HANDLER_CALLED: AtomicUsize = AtomicUsize::new(0);

        // Custom handler to be installed first
        extern "C" fn original_handler(
            sig: libc::c_int,
            _info: *mut siginfo_t,
            _context: *mut libc::c_void,
        ) {
            if sig == SIGTRAP {
                ORIGINAL_HANDLER_CALLED.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn our_callback(_sig: libc::c_int, _info: *mut siginfo_t, _context: *mut libc::c_void) {
            OUR_HANDLER_CALLED.fetch_add(1, Ordering::SeqCst);
        }

        // Reset counters
        ORIGINAL_HANDLER_CALLED.store(0, Ordering::SeqCst);
        OUR_HANDLER_CALLED.store(0, Ordering::SeqCst);

        // Install original handler
        let mut sa: sigaction = unsafe { mem::zeroed() };
        sa.sa_sigaction = original_handler as usize;
        sa.sa_flags = SA_SIGINFO;
        unsafe {
            libc::sigemptyset(&mut sa.sa_mask);
            let result = sigaction(SIGTRAP, &sa, ptr::null_mut());
            assert_eq!(result, 0, "Failed to install original handler");
        }

        // Test 1: Install our handler with chaining enabled and callback
        let result = install_sigtrap_handler(true, Some(our_callback));
        assert!(result.is_ok());

        // Generate a SIGTRAP signal
        unsafe {
            libc::raise(SIGTRAP);
        }

        // Verify that both handlers were called
        assert!(
            OUR_HANDLER_CALLED.load(Ordering::SeqCst) > 0,
            "Our callback was not called"
        );
        assert!(
            ORIGINAL_HANDLER_CALLED.load(Ordering::SeqCst) > 0,
            "Original handler was not chained"
        );

        // Reset counters
        let our_count = OUR_HANDLER_CALLED.load(Ordering::SeqCst);
        let orig_count = ORIGINAL_HANDLER_CALLED.load(Ordering::SeqCst);

        // Uninstall our handler
        let result = uninstall_sigtrap_handler();
        assert!(result.is_ok());

        // Test 2: Generate another SIGTRAP to verify original handler is restored
        unsafe {
            libc::raise(SIGTRAP);
        }

        // Verify only original handler was called this time
        assert_eq!(
            OUR_HANDLER_CALLED.load(Ordering::SeqCst),
            our_count,
            "Our handler was called after uninstall"
        );
        assert!(
            ORIGINAL_HANDLER_CALLED.load(Ordering::SeqCst) > orig_count,
            "Original handler was not restored"
        );
    }

    #[test]
    fn test_patch_enclave_binary() {
        // Minimal ELF64 binary with .text section containing prohibited instructions
        #[rustfmt::skip]
        let elf_binary = vec![
            // ELF Header (64 bytes)
            0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00,  // Magic, 64-bit, LE, v1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Padding
            0x01, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,  // ET_REL, x86-64, v1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Entry
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // PHoff
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // SHoff = 64
            0x00, 0x00, 0x00, 0x00,                          // Flags
            0x40, 0x00,                                      // EHsize = 64
            0x00, 0x00,                                      // PHentsize
            0x00, 0x00,                                      // PHnum
            0x40, 0x00,                                      // SHentsize = 64
            0x03, 0x00,                                      // SHnum = 3
            0x02, 0x00,                                      // SHstrndx = 2
            
            // Section headers at 0x40
            // [0] NULL
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            
            // [1] .text
            0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,  // Name=1, Type=PROGBITS
            0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Flags=AX
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Addr
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Offset=256
            0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Size=14
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Link, Info
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Align=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Entsize
            
            // [2] .shstrtab
            0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,  // Name=7, Type=STRTAB
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Flags
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Addr
            0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Offset=272
            0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Size=17
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Link, Info
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Align=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Entsize
            
            // .text content at 0x100
            0x90, 0x0F, 0xA2,  // NOP, CPUID
            0x90, 0x0F, 0x05,  // NOP, SYSCALL
            0x90, 0x0F, 0x34,  // NOP, SYSENTER
            0x90, 0xCD, 0x80,  // NOP, INT 0x80
            0x90, 0xC3,        // NOP, RET
            
            // .shstrtab content at 0x110
            0x00, b'.', b't', b'e', b'x', b't', 0x00,
            b'.', b's', b'h', b's', b't', b'r', b't', b'a', b'b', 0x00,
        ];

        // Call patch_enclave_binary
        let result = patch_enclave_binary(&elf_binary);
        assert!(result.is_ok(), "Failed to patch binary: {:?}", result.err());

        let patched = result.unwrap();

        // Verify patches at offset 0x100 (.text section)
        let offset = 0x100;
        assert_eq!(patched[offset], 0x90); // NOP unchanged
        assert_eq!(patched[offset + 1], 0xCC); // CPUID -> INT3
        assert_eq!(patched[offset + 2], INST_ID_CPUID); // CPUID identifier
        assert_eq!(patched[offset + 3], 0x90); // NOP unchanged
        assert_eq!(patched[offset + 4], 0xCC); // SYSCALL -> INT3
        assert_eq!(patched[offset + 5], INST_ID_SYSCALL); // SYSCALL identifier
        assert_eq!(patched[offset + 6], 0x90); // NOP unchanged
        assert_eq!(patched[offset + 7], 0xCC); // SYSENTER -> INT3
        assert_eq!(patched[offset + 8], INST_ID_SYSENTER); // SYSENTER identifier
        assert_eq!(patched[offset + 9], 0x90); // NOP unchanged
        assert_eq!(patched[offset + 10], 0xCC); // INT 0x80 -> INT3
        assert_eq!(patched[offset + 11], INST_ID_INT80); // INT 0x80 identifier
        assert_eq!(patched[offset + 12], 0x90); // NOP unchanged
        assert_eq!(patched[offset + 13], 0xC3); // RET unchanged
    }
}
