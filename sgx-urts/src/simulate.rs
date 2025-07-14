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
use iced_x86::{Code, Decoder, DecoderOptions};
use libc::{sigaction, siginfo_t, SA_NODEFER, SA_RESTART, SA_SIGINFO, SIGTRAP};
use object::elf::PF_X;
use object::{Object, ObjectSegment};
use sgx_types::*;
use std::mem;
use std::ptr;
use std::sync::Mutex;
use tracing::{debug, info};

// Store the original SIGTRAP handler that was installed before ours
static ORIGINAL_SIGTRAP_HANDLER: Mutex<Option<sigaction>> = Mutex::new(None);

// Instruction identifiers (lower 4 bits)
const INST_KIND_CPUID: u8 = 0x01;
const INST_KIND_SYSCALL: u8 = 0x02;
const INST_KIND_SYSENTER: u8 = 0x03;
const INST_KIND_INT80: u8 = 0x04;

// Helper function to create ID with length information
// Upper 4 bits: (length - 1), Lower 4 bits: instruction kind
const fn make_id(kind: u8, len: u8) -> u8 {
    ((len - 1) << 4) | (kind & 0x0F)
}

// Helper function to extract length from ID
const fn get_length_from_id(id: u8) -> u8 {
    (id >> 4) + 1
}

// Helper function to extract kind from ID
const fn get_kind_from_id(id: u8) -> u8 {
    id & 0x0F
}

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

    let mut total_patches = 0;
    let mut cpuid_count = 0;
    let mut syscall_count = 0;
    let mut sysenter_count = 0;
    let mut int80_count = 0;

    // Scan all executable segments (not just .text sections)
    for segment in obj.segments() {
        // Check if segment is executable
        let flags = segment.flags();
        if match flags {
            object::SegmentFlags::Elf { p_flags } => p_flags & PF_X == 0,
            object::SegmentFlags::MachO { .. } => false, // Not supported for now
            object::SegmentFlags::Coff { .. } => false,  // Not supported for now
            _ => true,                                   // Skip unknown formats
        } {
            continue;
        }

        let (file_offset, file_size) = segment.file_range();
        let segment_data = &binary_data[file_offset as usize..(file_offset + file_size) as usize];
        let segment_address = segment.address();

        debug!(
            "Scanning executable segment at file offset {:#x}, virtual address {:#x}, size {:#x}",
            file_offset, segment_address, file_size
        );

        // Create x86-64 decoder with the segment's virtual address
        let mut decoder = Decoder::with_ip(64, segment_data, segment_address, DecoderOptions::NONE);

        // Decode all instructions in the segment
        while decoder.can_decode() {
            let instruction = decoder.decode();

            // Determine if this is a prohibited instruction
            let (kind, needs_patch) = match instruction.code() {
                Code::Cpuid => (INST_KIND_CPUID, true),
                Code::Syscall => (INST_KIND_SYSCALL, true),
                Code::Sysenter => (INST_KIND_SYSENTER, true),
                // For INT 0x80, we need to check the immediate value
                Code::Int_imm8 => {
                    if instruction.immediate8() == 0x80 {
                        (INST_KIND_INT80, true)
                    } else {
                        (0, false)
                    }
                }
                _ => (0, false),
            };

            if !needs_patch {
                continue;
            }

            // Calculate file offset for this instruction
            let instruction_rva = instruction.ip() - segment_address;
            let file_position = file_offset as usize + instruction_rva as usize;
            let instruction_len = instruction.len() as u8;

            // Create ID with length information
            let id = make_id(kind, instruction_len);

            debug!(
                "Found {} at virtual address {:#x}, file offset {:#x}, length {} bytes",
                match kind {
                    INST_KIND_CPUID => "CPUID",
                    INST_KIND_SYSCALL => "SYSCALL",
                    INST_KIND_SYSENTER => "SYSENTER",
                    INST_KIND_INT80 => "INT 0x80",
                    _ => "UNKNOWN",
                },
                instruction.ip(),
                file_position,
                instruction_len
            );

            // Patch the instruction: INT3 + ID + NOPs
            patched_binary[file_position] = 0xCC; // INT3
            patched_binary[file_position + 1] = id; // ID with length info

            // Fill remaining bytes with NOPs
            for i in 2..instruction_len as usize {
                patched_binary[file_position + i] = 0x90; // NOP
            }

            // Update counters
            total_patches += 1;
            match kind {
                INST_KIND_CPUID => cpuid_count += 1,
                INST_KIND_SYSCALL => syscall_count += 1,
                INST_KIND_SYSENTER => sysenter_count += 1,
                INST_KIND_INT80 => int80_count += 1,
                _ => {}
            }
        }
    }

    info!("Patching completed. Total patches: {}", total_patches);
    info!("  CPUID: {}", cpuid_count);
    info!("  SYSCALL: {}", syscall_count);
    info!("  SYSENTER: {}", sysenter_count);
    info!("  INT 0x80: {}", int80_count);

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
        let id = unsafe { *(rip as *const u8) };

        // Extract instruction kind and length from ID
        let kind = get_kind_from_id(id);
        let length = get_length_from_id(id);

        let instruction_name = match kind {
            INST_KIND_CPUID => "CPUID",
            INST_KIND_SYSCALL => "SYSCALL",
            INST_KIND_SYSENTER => "SYSENTER",
            INST_KIND_INT80 => "INT 0x80",
            _ => "UNKNOWN",
        };

        log_to_stderr(&format!(
            "[SGX-URTS TRAP] Prohibited instruction detected: {instruction_name} (id: {id:#x}, length: {length})\n"
        ));

        // Skip the entire patched instruction (length includes INT3)
        // Since RIP already points to the ID byte (after INT3), we need to skip (length - 1) more bytes
        unsafe {
            let uc = context as *mut libc::ucontext_t;
            let gregs = &mut (*uc).uc_mcontext.gregs;
            gregs[libc::REG_RIP as usize] += (length - 1) as i64;
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
    fn test_patch_enclave_binary_basic() {
        // Create a minimal ELF with executable segment containing prohibited instructions
        let mut elf_binary = create_test_elf_with_code(&[
            0x90, // NOP
            0x0F, 0xA2, // CPUID (2 bytes)
            0x90, // NOP
            0x0F, 0x05, // SYSCALL (2 bytes)
            0x90, // NOP
            0x0F, 0x34, // SYSENTER (2 bytes)
            0x90, // NOP
            0xCD, 0x80, // INT 0x80 (2 bytes)
            0x90, // NOP
            0xC3, // RET
        ]);

        // Call patch_enclave_binary
        let result = patch_enclave_binary(&elf_binary);
        assert!(result.is_ok(), "Failed to patch binary: {:?}", result.err());

        let patched = result.unwrap();

        // Find the code section
        let code_offset = find_code_offset(&elf_binary);

        // Verify patches
        assert_eq!(patched[code_offset], 0x90); // NOP unchanged
        assert_eq!(patched[code_offset + 1], 0xCC); // CPUID -> INT3
        assert_eq!(patched[code_offset + 2], make_id(INST_KIND_CPUID, 2)); // CPUID ID with length 2
        assert_eq!(patched[code_offset + 3], 0x90); // NOP unchanged
        assert_eq!(patched[code_offset + 4], 0xCC); // SYSCALL -> INT3
        assert_eq!(patched[code_offset + 5], make_id(INST_KIND_SYSCALL, 2)); // SYSCALL ID with length 2
        assert_eq!(patched[code_offset + 6], 0x90); // NOP unchanged
        assert_eq!(patched[code_offset + 7], 0xCC); // SYSENTER -> INT3
        assert_eq!(patched[code_offset + 8], make_id(INST_KIND_SYSENTER, 2)); // SYSENTER ID with length 2
        assert_eq!(patched[code_offset + 9], 0x90); // NOP unchanged
        assert_eq!(patched[code_offset + 10], 0xCC); // INT 0x80 -> INT3
        assert_eq!(patched[code_offset + 11], make_id(INST_KIND_INT80, 2)); // INT 0x80 ID with length 2
        assert_eq!(patched[code_offset + 12], 0x90); // NOP unchanged
        assert_eq!(patched[code_offset + 13], 0xC3); // RET unchanged
    }

    #[test]
    fn test_patch_enclave_binary_with_prefixes() {
        // Test instructions with prefixes (different lengths)
        let elf_binary = create_test_elf_with_code(&[
            // REX prefix + SYSCALL (3 bytes)
            0x48, 0x0F, 0x05, // REX.W SYSCALL
            // Operand size prefix + SYSCALL (3 bytes)
            0x66, 0x0F, 0x05, // 66 SYSCALL
            // REP prefix + CPUID (3 bytes)
            0xF3, 0x0F, 0xA2, // REP CPUID
            // Multiple prefixes + SYSENTER (4 bytes)
            0x66, 0xF3, 0x0F, 0x34, // 66 REP SYSENTER
            0xC3, // RET
        ]);

        let result = patch_enclave_binary(&elf_binary);
        assert!(result.is_ok(), "Failed to patch binary: {:?}", result.err());

        let patched = result.unwrap();
        let code_offset = find_code_offset(&elf_binary);

        // Verify REX.W SYSCALL patch (3 bytes)
        assert_eq!(patched[code_offset], 0xCC); // INT3
        assert_eq!(patched[code_offset + 1], make_id(INST_KIND_SYSCALL, 3)); // ID with length 3
        assert_eq!(patched[code_offset + 2], 0x90); // NOP padding

        // Verify 66 SYSCALL patch (3 bytes)
        assert_eq!(patched[code_offset + 3], 0xCC); // INT3
        assert_eq!(patched[code_offset + 4], make_id(INST_KIND_SYSCALL, 3)); // ID with length 3
        assert_eq!(patched[code_offset + 5], 0x90); // NOP padding

        // Verify REP CPUID patch (3 bytes)
        assert_eq!(patched[code_offset + 6], 0xCC); // INT3
        assert_eq!(patched[code_offset + 7], make_id(INST_KIND_CPUID, 3)); // ID with length 3
        assert_eq!(patched[code_offset + 8], 0x90); // NOP padding

        // Verify 66 REP SYSENTER patch (4 bytes)
        assert_eq!(patched[code_offset + 9], 0xCC); // INT3
        assert_eq!(patched[code_offset + 10], make_id(INST_KIND_SYSENTER, 4)); // ID with length 4
        assert_eq!(patched[code_offset + 11], 0x90); // NOP padding
        assert_eq!(patched[code_offset + 12], 0x90); // NOP padding

        // RET unchanged
        assert_eq!(patched[code_offset + 13], 0xC3);
    }

    #[test]
    fn test_patch_enclave_binary_no_false_positives() {
        // Test that we don't patch data that looks like instructions
        let elf_binary = create_test_elf_with_mixed_sections(
            &[
                // .text section
                0x90, // NOP
                0x0F, 0xA2, // CPUID (should be patched)
                0xC3, // RET
            ],
            &[
                // .data section (non-executable)
                0x0F, 0xA2, // Data that looks like CPUID (should NOT be patched)
                0x0F, 0x05, // Data that looks like SYSCALL (should NOT be patched)
                0x0F, 0x34, // Data that looks like SYSENTER (should NOT be patched)
                0xCD, 0x80, // Data that looks like INT 0x80 (should NOT be patched)
            ],
        );

        let result = patch_enclave_binary(&elf_binary);
        assert!(result.is_ok(), "Failed to patch binary: {:?}", result.err());

        let patched = result.unwrap();
        let (text_offset, data_offset) = find_section_offsets(&elf_binary);

        // Verify .text section: CPUID should be patched
        assert_eq!(patched[text_offset], 0x90); // NOP unchanged
        assert_eq!(patched[text_offset + 1], 0xCC); // CPUID -> INT3
        assert_eq!(patched[text_offset + 2], make_id(INST_KIND_CPUID, 2)); // CPUID ID
        assert_eq!(patched[text_offset + 3], 0xC3); // RET unchanged

        // Verify .data section: nothing should be patched
        assert_eq!(patched[data_offset], 0x0F); // Data unchanged
        assert_eq!(patched[data_offset + 1], 0xA2); // Data unchanged
        assert_eq!(patched[data_offset + 2], 0x0F); // Data unchanged
        assert_eq!(patched[data_offset + 3], 0x05); // Data unchanged
        assert_eq!(patched[data_offset + 4], 0x0F); // Data unchanged
        assert_eq!(patched[data_offset + 5], 0x34); // Data unchanged
        assert_eq!(patched[data_offset + 6], 0xCD); // Data unchanged
        assert_eq!(patched[data_offset + 7], 0x80); // Data unchanged
    }

    #[test]
    fn test_patch_enclave_binary_jump_table_no_false_positive() {
        // Test that jump table entries are not mistaken for instructions
        let elf_binary = create_test_elf_with_code(&[
            // A simple function with embedded data (simulating a jump table)
            0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, // MOV RAX, [RIP+0]
            0xFF, 0xE0, // JMP RAX
            // Data that looks like prohibited instructions but is actually jump addresses
            0x05, 0x0F, 0x00, 0x00, // Address that starts with 0x05, 0x0F (not SYSCALL)
            0xA2, 0x0F, 0x00, 0x00, // Address that starts with 0xA2, 0x0F (not CPUID)
            // Real prohibited instruction after the data
            0x0F, 0xA2, // CPUID (should be patched)
            0xC3, // RET
        ]);

        let result = patch_enclave_binary(&elf_binary);
        assert!(result.is_ok(), "Failed to patch binary: {:?}", result.err());

        let patched = result.unwrap();
        let code_offset = find_code_offset(&elf_binary);

        // Verify that the jump table data is not patched
        assert_eq!(patched[code_offset + 9], 0x05); // Data unchanged
        assert_eq!(patched[code_offset + 10], 0x0F); // Data unchanged
        assert_eq!(patched[code_offset + 13], 0xA2); // Data unchanged
        assert_eq!(patched[code_offset + 14], 0x0F); // Data unchanged

        // Verify that the real CPUID instruction is patched
        assert_eq!(patched[code_offset + 17], 0xCC); // CPUID -> INT3
        assert_eq!(patched[code_offset + 18], make_id(INST_KIND_CPUID, 2)); // CPUID ID
    }

    #[test]
    fn test_id_format() {
        // Test ID encoding and decoding
        for len in 1u8..=15u8 {
            for kind in [
                INST_KIND_CPUID,
                INST_KIND_SYSCALL,
                INST_KIND_SYSENTER,
                INST_KIND_INT80,
            ] {
                let id = make_id(kind, len);
                assert_eq!(
                    get_kind_from_id(id),
                    kind,
                    "Kind mismatch for len={len}, kind={kind}"
                );
                assert_eq!(
                    get_length_from_id(id),
                    len,
                    "Length mismatch for len={len}, kind={kind}"
                );
            }
        }
    }

    // Helper functions for tests
    fn create_test_elf_with_code(code: &[u8]) -> Vec<u8> {
        create_test_elf_with_mixed_sections(code, &[])
    }

    fn create_test_elf_with_mixed_sections(text_content: &[u8], data_content: &[u8]) -> Vec<u8> {
        // This creates a minimal ELF with proper program headers and sections
        // The actual implementation would create a valid ELF structure
        // For brevity, using a simplified version here
        let total_size = 0x3000 + text_content.len().max(data_content.len());
        let mut elf = vec![0u8; total_size]; // Allocate space

        // ELF header
        elf[0..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00]);
        elf[0x10] = 0x02; // ET_EXEC
        elf[0x12] = 0x3e; // EM_X86_64
        elf[0x14] = 0x01; // EV_CURRENT

        // Program header offset
        elf[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());

        // e_phentsize (size of program header entry)
        elf[0x36..0x38].copy_from_slice(&0x38u16.to_le_bytes());

        // e_phnum (number of program headers)
        let phnum = if data_content.is_empty() { 1u16 } else { 2u16 };
        elf[0x38..0x3A].copy_from_slice(&phnum.to_le_bytes());

        // Program header for executable segment at offset 0x40
        elf[0x40] = 0x01; // PT_LOAD
        elf[0x44] = 0x05; // PF_X | PF_R (executable)
        elf[0x48..0x50].copy_from_slice(&0x1000u64.to_le_bytes()); // offset
        elf[0x50..0x58].copy_from_slice(&0x1000u64.to_le_bytes()); // vaddr
        elf[0x60..0x68].copy_from_slice(&(text_content.len() as u64).to_le_bytes()); // filesz
        elf[0x68..0x70].copy_from_slice(&(text_content.len() as u64).to_le_bytes()); // memsz

        // Copy text content
        elf[0x1000..0x1000 + text_content.len()].copy_from_slice(text_content);

        if !data_content.is_empty() {
            // Program header for data segment at offset 0x80
            elf[0x80] = 0x01; // PT_LOAD
            elf[0x84] = 0x06; // PF_R | PF_W (not executable)
            elf[0x88..0x90].copy_from_slice(&0x2000u64.to_le_bytes()); // offset
            elf[0x90..0x98].copy_from_slice(&0x2000u64.to_le_bytes()); // vaddr
            elf[0xA0..0xA8].copy_from_slice(&(data_content.len() as u64).to_le_bytes()); // filesz
            elf[0xA8..0xB0].copy_from_slice(&(data_content.len() as u64).to_le_bytes()); // memsz

            // Copy data content
            elf[0x2000..0x2000 + data_content.len()].copy_from_slice(data_content);
        }

        elf
    }

    fn find_code_offset(elf: &[u8]) -> usize {
        // For our test ELF, code starts at 0x1000
        0x1000
    }

    fn find_section_offsets(elf: &[u8]) -> (usize, usize) {
        // For our test ELF, text at 0x1000, data at 0x2000
        (0x1000, 0x2000)
    }
}
