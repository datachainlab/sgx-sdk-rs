#![no_std]
#![crate_name = "enclave"]
#![crate_type = "staticlib"]

extern crate alloc;
extern crate sgx_ert;

use alloc::format;
use alloc::slice;
use alloc::string::String;
use sgx_types::*;

/// Sample ecall function that corresponds to the EDL definition
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn ecall_sample(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_max_len: usize,
    output_len: *mut usize,
) -> sgx_status_t {
    // Validate output_len pointer
    if output_len.is_null() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    // Convert input to string
    let input_slice = unsafe { slice::from_raw_parts(input, input_len) };
    let input_string = match String::from_utf8(input_slice.to_vec()) {
        Ok(s) => s,
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    let result = match input_string.as_str() {
        "cpuid" => {
            let id = unsafe {
                use core::arch::x86_64::__cpuid;
                __cpuid(0)
            };
            format!("Executed CPUID: {id:?}")
        }
        "syscall" => {
            unsafe {
                core::arch::asm!("syscall", options(nostack, preserves_flags));
            }
            String::from("Executed SYSCALL")
        }
        "sysenter" => {
            unsafe {
                core::arch::asm!("sysenter", options(nostack, preserves_flags));
            }
            String::from("Executed SYSENTER")
        }
        "int80" => {
            unsafe {
                core::arch::asm!("int 0x80", options(nostack, preserves_flags));
            }
            String::from("Executed INT 0x80")
        }
        _ => {
            // normal execution
            format!("Hello from enclave: {input_string}")
        }
    };

    let result_bytes = result.as_bytes();

    // Check if output buffer is large enough
    if result_bytes.len() > output_max_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    // Copy result to output buffer
    let output_slice = unsafe { slice::from_raw_parts_mut(output, output_max_len) };
    output_slice[..result_bytes.len()].copy_from_slice(result_bytes);

    // Set the actual output length
    unsafe {
        *output_len = result_bytes.len();
    }

    sgx_status_t::SGX_SUCCESS
}
