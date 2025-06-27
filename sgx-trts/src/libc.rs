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

//! Minimal libc implementation for SGX enclaves

use core::sync::atomic::{AtomicI32, Ordering};

// Error handling
static ERRNO: AtomicI32 = AtomicI32::new(0);

pub fn errno() -> i32 {
    ERRNO.load(Ordering::Relaxed)
}

pub fn set_errno(e: i32) {
    ERRNO.store(e, Ordering::Relaxed);
}

pub fn error_string(errno: i32) -> &'static str {
    match errno {
        0 => "Success",
        1 => "Operation not permitted",
        2 => "No such file or directory",
        12 => "Cannot allocate memory",
        22 => "Invalid argument",
        _ => "Unknown error",
    }
}

// Memory search functions
pub unsafe fn memchr(s: *const u8, c: u8, n: usize) -> *const u8 {
    if s.is_null() || n == 0 {
        return core::ptr::null();
    }

    let slice = core::slice::from_raw_parts(s, n);
    for (i, &byte) in slice.iter().enumerate() {
        if byte == c {
            return s.add(i);
        }
    }
    core::ptr::null()
}

pub unsafe fn memrchr(s: *const u8, c: u8, n: usize) -> *const u8 {
    if s.is_null() || n == 0 {
        return core::ptr::null();
    }

    let slice = core::slice::from_raw_parts(s, n);
    for (i, &byte) in slice.iter().enumerate().rev() {
        if byte == c {
            return s.add(i);
        }
    }
    core::ptr::null()
}

// Process control
pub type exit_function_t = unsafe extern "C" fn();

// Dummy implementation - SGX enclaves don't support atexit
pub unsafe fn atexit(_func: exit_function_t) -> i32 {
    -1 // Return error
}

pub unsafe fn abort() -> ! {
    // In SGX, we trigger an illegal instruction to abort
    core::arch::asm!("ud2");
    core::hint::unreachable_unchecked()
}

// Re-export commonly used C types
pub use sgx_types::*;
