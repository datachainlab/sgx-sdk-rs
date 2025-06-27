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

#![no_std]
#![crate_name = "unittestsampleenclave"]
#![crate_type = "staticlib"]

extern crate alloc;
extern crate sgx_ert;

use sgx_types::*;

// Simple print functions for no_std environment
use core::fmt;

extern "C" {
    fn ocall_print_string(str_ptr: *const u8, str_len: usize) -> sgx_status_t;
}

struct Print;

impl fmt::Write for Print {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        unsafe {
            ocall_print_string(s.as_ptr(), s.len());
        }
        Ok(())
    }
}

fn print(args: fmt::Arguments) {
    use fmt::Write;
    let _ = Print.write_fmt(args);
}

macro_rules! print {
    ($($arg:tt)*) => {
        print(format_args!($($arg)*))
    };
}

macro_rules! println {
    () => { print!("\n") };
    ($($arg:tt)*) => {
        print!("{}\n", format_args!($($arg)*))
    };
}

mod utils;

mod test_crypto;
use test_crypto::*;

pub mod test_rts;
use test_rts::*;

mod test_seal;
use test_seal::*;

mod test_types;
use test_types::*;

mod test_crate;
use test_crate::*;

// Simple test result type
type TestResult = Result<(), &'static str>;

#[no_mangle]
pub extern "C" fn test_main_entrance() -> size_t {
    // Run tests that are supported by our crates
    let mut passed = 0;
    let mut failed = 0;

    // tcrypto tests
    print!("test_rsgx_sha256_slice ... ");
    match test_rsgx_sha256_slice() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    print!("test_rsgx_sha256_handle ... ");
    match test_rsgx_sha256_handle() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    // rts tests
    print!("test_rsgx_get_thread_policy ... ");
    match test_rsgx_get_thread_policy() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    print!("test_read_rand ... ");
    match test_read_rand() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    print!("test_data_is_within_enclave ... ");
    match test_data_is_within_enclave() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    print!("test_slice_is_within_enclave ... ");
    match test_slice_is_within_enclave() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    print!("test_raw_is_within_enclave ... ");
    match test_raw_is_within_enclave() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    print!("test_data_is_outside_enclave ... ");
    match test_data_is_outside_enclave() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    print!("test_slice_is_outside_enclave ... ");
    match test_slice_is_outside_enclave() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    print!("test_raw_is_outside_enclave ... ");
    match test_raw_is_outside_enclave() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    // tseal tests
    print!("test_seal_unseal ... ");
    match test_seal_unseal() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    print!("test_mac_aadata_slice ... ");
    match test_mac_aadata_slice() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    // types tests
    print!("check_metadata_size ... ");
    match check_metadata_size() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    print!("check_version ... ");
    match check_version() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    print!("test_sha2_crate ... ");
    match test_sha2_crate() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    print!("test_rand_crate ... ");
    match test_rand_crate() {
        Ok(_) => {
            println!("ok");
            passed += 1;
        }
        Err(e) => {
            println!("failed: {:?}", e);
            failed += 1;
        }
    }

    println!("\ntest result: ok. {} passed; {} failed", passed, failed);

    passed
}
