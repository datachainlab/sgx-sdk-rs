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

static ENCLAVE_FILE: &str = "enclave.signed.so";

extern "C" {
    fn ecall_sample(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        input: *const u8,
        input_len: usize,
        output: *mut u8,
        output_max_len: usize,
        output_len: *mut usize,
    ) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

fn main() {
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

    let input_string = String::from("Hello, world!");
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut output_buffer = vec![0u8; 256]; // Allocate buffer for output
    let mut output_len: usize = 0; // Variable to receive actual output length

    let result = unsafe {
        ecall_sample(
            enclave.geteid(),
            &mut retval,
            input_string.as_ptr(),
            input_string.len(),
            output_buffer.as_mut_ptr(),
            output_buffer.len(),
            &mut output_len,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }

    // Check if the ecall itself returned an error
    if retval != sgx_status_t::SGX_SUCCESS {
        println!("[-] ECALL returned error: {}!", retval.as_str());
        return;
    }

    // Use the actual output length returned by the enclave
    let output_string = String::from_utf8_lossy(&output_buffer[..output_len]);

    println!("[+] ecall_sample success...");
    println!("[+] Enclave returned: {output_string}");
    enclave.destroy();
}
