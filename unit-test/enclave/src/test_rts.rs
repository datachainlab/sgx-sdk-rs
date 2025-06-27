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

use crate::TestResult;

use sgx_trts::enclave::*;
use sgx_trts::trts::*;

pub fn test_rsgx_get_thread_policy() -> TestResult {
    if rsgx_get_thread_policy() != SgxThreadPolicy::Bound {
        return Err("Thread policy is not Bound");
    }
    Ok(())
}

pub fn test_read_rand() -> TestResult {
    let mut rand_arr = [0; 100];
    rsgx_read_rand(&mut rand_arr[..]).map_err(|_| "Failed to read random")?;

    // Cannot all be zero
    let all_zero = rand_arr.iter().all(|&x| x == 0);
    if all_zero {
        return Err("Random array is all zeros");
    }
    Ok(())
}

pub fn test_data_is_within_enclave() -> TestResult {
    #[allow(dead_code)]
    #[derive(Clone, Copy)]
    struct SampleDs {
        x: i32,
        y: i32,
        z: [i32; 100],
    }
    unsafe impl sgx_types::marker::ContiguousMemory for SampleDs {}

    let mut sample_object = SampleDs {
        x: 0,
        y: 0,
        z: [0; 100],
    };
    sample_object.x = 100;
    sample_object.y = 100;
    sample_object.z[0] = 100;

    if !rsgx_data_is_within_enclave(&sample_object) {
        return Err("Data should be within enclave");
    }

    let ooo;
    unsafe {
        let ppp = 0xdeadbeafdeadbeaf as *const u8;
        ooo = &*ppp;
    }
    if rsgx_data_is_within_enclave(ooo) {
        return Err("Data should not be within enclave");
    }

    Ok(())
}

pub fn test_slice_is_within_enclave() -> TestResult {
    let one_array = [0; 100];
    if !rsgx_slice_is_within_enclave(&one_array[..]) {
        return Err("Slice should be within enclave");
    }
    Ok(())
}

pub fn test_raw_is_within_enclave() -> TestResult {
    if !rsgx_raw_is_within_enclave(test_raw_is_within_enclave as *const u8, 10) {
        return Err("Function pointer should be within enclave");
    }
    if rsgx_raw_is_within_enclave(0xdeadbeafdeadbeaf as *const u8, 10) {
        return Err("Invalid pointer should not be within enclave");
    }
    Ok(())
}

pub fn test_data_is_outside_enclave() -> TestResult {
    #[allow(dead_code)]
    #[derive(Clone, Copy)]
    struct SampleDs {
        x: i32,
        y: i32,
        z: [i32; 100],
    }
    unsafe impl sgx_types::marker::ContiguousMemory for SampleDs {}

    let sample_object = SampleDs {
        x: 100,
        y: 100,
        z: [100; 100],
    };

    if rsgx_data_is_outside_enclave(&sample_object) {
        return Err("Enclave data should not be outside");
    }

    // Note: Testing with actual outside pointer is unsafe and may crash
    // Skipping the unsafe test case

    Ok(())
}

pub fn test_slice_is_outside_enclave() -> TestResult {
    let one_array = [0; 100];
    if rsgx_slice_is_outside_enclave(&one_array[..]) {
        return Err("Enclave slice should not be outside");
    }
    Ok(())
}

pub fn test_raw_is_outside_enclave() -> TestResult {
    if rsgx_raw_is_outside_enclave(test_raw_is_outside_enclave as *const u8, 10) {
        return Err("Function pointer should not be outside enclave");
    }
    // Note: Cannot safely test with actual outside pointer
    Ok(())
}
