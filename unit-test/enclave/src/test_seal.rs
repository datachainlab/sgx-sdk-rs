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
use sgx_trts::trts::*;
use sgx_tseal::*;
use sgx_types::marker::*;
use sgx_types::*;

fn to_sealed_log<T: Copy + ContiguousMemory>(
    sealed_data: &SgxSealedData<T>,
    sealed_log: *mut u8,
    sealed_log_size: u32,
) -> Option<*mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as *mut sgx_sealed_data_t, sealed_log_size)
    }
}

fn from_sealed_log<'a, T: Copy + ContiguousMemory>(
    sealed_log: *mut u8,
    sealed_log_size: u32,
) -> Option<SgxSealedData<'a, T>> {
    unsafe {
        SgxSealedData::<T>::from_raw_sealed_data_t(
            sealed_log as *mut sgx_sealed_data_t,
            sealed_log_size,
        )
    }
}

pub fn test_seal_unseal() -> TestResult {
    #[derive(Copy, Clone, Default, Debug)]
    struct RandData {
        key: u32,
        rand: [u8; 16],
    }

    unsafe impl ContiguousMemory for RandData {}

    let mut data = RandData::default();
    data.key = 0x1234;

    // Use sgx random instead of StdRng
    rsgx_read_rand(&mut data.rand).map_err(|_| "Failed to generate random data")?;

    let aad: [u8; 0] = [0_u8; 0];
    let sealed_data =
        SgxSealedData::<RandData>::seal_data(&aad, &data).map_err(|_| "Failed to seal data")?;

    let mut sealed_log_arr: [u8; 2048] = [0; 2048];
    let sealed_log = sealed_log_arr.as_mut_ptr();
    let sealed_log_size: u32 = 2048;
    let opt = to_sealed_log(&sealed_data, sealed_log, sealed_log_size);
    if opt.is_none() {
        return Err("Failed to convert to sealed log");
    }

    let sealed_data = from_sealed_log::<RandData>(sealed_log, sealed_log_size)
        .ok_or("Failed to read from sealed log")?;
    let unsealed_data = sealed_data
        .unseal_data()
        .map_err(|_| "Failed to unseal data")?;
    let udata = unsealed_data.get_decrypt_txt();

    if data.key != udata.key {
        return Err("Key mismatch after unseal");
    }
    if data.rand != udata.rand {
        return Err("Random data mismatch after unseal");
    }

    Ok(())
}

pub fn test_mac_aadata_slice() -> TestResult {
    // Test with MAC for additional authenticated data
    let aad_data: [u8; 16] = [0; 16];
    let text: [u8; 16] = [1; 16];

    // Use SgxSealedData with additional authenticated data
    let sealed_data = SgxSealedData::<[u8; 16]>::seal_data(&aad_data, &text)
        .map_err(|_| "Failed to create sealed data with AAD")?;

    // Verify by unsealing
    let unsealed_data = sealed_data
        .unseal_data()
        .map_err(|_| "Failed to unseal data")?;

    // Check both encrypted text and AAD match
    if unsealed_data.get_decrypt_txt() != &text {
        return Err("Decrypted text verification failed");
    }
    if unsealed_data.get_additional_txt() != &aad_data {
        return Err("AAD verification failed");
    }

    Ok(())
}
