use crate::TestResult;
use sgx_types::metadata::*;
use sgx_types::*;

use core::mem;

pub fn check_metadata_size() -> TestResult {
    if mem::size_of::<layout_group_t>() != 32 {
        return Err("layout_group_t size mismatch");
    }
    if mem::size_of::<layout_entry_t>() != 32 {
        return Err("layout_entry_t size mismatch");
    }
    if mem::size_of::<layout_t>() != 32 {
        return Err("layout_t size mismatch");
    }
    if mem::size_of::<css_header_t>() != 128 {
        return Err("css_header_t size mismatch");
    }
    if mem::size_of::<css_key_t>() != 772 {
        return Err("css_key_t size mismatch");
    }
    if mem::size_of::<css_body_t>() != 128 {
        return Err("css_body_t size mismatch");
    }
    if mem::size_of::<css_buffer_t>() != 780 {
        return Err("css_buffer_t size mismatch");
    }
    if mem::size_of::<enclave_css_t>() != 1808 {
        return Err("enclave_css_t size mismatch");
    }
    if mem::size_of::<metadata_t>() != METADATA_SIZE {
        return Err("metadata_t size mismatch");
    }
    Ok(())
}

pub fn check_version() -> TestResult {
    //https://github.com/intel/linux-sgx/blob/master/common/inc/internal/metadata.h#L41
    let curr_version = 0x0000000300000000;
    if meta_data_make_version!(MAJOR_VERSION, MINOR_VERSION) != curr_version {
        return Err("Version mismatch");
    }
    if major_version_of_metadata!(curr_version) != MAJOR_VERSION as u64 {
        return Err("Major version mismatch");
    }
    if minor_version_of_metadata!(curr_version) != MINOR_VERSION as u64 {
        return Err("Minor version mismatch");
    }
    Ok(())
}
