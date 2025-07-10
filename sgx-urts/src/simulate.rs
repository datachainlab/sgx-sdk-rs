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
use object::elf::PF_X;
use object::{Object, ObjectSegment};
use sgx_types::*;
use std::ptr;
use tracing::{debug, info};

/// Patch prohibited instructions in enclave binary
pub fn patch_enclave_binary(binary_data: &[u8]) -> Result<Vec<u8>, String> {
    info!("Loading and patching enclave binary");

    // Create a mutable copy
    let mut patched_binary = binary_data.to_vec();

    // Parse the binary
    let obj =
        object::File::parse(binary_data).map_err(|e| format!("Failed to parse binary: {e}"))?;

    // Check if this is an ELF binary - only ELF is supported for now
    let format = obj.format();
    if format != object::BinaryFormat::Elf {
        return Err(format!(
            "Unsupported binary format: {format:?}. Only ELF binaries are supported for patching.",
        ));
    }

    let mut total_patches = 0;
    let mut cpuid_count = 0;
    let mut syscall_count = 0;
    let mut sysenter_count = 0;
    let mut int80_count = 0;

    // Scan all executable segments
    for segment in obj.segments() {
        // Check if segment is executable
        let flags = segment.flags();
        if match flags {
            object::SegmentFlags::Elf { p_flags } => p_flags & PF_X == 0,
            _ => {
                // This should not happen as we already checked for ELF format
                debug!("Unexpected segment flags type in ELF binary");
                true
            }
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
            let needs_patch = match instruction.code() {
                Code::Cpuid => true,
                Code::Syscall => true,
                Code::Sysenter => true,
                // For INT 0x80, we need to check the immediate value
                Code::Int_imm8 => instruction.immediate8() == 0x80,
                _ => false,
            };

            if !needs_patch {
                continue;
            }

            // Calculate file offset for this instruction
            let instruction_rva = instruction.ip() - segment_address;
            let file_position = file_offset as usize + instruction_rva as usize;
            let instruction_len = instruction.len() as u8;

            debug!(
                "Found {} at virtual address {:#x}, file offset {:#x}, length {} bytes",
                match instruction.code() {
                    Code::Cpuid => "CPUID",
                    Code::Syscall => "SYSCALL",
                    Code::Sysenter => "SYSENTER",
                    Code::Int_imm8 if instruction.immediate8() == 0x80 => "INT 0x80",
                    _ => "UNKNOWN",
                },
                instruction.ip(),
                file_position,
                instruction_len
            );

            // Patch the instruction: UD2 + NOPs
            patched_binary[file_position] = 0x0F; // UD2 first byte
            patched_binary[file_position + 1] = 0x0B; // UD2 second byte

            // Fill remaining bytes with NOPs
            for i in 2..instruction_len as usize {
                patched_binary[file_position + i] = 0x90; // NOP
            }

            // Update counters
            total_patches += 1;
            match instruction.code() {
                Code::Cpuid => cpuid_count += 1,
                Code::Syscall => syscall_count += 1,
                Code::Sysenter => sysenter_count += 1,
                Code::Int_imm8 if instruction.immediate8() == 0x80 => int80_count += 1,
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

/// Create an enclave from a file with prohibited instructions patched to UD2
pub fn create_patched_enclave(
    enclave_file: &str,
    debug: i32,
    misc_attr: &mut sgx_misc_attribute_t,
) -> SgxResult<SgxEnclave> {
    // Read enclave binary
    let binary_data =
        std::fs::read(enclave_file).map_err(|_| sgx_status_t::SGX_ERROR_INVALID_ENCLAVE)?;

    // Use the buffer version
    create_patched_enclave_from_buffer(&binary_data, debug, misc_attr)
}

/// Create an enclave from a buffer with prohibited instructions patched to UD2
pub fn create_patched_enclave_from_buffer(
    enclave_buffer: &[u8],
    debug: i32,
    misc_attr: &mut sgx_misc_attribute_t,
) -> SgxResult<SgxEnclave> {
    // Patch prohibited instructions
    let patched_binary = patch_enclave_binary(enclave_buffer)
        .map_err(|_| sgx_status_t::SGX_ERROR_INVALID_ENCLAVE)?;

    // Create enclave from patched binary
    SgxEnclave::create_from_buffer(&patched_binary, debug, misc_attr, 0, &[ptr::null(); 32])
}

#[cfg(test)]
mod tests {
    use super::*;

    // Constants for test ELF layout
    const TEST_ELF_TEXT_OFFSET: usize = 0x1000;
    const TEST_ELF_DATA_OFFSET: usize = 0x2000;

    #[test]
    fn test_patch_enclave_binary_basic() {
        // Create a minimal ELF with executable segment containing prohibited instructions
        let elf_binary = create_test_elf_with_code(&[
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
        let code_offset = TEST_ELF_TEXT_OFFSET;

        // Verify patches
        assert_eq!(patched[code_offset], 0x90); // NOP unchanged
        assert_eq!(patched[code_offset + 1], 0x0F); // CPUID -> UD2 first byte
        assert_eq!(patched[code_offset + 2], 0x0B); // CPUID -> UD2 second byte
        assert_eq!(patched[code_offset + 3], 0x90); // NOP unchanged
        assert_eq!(patched[code_offset + 4], 0x0F); // SYSCALL -> UD2 first byte
        assert_eq!(patched[code_offset + 5], 0x0B); // SYSCALL -> UD2 second byte
        assert_eq!(patched[code_offset + 6], 0x90); // NOP unchanged
        assert_eq!(patched[code_offset + 7], 0x0F); // SYSENTER -> UD2 first byte
        assert_eq!(patched[code_offset + 8], 0x0B); // SYSENTER -> UD2 second byte
        assert_eq!(patched[code_offset + 9], 0x90); // NOP unchanged
        assert_eq!(patched[code_offset + 10], 0x0F); // INT 0x80 -> UD2 first byte
        assert_eq!(patched[code_offset + 11], 0x0B); // INT 0x80 -> UD2 second byte
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
        let code_offset = TEST_ELF_TEXT_OFFSET;

        // Verify REX.W SYSCALL patch (3 bytes)
        assert_eq!(patched[code_offset], 0x0F); // UD2 first byte
        assert_eq!(patched[code_offset + 1], 0x0B); // UD2 second byte
        assert_eq!(patched[code_offset + 2], 0x90); // NOP padding

        // Verify 66 SYSCALL patch (3 bytes)
        assert_eq!(patched[code_offset + 3], 0x0F); // UD2 first byte
        assert_eq!(patched[code_offset + 4], 0x0B); // UD2 second byte
        assert_eq!(patched[code_offset + 5], 0x90); // NOP padding

        // Verify REP CPUID patch (3 bytes)
        assert_eq!(patched[code_offset + 6], 0x0F); // UD2 first byte
        assert_eq!(patched[code_offset + 7], 0x0B); // UD2 second byte
        assert_eq!(patched[code_offset + 8], 0x90); // NOP padding

        // Verify 66 REP SYSENTER patch (4 bytes)
        assert_eq!(patched[code_offset + 9], 0x0F); // UD2 first byte
        assert_eq!(patched[code_offset + 10], 0x0B); // UD2 second byte
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
        let text_offset = TEST_ELF_TEXT_OFFSET;
        let data_offset = TEST_ELF_DATA_OFFSET;

        // Verify .text section: CPUID should be patched
        assert_eq!(patched[text_offset], 0x90); // NOP unchanged
        assert_eq!(patched[text_offset + 1], 0x0F); // CPUID -> UD2 first byte
        assert_eq!(patched[text_offset + 2], 0x0B); // CPUID -> UD2 second byte
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
        let code_offset = TEST_ELF_TEXT_OFFSET;

        // Verify that the jump table data is not patched
        assert_eq!(patched[code_offset + 9], 0x05); // Data unchanged
        assert_eq!(patched[code_offset + 10], 0x0F); // Data unchanged
        assert_eq!(patched[code_offset + 13], 0xA2); // Data unchanged
        assert_eq!(patched[code_offset + 14], 0x0F); // Data unchanged

        // Verify that the real CPUID instruction is patched
        assert_eq!(patched[code_offset + 17], 0x0F); // CPUID -> UD2 first byte
        assert_eq!(patched[code_offset + 18], 0x0B); // CPUID -> UD2 second byte
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
        elf[0x10] = 0x03; // ET_DYN
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
        elf[0x48..0x50].copy_from_slice(&(TEST_ELF_TEXT_OFFSET as u64).to_le_bytes()); // offset
        elf[0x50..0x58].copy_from_slice(&(TEST_ELF_TEXT_OFFSET as u64).to_le_bytes()); // vaddr
        elf[0x60..0x68].copy_from_slice(&(text_content.len() as u64).to_le_bytes()); // filesz
        elf[0x68..0x70].copy_from_slice(&(text_content.len() as u64).to_le_bytes()); // memsz

        // Copy text content
        elf[TEST_ELF_TEXT_OFFSET..TEST_ELF_TEXT_OFFSET + text_content.len()]
            .copy_from_slice(text_content);

        if !data_content.is_empty() {
            // Program header for data segment at offset 0x80
            elf[0x80] = 0x01; // PT_LOAD
            elf[0x84] = 0x06; // PF_R | PF_W (not executable)
            elf[0x88..0x90].copy_from_slice(&(TEST_ELF_DATA_OFFSET as u64).to_le_bytes()); // offset
            elf[0x90..0x98].copy_from_slice(&(TEST_ELF_DATA_OFFSET as u64).to_le_bytes()); // vaddr
            elf[0xA0..0xA8].copy_from_slice(&(data_content.len() as u64).to_le_bytes()); // filesz
            elf[0xA8..0xB0].copy_from_slice(&(data_content.len() as u64).to_le_bytes()); // memsz

            // Copy data content
            elf[TEST_ELF_DATA_OFFSET..TEST_ELF_DATA_OFFSET + data_content.len()]
                .copy_from_slice(data_content);
        }

        elf
    }
}
