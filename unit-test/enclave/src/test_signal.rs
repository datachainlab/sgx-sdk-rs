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

use crate::{print, TestResult};

// Test CPUID instruction execution and trapping
pub fn test_cpuid_trap() -> TestResult {
    // This test only works in simulation mode where instructions are patched
    #[cfg(not(sgx_sim))]
    {
        // In HW mode, CPUID would cause an exception, so we skip this test
        return Ok(());
    }

    #[cfg(sgx_sim)]
    {
        // In simulation mode, CPUID should be patched to UD2 and handled by our trap handler
        unsafe {
            use core::arch::x86_64::__cpuid;
            __cpuid(0)
        };
        // If we reach here, the trap handler successfully handled the UD2
        println!("CPUID trap test: Successfully trapped and continued execution");
        Ok(())
    }
}

// Test SYSCALL instruction execution and trapping
pub fn test_syscall_trap() -> TestResult {
    #[cfg(not(sgx_sim))]
    {
        return Ok(());
    }

    #[cfg(sgx_sim)]
    {
        // Execute SYSCALL instruction
        unsafe {
            core::arch::asm!("syscall", options(nostack, preserves_flags));
        }
        // If we reach here, the trap handler successfully handled the UD2
        println!("SYSCALL trap test: Successfully trapped and continued execution");

        Ok(())
    }
}

// Test SYSENTER instruction execution and trapping
pub fn test_sysenter_trap() -> TestResult {
    #[cfg(not(sgx_sim))]
    {
        return Ok(());
    }

    #[cfg(sgx_sim)]
    {
        // Execute SYSENTER instruction
        unsafe {
            core::arch::asm!("sysenter", options(nostack, preserves_flags));
        }
        // If we reach here, the trap handler successfully handled the UD2
        println!("SYSENTER trap test: Successfully trapped and continued execution");
        Ok(())
    }
}

// Test INT 0x80 instruction execution and trapping
pub fn test_int80_trap() -> TestResult {
    #[cfg(not(sgx_sim))]
    {
        return Ok(());
    }

    #[cfg(sgx_sim)]
    {
        // Execute INT 0x80 instruction
        unsafe {
            core::arch::asm!("int 0x80", options(nostack, preserves_flags));
        }
        // If we reach here, the trap handler successfully handled the UD2
        println!("INT 0x80 trap test: Successfully trapped and continued execution");
        Ok(())
    }
}
