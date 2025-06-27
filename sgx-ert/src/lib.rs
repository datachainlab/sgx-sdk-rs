#![no_std]
#![allow(internal_features)]
#![feature(rustc_private)]
#![feature(lang_items)]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::sync::atomic::{AtomicPtr, Ordering};
use core::{mem, ptr};

pub use alloc::alloc::*;
pub use sgx_alloc::System;

/// re-export
pub use sgx_types;

/// global allocator and panic handler for enclave
///
/// This is a fork of the `sgx_no_tstd` crate, with the following change:
/// - The `begin_panic_handler` function is added to logging the panic message before aborting.
#[global_allocator]
static ALLOC: sgx_alloc::System = sgx_alloc::System;

#[cfg(feature = "panic-handler")]
#[allow(unused_variables)]
#[panic_handler]
fn begin_panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    sgx_abort();
}

#[lang = "eh_personality"]
fn rust_eh_personality() {}

static HOOK: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

/// Registers a custom allocation error hook, replacing any that was previously registered.
///
/// The allocation error hook is invoked when an infallible memory allocation fails, before
/// the runtime aborts. The default hook prints a message to standard error,
/// but this behavior can be customized with the [`set_alloc_error_hook`] and
/// [`take_alloc_error_hook`] functions.
///
/// The hook is provided with a `Layout` struct which contains information
/// about the allocation that failed.
///
/// The allocation error hook is a global resource.
pub fn set_alloc_error_hook(hook: fn(Layout)) {
    HOOK.store(hook as *mut (), Ordering::SeqCst);
}

/// Unregisters the current allocation error hook, returning it.
///
/// *See also the function [`set_alloc_error_hook`].*
///
/// If no custom hook is registered, the default hook will be returned.
pub fn take_alloc_error_hook() -> fn(Layout) {
    let hook = HOOK.swap(ptr::null_mut(), Ordering::SeqCst);
    if hook.is_null() {
        default_alloc_error_hook
    } else {
        unsafe { mem::transmute::<*mut (), fn(Layout)>(hook) }
    }
}

fn default_alloc_error_hook(_layout: Layout) {}

#[alloc_error_handler]
pub fn rust_oom(layout: Layout) -> ! {
    let hook = HOOK.load(Ordering::SeqCst);
    let hook: fn(Layout) = if hook.is_null() {
        default_alloc_error_hook
    } else {
        unsafe { mem::transmute::<*mut (), fn(Layout)>(hook) }
    };
    hook(layout);
    sgx_abort();
}

fn sgx_abort() -> ! {
    unsafe { sgx_types::abort() }
}
