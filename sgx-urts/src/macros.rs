/// Define an ocall function that only has a real implementation on Linux.
/// On non-Linux targets, sets `*error = ENOSYS` and returns `-1`.
///
/// # Example
///
/// ```ignore
/// linux_only_ocall! {
///     pub extern "C" fn u_epoll_create1_ocall(error: *mut c_int, flags: c_int) -> c_int {
///         let mut errno = 0;
///         let ret = unsafe { libc::epoll_create1(flags) };
///         if ret < 0 {
///             errno = Error::last_os_error().raw_os_error().unwrap_or(0);
///         }
///         if !error.is_null() {
///             unsafe {
///                 *error = errno;
///             }
///         }
///         ret
///     }
/// }
/// ```
macro_rules! linux_only_ocall {
    (
        pub extern "C" fn $name:ident(
            $error:ident: *mut c_int
            $(, $param:ident: $ty:ty)* $(,)?
        ) -> $ret:ty
            $linux_body:block
    ) => {
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
        #[no_mangle]
        pub extern "C" fn $name($error: *mut c_int $(, $param: $ty)*) -> $ret {
            #[cfg(target_os = "linux")]
            $linux_body

            #[cfg(not(target_os = "linux"))]
            {
                if !$error.is_null() {
                    unsafe {
                        *$error = libc::ENOSYS;
                    }
                }
                return -1;
            }
        }
    };
}
