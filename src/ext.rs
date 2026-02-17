use windows::{
    Win32::Foundation::*, Win32::System::Diagnostics::Debug::*, core::*,
};


#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn GetThreadContext(hthread: HANDLE, lpcontext: *mut CONTEXT) -> i32;
    pub fn SetThreadContext(hthread: HANDLE, lpcontext: *const CONTEXT) -> i32;
    pub fn LoadLibraryA(lplibfilename: *const u8) -> isize;
    pub fn GetProcAddress(hmodule: isize, lpprocname: *const u8) -> *const std::ffi::c_void;
}