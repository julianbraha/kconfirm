// SPDX-License-Identifier: GPL-2.0-only
use std::env;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::ptr;

pub const REQUIRED_ARGUMENT: c_int = 1;

#[repr(C)]
pub struct option {
    pub name: *const c_char,
    pub has_arg: c_int,
    pub flag: *mut c_int,
    pub val: c_int,
}

#[link(name = "c")]
unsafe extern "C" {
    fn getopt_long(
        argc: c_int,
        argv: *mut *mut c_char,
        optstring: *const c_char,
        longopts: *const option,
        longindex: *mut c_int,
    ) -> c_int;

    static mut optarg: *mut c_char;
    static mut optind: c_int;
}

pub struct Getopt {
    _cstrings: Vec<CString>,
    argv: Vec<*mut c_char>,
    argc: c_int,
}

impl Getopt {
    pub fn new() -> Self {
        let raw_args: Vec<String> = env::args().collect();

        let cstrings: Vec<CString> = raw_args
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect();

        let mut argv: Vec<*mut c_char> =
            cstrings.iter().map(|s| s.as_ptr() as *mut c_char).collect();

        argv.push(ptr::null_mut());

        let argc = (argv.len() - 1) as c_int;

        Self {
            _cstrings: cstrings,
            argv,
            argc,
        }
    }

    pub fn reset(&mut self) {
        unsafe {
            optind = 1;
        }
    }

    pub fn next(
        &mut self,
        optstring: &CStr,
        longopts: &[option],
    ) -> Option<Result<(char, Option<String>), String>> {
        unsafe {
            let c = getopt_long(
                self.argc,
                self.argv.as_mut_ptr(),
                optstring.as_ptr(),
                longopts.as_ptr(),
                ptr::null_mut(),
            );

            if c == -1 {
                return None;
            }

            if c == '?' as c_int {
                return Some(Err("invalid argument".into()));
            }

            let arg = if optarg.is_null() {
                None
            } else {
                Some(CStr::from_ptr(optarg).to_string_lossy().into_owned())
            };

            Some(Ok((c as u8 as char, arg)))
        }
    }
}
