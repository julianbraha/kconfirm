// SPDX-License-Identifier: GPL-2.0-only

use libc::c_char;
use libc::c_int;
use libc::c_long;
use libc::c_void;
use std::ffi::CStr;
use std::ffi::CString;
use std::sync::OnceLock;

#[derive(PartialEq, Debug)]
pub enum LinkStatus {
    Ok,
    ProbablyBlocked,
    Redirected(String),
    NotFound,
    ServerError,
    Unreachable(String),
    UnsupportedScheme(String),
}

static CURL_INIT: OnceLock<()> = OnceLock::new();

#[repr(C)]
pub struct CURL {
    _private: [u8; 0],
}

type CURLcode = c_int;
type CURLoption = u32;
type CURLINFO = u32;

const CURLE_OK: CURLcode = 0;

const CURL_GLOBAL_DEFAULT: c_long = 3;

const CURLOPT_URL: CURLoption = 10002;
const CURLOPT_NOBODY: CURLoption = 44;
const CURLOPT_TIMEOUT: CURLoption = 13;
const CURLOPT_FOLLOWLOCATION: CURLoption = 52;
const CURLOPT_USERAGENT: CURLoption = 10018;
const CURLOPT_HEADERFUNCTION: CURLoption = 20079;
const CURLOPT_HEADERDATA: CURLoption = 10029;

const CURLINFO_RESPONSE_CODE: CURLINFO = 0x200002;

#[link(name = "curl")]
unsafe extern "C" {}

unsafe extern "C" {
    fn curl_global_init(flags: c_long) -> CURLcode;

    fn curl_easy_init() -> *mut CURL;

    fn curl_easy_cleanup(handle: *mut CURL);

    fn curl_easy_perform(handle: *mut CURL) -> CURLcode;

    fn curl_easy_strerror(code: CURLcode) -> *const c_char;

    fn curl_easy_setopt(handle: *mut CURL, option: CURLoption, ...) -> CURLcode;

    fn curl_easy_getinfo(handle: *mut CURL, info: CURLINFO, ...) -> CURLcode;
}

fn init_curl() {
    CURL_INIT.get_or_init(|| unsafe {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    });
}

struct HeaderCapture {
    location: Option<String>,
}

extern "C" fn header_callback(
    buffer: *mut c_char,
    size: usize,
    nitems: usize,
    userdata: *mut c_void,
) -> usize {
    let total = size * nitems;

    unsafe {
        let bytes = std::slice::from_raw_parts(buffer as *const u8, total);

        if let Ok(header) = std::str::from_utf8(bytes) {
            let lower = header.to_ascii_lowercase();

            if lower.starts_with("location:") {
                if let Some((_, value)) = header.split_once(':') {
                    let capture = &mut *(userdata as *mut HeaderCapture);

                    capture.location = Some(value.trim().to_string());
                }
            }
        }
    }

    total
}

fn curl_error(code: CURLcode) -> String {
    unsafe {
        let ptr = curl_easy_strerror(code);

        if ptr.is_null() {
            return format!("curl error {}", code);
        }

        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

pub fn check_link(url: &str) -> LinkStatus {
    if let Some(scheme) = url.split("://").next() {
        match scheme {
            "http" | "https" => return check_http(url),

            "git" | "ftp" => {
                return LinkStatus::UnsupportedScheme(scheme.into());
            }

            _ => {
                return LinkStatus::UnsupportedScheme(scheme.into());
            }
        }
    }

    LinkStatus::Unreachable("invalid URL".into())
}

fn check_http(url: &str) -> LinkStatus {
    init_curl();

    unsafe {
        let curl = curl_easy_init();

        if curl.is_null() {
            return LinkStatus::Unreachable("curl_easy_init failed".into());
        }

        let url_c = match CString::new(url) {
            Ok(v) => v,
            Err(_) => {
                curl_easy_cleanup(curl);

                return LinkStatus::Unreachable("invalid URL".into());
            }
        };

        let ua_c = CString::new("link-checker/1.0").unwrap();

        let mut headers = HeaderCapture { location: None };

        macro_rules! setopt {
            ($opt:expr, $val:expr) => {{
                let rc = curl_easy_setopt(curl, $opt, $val);

                if rc != CURLE_OK {
                    curl_easy_cleanup(curl);

                    return LinkStatus::Unreachable(curl_error(rc));
                }
            }};
        }

        setopt!(CURLOPT_URL, url_c.as_ptr());
        setopt!(CURLOPT_NOBODY, 1 as c_long);
        setopt!(CURLOPT_TIMEOUT, 10 as c_long);
        setopt!(CURLOPT_FOLLOWLOCATION, 0 as c_long);
        setopt!(CURLOPT_USERAGENT, ua_c.as_ptr());

        setopt!(
            CURLOPT_HEADERFUNCTION,
            header_callback as extern "C" fn(_, _, _, _) -> _
        );

        setopt!(CURLOPT_HEADERDATA, &mut headers as *mut _ as *mut c_void);

        let rc = curl_easy_perform(curl);

        if rc != CURLE_OK {
            curl_easy_cleanup(curl);

            return LinkStatus::Unreachable(curl_error(rc));
        }

        let mut response_code: c_long = 0;

        let rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &mut response_code);

        if rc != CURLE_OK {
            curl_easy_cleanup(curl);

            return LinkStatus::Unreachable(curl_error(rc));
        }

        curl_easy_cleanup(curl);

        match response_code {
            200..=299 => LinkStatus::Ok,

            301 | 302 => {
                LinkStatus::Redirected(headers.location.unwrap_or_else(|| "unknown".into()))
            }

            403 | 429 => LinkStatus::ProbablyBlocked,

            404 => LinkStatus::NotFound,

            500..=599 => LinkStatus::ServerError,

            _ => LinkStatus::ProbablyBlocked,
        }
    }
}

pub fn find_links(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();

    let mut links = Vec::new();

    let mut i = 0;

    while i + 3 < bytes.len() {
        if bytes[i] == b':' && bytes[i + 1] == b'/' && bytes[i + 2] == b'/' {
            let mut start = i;

            while start > 0 {
                let c = bytes[start - 1];

                let valid = c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.';

                if !valid {
                    break;
                }

                start -= 1;
            }

            if start == i {
                i += 3;

                continue;
            }

            let scheme_first = bytes[start];

            if !scheme_first.is_ascii_alphabetic() {
                i += 3;

                continue;
            }

            let mut end = i + 3;

            while end < bytes.len() {
                let c = bytes[end];

                let stop = c.is_ascii_whitespace()
                    || matches!(c, b')' | b']' | b'}' | b'"' | b'\'' | b'<' | b'>');

                if stop {
                    break;
                }

                end += 1;
            }

            let mut url = &text[start..end];

            url = url.trim_end_matches(&['.', ',', ';', ':', '!', '?'][..]);

            links.push(url.to_string());

            i = end;
        } else {
            i += 1;
        }
    }

    links
}
