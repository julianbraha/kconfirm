// SPDX-License-Identifier: GPL-2.0-only

use curl::easy::Easy;
use regex::Regex;
use std::sync::OnceLock;
use std::time::Duration;

/*
 * during testing, "Unreachable" and "ServerError" seem to be a 50/50
 * as to whether or not they're actually dead links
 */
#[derive(PartialEq, Debug)]
pub enum LinkStatus {
    Ok,                        // 2xx, definitely alive
    ProbablyBlocked,           // 403, 429, or cloudflare-style response
    Redirected(String),        // 301/302, redirection, consider updating the link
    NotFound,                  // 404, probably dead
    ServerError,               // 5xx, might be temporary
    Unreachable(String),       // connection failed, timeout, DNS error etc.
    UnsupportedScheme(String), // e.g. ftp, git
}

static CURL_INIT: OnceLock<()> = OnceLock::new();

fn init_curl() {
    CURL_INIT.get_or_init(|| {
        curl::init();
    });
}

pub fn check_link(url: &str) -> LinkStatus {
    if let Some(scheme) = url.split("://").next() {
        match scheme {
            "http" | "https" => return check_http(url),
            "git" | "ftp" | _ => return LinkStatus::UnsupportedScheme(scheme.into()),
        }
    }

    LinkStatus::Unreachable("invalid URL".into())
}

fn check_http(url: &str) -> LinkStatus {
    init_curl();

    let mut easy = Easy::new();

    if let Err(e) = easy.url(url) {
        return LinkStatus::Unreachable(e.to_string());
    }

    // HEAD request
    if let Err(e) = easy.nobody(true) {
        return LinkStatus::Unreachable(e.to_string());
    }

    // 10 second timeout
    if let Err(e) = easy.timeout(Duration::from_secs(10)) {
        return LinkStatus::Unreachable(e.to_string());
    }

    // disable redirects so we can report them
    if let Err(e) = easy.follow_location(false) {
        return LinkStatus::Unreachable(e.to_string());
    }

    // optional: set a user agent
    let _ = easy.useragent("link-checker/1.0");

    let mut location_header: Option<String> = None;

    {
        let mut transfer = easy.transfer();

        // capture headers
        if let Err(e) = transfer.header_function(|header| {
            if let Ok(s) = std::str::from_utf8(header) {
                let lower = s.to_ascii_lowercase();

                if lower.starts_with("location:") {
                    if let Some((_, value)) = s.split_once(':') {
                        location_header = Some(value.trim().to_string());
                    }
                }
            }

            true
        }) {
            return LinkStatus::Unreachable(e.to_string());
        }

        if let Err(e) = transfer.perform() {
            return LinkStatus::Unreachable(e.to_string());
        }
    }

    let status = match easy.response_code() {
        Ok(code) => code,
        Err(e) => return LinkStatus::Unreachable(e.to_string()),
    };

    match status {
        200..=299 => LinkStatus::Ok,

        301 | 302 => LinkStatus::Redirected(location_header.unwrap_or_else(|| "unknown".into())),

        403 | 429 => LinkStatus::ProbablyBlocked,

        404 => LinkStatus::NotFound,

        500..=599 => LinkStatus::ServerError,

        _ => LinkStatus::ProbablyBlocked,
    }
}

pub fn find_links(text: &str) -> Vec<String> {
    let re = Regex::new(r#"[a-zA-Z][a-zA-Z0-9+\-.]*://[^\s\)\]\}\"'<>]+"#).unwrap();

    re.find_iter(text).map(|m| m.as_str().to_string()).collect()
}
