// SPDX-License-Identifier: GPL-2.0-only
use regex::Regex;
use reqwest::blocking::Client;
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
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    match client.head(url).send() {
        Ok(response) => match response.status().as_u16() {
            200..=299 => LinkStatus::Ok,
            301 | 302 => {
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("unknown")
                    .to_string();
                LinkStatus::Redirected(location)
            }
            403 | 429 => LinkStatus::ProbablyBlocked,
            404 => LinkStatus::NotFound,
            500..=599 => LinkStatus::ServerError,
            _ => LinkStatus::ProbablyBlocked,
        },
        Err(e) => LinkStatus::Unreachable(e.to_string()),
    }
}

pub fn find_links(text: &str) -> Vec<String> {
    let re = Regex::new(r#"[a-zA-Z][a-zA-Z0-9+\-.]*://[^\s\)\]\}\"'<>]+"#).unwrap();

    re.find_iter(text).map(|m| m.as_str().to_string()).collect()
}
