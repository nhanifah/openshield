//! Path normalization for `http.request.uri.path.normalized`.
//!
//! Backends often decode and clean a path before routing it, so a rule on
//! the raw path can be sidestepped with `/%61dmin`, `//admin`, `/./admin`
//! or `/x/../admin`. The normalized form approximates what a typical
//! backend routes on, so path rules can match on that instead.

/// Percent-decode once, turn `\` into `/`, drop NUL bytes, collapse repeated
/// slashes, resolve `.` and `..` segments, and drop a trailing slash. The
/// result always starts with `/`. Case is preserved.
pub fn normalize_path(path: &str) -> String {
    let decoded = percent_decode(path.as_bytes());
    let decoded = String::from_utf8_lossy(&decoded);

    let mut segments: Vec<&str> = Vec::new();
    for seg in decoded.split(['/', '\\']) {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }

    let mut out = String::with_capacity(path.len() + 1);
    for seg in &segments {
        out.push('/');
        out.extend(seg.chars().filter(|c| *c != '\0'));
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

fn percent_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%'
            && i + 2 < input.len()
            && let (Some(h), Some(l)) = (hex(input[i + 1]), hex(input[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_path;

    #[test]
    fn bypass_variants_normalize_to_the_same_path() {
        for p in [
            "/admin",
            "/%61dmin",
            "//admin",
            "/./admin",
            "/admin/",
            "/foo/../admin",
            "/foo/%2e%2e/admin",
            "\\admin",
            "/ad%00min",
            "/%2Fadmin",
        ] {
            assert_eq!(normalize_path(p), "/admin", "{p}");
        }
    }

    #[test]
    fn root_and_escapes_above_root() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("/../../etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn case_and_invalid_escapes_are_kept() {
        assert_eq!(normalize_path("/ADMIN"), "/ADMIN");
        assert_eq!(normalize_path("/a%zzb"), "/a%zzb");
        assert_eq!(normalize_path("/a%2"), "/a%2");
    }
}
