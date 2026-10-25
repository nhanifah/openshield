use std::time::{SystemTime, UNIX_EPOCH};

use wirefilter_engine::{ExecutionContext, LhsValue, Scheme};

use super::{get_header, parse_form_urlencoded, set_field, split_pairs};
use crate::waf::data::RequestData;

fn parse_cookies(cookie_header: &str) -> Vec<(String, String)> {
    cookie::Cookie::split_parse(cookie_header)
        .filter_map(|c| c.ok())
        .map(|c| (c.name().to_string(), c.value().to_string()))
        .collect()
}

fn parse_accept_language(header: &str) -> Vec<String> {
    header
        .split(',')
        .map(|lang| lang.split(';').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn request_fields(ctx: &mut ExecutionContext<'static>, scheme: &Scheme, req: &RequestData) {
    if let Some(ip) = req.client_ip {
        set_field!(ctx, scheme, "ip.src", Ip, ip);
    }

    if let Some(ref g) = req.geo {
        if let Some(v) = g.asn {
            set_field!(ctx, scheme, "ip.src.asnum", Int, v);
        }
        if let Some(ref v) = g.city {
            set_field!(ctx, scheme, "ip.src.city", Str, v);
        }
        if let Some(ref v) = g.continent {
            set_field!(ctx, scheme, "ip.src.continent", Str, v);
        }
        if let Some(ref v) = g.country {
            set_field!(ctx, scheme, "ip.src.country", Str, v);
        }
        set_field!(
            ctx,
            scheme,
            "ip.src.is_in_european_union",
            Bool,
            g.is_in_european_union
        );
        if let Some(ref v) = g.postal_code {
            set_field!(ctx, scheme, "ip.src.postal_code", Str, v);
        }
        if let Some(ref v) = g.region {
            set_field!(ctx, scheme, "ip.src.region", Str, v);
        }
        if let Some(ref v) = g.region_code {
            set_field!(ctx, scheme, "ip.src.region_code", Str, v);
        }
        if let Some(ref v) = g.timezone {
            set_field!(ctx, scheme, "ip.src.timezone.name", Str, v);
        }
        if let Some(v) = g.metro_code {
            set_field!(ctx, scheme, "ip.src.metro_code", Str, &v.to_string());
        }
        if let Some(v) = g.lat {
            set_field!(ctx, scheme, "ip.src.lat", Str, &format!("{v}"));
        }
        if let Some(v) = g.lon {
            set_field!(ctx, scheme, "ip.src.lon", Str, &format!("{v}"));
        }
    }

    set_field!(ctx, scheme, "ssl", Bool, req.is_tls);

    set_field!(
        ctx,
        scheme,
        "http.request.method",
        Bytes,
        req.method.as_bytes()
    );
    set_field!(
        ctx,
        scheme,
        "http.request.version",
        Bytes,
        req.version.as_bytes()
    );

    if let Ok(dur) = SystemTime::now().duration_since(UNIX_EPOCH) {
        set_field!(
            ctx,
            scheme,
            "http.request.timestamp.sec",
            Int,
            dur.as_secs()
        );
        set_field!(
            ctx,
            scheme,
            "http.request.timestamp.msec",
            Int,
            dur.subsec_millis()
        );
    }

    if let Some(v) = get_header(&req.headers, "host") {
        set_field!(ctx, scheme, "http.host", Str, v);
    } else if !req.host.is_empty() {
        set_field!(ctx, scheme, "http.host", Str, &req.host);
    }

    if let Some(v) = get_header(&req.headers, "user-agent") {
        set_field!(ctx, scheme, "http.user_agent", Str, v);
    }
    if let Some(v) = get_header(&req.headers, "referer") {
        set_field!(ctx, scheme, "http.referer", Str, v);
    }
    if let Some(v) = get_header(&req.headers, "cookie") {
        set_field!(ctx, scheme, "http.cookie", Str, v);
    }
    if let Some(v) = get_header(&req.headers, "x-forwarded-for") {
        set_field!(ctx, scheme, "http.x_forwarded_for", Str, v);
    }

    let (header_names, header_values) = split_pairs(&req.headers);
    set_field!(
        ctx,
        scheme,
        "http.request.headers",
        MapArr,
        req.headers.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    );
    set_field!(ctx, scheme, "http.request.headers.names", Arr, header_names);
    set_field!(
        ctx,
        scheme,
        "http.request.headers.values",
        Arr,
        header_values
    );

    if let Some(v) = get_header(&req.headers, "cookie") {
        let cookies = parse_cookies(v);
        let (cookie_names, cookie_values) = split_pairs(&cookies);
        set_field!(ctx, scheme, "http.request.cookies", MapArr, cookies);
        set_field!(ctx, scheme, "http.request.cookies.names", Arr, cookie_names);
        set_field!(
            ctx,
            scheme,
            "http.request.cookies.values",
            Arr,
            cookie_values
        );
    }

    if let Some(v) = get_header(&req.headers, "accept-language") {
        set_field!(
            ctx,
            scheme,
            "http.request.accepted_languages",
            Arr,
            parse_accept_language(v)
        );
    }

    set_field!(
        ctx,
        scheme,
        "http.request.full_uri",
        Bytes,
        req.full_uri.as_bytes()
    );
    set_field!(ctx, scheme, "http.request.uri", Str, &req.uri);
    set_field!(
        ctx,
        scheme,
        "http.request.uri.path",
        Bytes,
        req.path.as_bytes()
    );
    set_field!(
        ctx,
        scheme,
        "http.request.uri.path.normalized",
        Bytes,
        crate::waf::normalize::normalize_path(&req.path).as_bytes()
    );
    set_field!(
        ctx,
        scheme,
        "http.request.uri.path.extension",
        Bytes,
        req.extension.as_bytes()
    );
    set_field!(
        ctx,
        scheme,
        "http.request.uri.query",
        Bytes,
        req.query.as_bytes()
    );

    if !req.query.is_empty() {
        let args = parse_form_urlencoded(req.query.as_bytes());
        let (names, values) = split_pairs(&args);
        set_field!(ctx, scheme, "http.request.uri.args", MapArr, args);
        set_field!(ctx, scheme, "http.request.uri.args.names", Arr, names);
        set_field!(ctx, scheme, "http.request.uri.args.values", Arr, values);
    }

    if let Some(v) = get_header(&req.headers, "content-type") {
        set_field!(ctx, scheme, "http.request.body.mime", Str, v);
    }
}

#[cfg(test)]
mod tests {
    use wirefilter_engine::{ExecutionContext, Scheme};

    use super::request_fields;
    use crate::waf::data::RequestData;
    use crate::waf::populate::test_support::{check, context, empty_request, scheme};

    fn populate(req: &RequestData) -> (Scheme, ExecutionContext<'static>) {
        let scheme = scheme();
        let mut ctx = context(&scheme);
        request_fields(&mut ctx, &scheme, req);
        (scheme, ctx)
    }

    #[test]
    fn host_from_header_case_insensitive() {
        let mut req = empty_request();
        req.headers.push(("HOST".into(), "example.com".into()));
        let (scheme, ctx) = populate(&req);
        assert!(check(&scheme, &ctx, r#"http.host == "example.com""#));
    }

    #[test]
    fn host_falls_back_to_host_field() {
        let mut req = empty_request();
        req.host = "fallback.com".into();
        let (scheme, ctx) = populate(&req);
        assert!(check(&scheme, &ctx, r#"http.host == "fallback.com""#));
    }

    #[test]
    fn method_and_tls_flag() {
        let mut req = empty_request();
        req.method = "GET".into();
        req.is_tls = true;
        let (scheme, ctx) = populate(&req);
        assert!(check(&scheme, &ctx, r#"http.request.method == "GET""#));
        assert!(check(&scheme, &ctx, "ssl"));
    }

    #[test]
    fn query_string_parsed_into_args() {
        let mut req = empty_request();
        req.query = "a=1&b=two".into();
        let (scheme, ctx) = populate(&req);
        assert!(check(
            &scheme,
            &ctx,
            r#"any(http.request.uri.args.names[*] == "a")"#
        ));
        assert!(check(
            &scheme,
            &ctx,
            r#"any(http.request.uri.args.values[*] == "two")"#
        ));
    }

    #[test]
    fn cookies_parsed() {
        let mut req = empty_request();
        req.headers
            .push(("Cookie".into(), "sid=abc; theme=dark".into()));
        let (scheme, ctx) = populate(&req);
        assert!(check(
            &scheme,
            &ctx,
            r#"any(http.request.cookies.names[*] == "sid")"#
        ));
        assert!(check(
            &scheme,
            &ctx,
            r#"any(http.request.cookies.values[*] == "dark")"#
        ));
    }

    #[test]
    fn header_arrays_and_named_fields() {
        let mut req = empty_request();
        req.headers.push(("User-Agent".into(), "curl/8.0".into()));
        req.headers.push(("X-Test".into(), "val".into()));
        let (scheme, ctx) = populate(&req);
        assert!(check(&scheme, &ctx, r#"http.user_agent == "curl/8.0""#));
        assert!(check(
            &scheme,
            &ctx,
            r#"any(http.request.headers.names[*] == "X-Test")"#
        ));
        assert!(check(
            &scheme,
            &ctx,
            r#"any(http.request.headers.values[*] == "val")"#
        ));
    }

    #[test]
    fn accept_language_parsed_dropping_qvalues() {
        let mut req = empty_request();
        req.headers
            .push(("Accept-Language".into(), "en-US,en;q=0.9,fr".into()));
        let (scheme, ctx) = populate(&req);
        assert!(check(
            &scheme,
            &ctx,
            r#"any(http.request.accepted_languages[*] == "en-US")"#
        ));
        assert!(check(
            &scheme,
            &ctx,
            r#"any(http.request.accepted_languages[*] == "fr")"#
        ));
    }

    #[test]
    fn content_type_sets_mime() {
        let mut req = empty_request();
        req.headers
            .push(("Content-Type".into(), "application/json".into()));
        let (scheme, ctx) = populate(&req);
        assert!(check(
            &scheme,
            &ctx,
            r#"http.request.body.mime == "application/json""#
        ));
    }

    #[test]
    fn eu_flag_follows_geo_data() {
        use crate::waf::data::GeoData;
        let geo = |country: &str, eu: bool| GeoData {
            asn: None,
            is_in_european_union: eu,
            city: None,
            continent: None,
            country: Some(country.into()),
            lat: None,
            lon: None,
            metro_code: None,
            postal_code: None,
            region: None,
            region_code: None,
            timezone: None,
        };

        let mut req = empty_request();
        req.geo = Some(geo("FR", true));
        let (scheme, ctx) = populate(&req);
        assert!(check(&scheme, &ctx, "ip.src.is_in_european_union"));
        assert!(check(
            &scheme,
            &ctx,
            r#"ip.src.country == "FR" and ip.src.is_in_european_union"#
        ));

        req.geo = Some(geo("GB", false));
        let (scheme, ctx) = populate(&req);
        assert!(check(&scheme, &ctx, "not ip.src.is_in_european_union"));
    }
}
