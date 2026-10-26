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
    set_field!(ctx, scheme, "ip.src.allowlisted", Bool, req.allowlisted);
    let geo = req.geo.as_ref();
    set_field!(ctx, scheme, "ip.src.has_country", Bool, geo.is_some_and(|g| g.country.is_some()));
    set_field!(ctx, scheme, "ip.src.has_asnum", Bool, geo.is_some_and(|g| g.asn.is_some()));

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
            is_in_european_union: eu,
            country: Some(country.into()),
            ..Default::default()
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

    #[test]
    fn geo_rules_match_as_intended() {
        use crate::config::{Action, GeoMode, GeoRule};
        use crate::waf::data::GeoData;
        let rule = |mode: GeoMode, countries: &[&str], regions: &[&str], asns: &[u32]| GeoRule {
            id: "t".into(),
            description: None,
            enabled: true,
            mode,
            action: Action::Block,
            countries: countries.iter().map(|s| s.to_string()).collect(),
            regions: regions.iter().map(|s| s.to_string()).collect(),
            asns: asns.to_vec(),
        };
        // `region` is a code ("JK"), or a name when prefixed with "=" ("=Jakarta").
        let at = |country: Option<&str>, region: Option<&str>, asn: Option<u32>, allowlisted: bool| {
            let mut req = empty_request();
            req.allowlisted = allowlisted;
            if country.is_some() || asn.is_some() {
                let (code, name) = match region {
                    Some(r) if r.starts_with('=') => (None, Some(r[1..].to_string())),
                    Some(r) => (Some(r.to_string()), None),
                    None => (None, None),
                };
                req.geo = Some(GeoData {
                    country: country.map(String::from),
                    region_code: code,
                    region: name,
                    asn,
                    ..Default::default()
                });
            }
            req
        };
        // The expression and `matches` (used for impact estimates) agree.
        let hit = |r: &GeoRule, req: &RequestData| {
            let (scheme, ctx) = populate(req);
            let by_expr = check(&scheme, &ctx, &r.expression());
            if !req.allowlisted {
                let g = req.geo.as_ref();
                let country = g.and_then(|g| g.country.clone());
                let region = g.and_then(|g| crate::geoip::region_key(g.country.as_deref(), g.region_code.as_deref(), g.region.as_deref()));
                let by_fn = r.matches(country.as_deref(), region.as_deref(), g.and_then(|g| g.asn));
                assert_eq!(by_expr, by_fn, "expression and matches() disagree for {:?}", req.geo);
            }
            by_expr
        };

        let deny_cn = rule(GeoMode::Deny, &["CN"], &[], &[]);
        assert!(hit(&deny_cn, &at(Some("CN"), None, None, false)));
        assert!(!hit(&deny_cn, &at(Some("ID"), None, None, false)));
        assert!(!hit(&deny_cn, &at(None, None, None, false)), "unknown location is not blocked");
        assert!(!hit(&deny_cn, &at(Some("CN"), None, None, true)), "IP allows win");

        let only_id = rule(GeoMode::AllowOnly, &["ID"], &[], &[]);
        assert!(!hit(&only_id, &at(Some("ID"), None, None, false)));
        assert!(hit(&only_id, &at(Some("US"), None, None, false)));
        assert!(!hit(&only_id, &at(None, None, None, false)), "private or unknown addresses pass");
        assert!(!hit(&only_id, &at(Some("US"), None, None, true)));

        let jakarta = rule(GeoMode::Deny, &[], &["ID-JK"], &[]);
        assert!(hit(&jakarta, &at(Some("ID"), Some("JK"), None, false)));
        assert!(!hit(&jakarta, &at(Some("ID"), Some("JB"), None, false)));
        assert!(!hit(&jakarta, &at(Some("MY"), Some("JK"), None, false)));

        let by_name = rule(GeoMode::Deny, &[], &["ID:Jakarta"], &[]);
        assert!(hit(&by_name, &at(Some("ID"), Some("=Jakarta"), None, false)));
        assert!(!hit(&by_name, &at(Some("ID"), Some("=Bali"), None, false)));
        assert!(!hit(&by_name, &at(Some("MY"), Some("=Jakarta"), None, false)));

        let asn = rule(GeoMode::Deny, &[], &[], &[64500]);
        assert!(hit(&asn, &at(Some("US"), None, Some(64500), false)));
        assert!(!hit(&asn, &at(Some("US"), None, Some(64501), false)));
        let only_asn = rule(GeoMode::AllowOnly, &[], &[], &[64500]);
        assert!(hit(&only_asn, &at(None, None, Some(64501), false)));
        assert!(!hit(&only_asn, &at(None, None, Some(64500), false)));
        assert!(!hit(&only_asn, &at(Some("US"), None, None, false)), "no ASN data: unknown, left alone");
    }

    #[test]
    fn geo_rule_validation() {
        use crate::config::{Action, GeoMode, GeoRule};
        let base = GeoRule {
            id: "only-id".into(),
            description: None,
            enabled: true,
            mode: GeoMode::AllowOnly,
            action: Action::Block,
            countries: vec!["ID".into()],
            regions: vec![],
            asns: vec![],
        };
        assert!(base.validate().is_ok());
        let bad = |f: &dyn Fn(&mut GeoRule)| {
            let mut r = base.clone();
            f(&mut r);
            r.validate().is_err()
        };
        assert!(bad(&|r| r.countries = vec!["id".into()]));
        assert!(bad(&|r| r.countries = vec!["IDN".into()]));
        assert!(bad(&|r| r.countries = vec![r#"ID" or "1"#.into()]));
        assert!(bad(&|r| r.regions = vec!["JK".into()]));
        assert!(bad(&|r| r.regions = vec![r#"ID:Jak" or "1"#.into()]));
        assert!(bad(&|r| r.regions = vec!["ID:".into()]));
        assert!(!bad(&|r| r.regions = vec!["ID:Jakarta".into(), "ID-JK".into()]));
        assert!(bad(&|r| r.countries.clear()));
        assert!(bad(&|r| r.action = Action::Allow));
        assert!(bad(&|r| r.id = "Has Space".into()));
        assert!(bad(&|r| r.asns = vec![0]));
    }
}
