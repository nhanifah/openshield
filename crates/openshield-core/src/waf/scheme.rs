use wirefilter_engine::{ExecutionContext, Scheme, SchemeBuilder, Type};

use super::functions;
use super::lists::{BytesListDefinition, IpListDefinition};

macro_rules! opt {
    ($b:expr, $name:expr, Str) => {
        $b.add_optional_field($name, Type::Bytes).unwrap()
    };
    ($b:expr, $name:expr, Int) => {
        $b.add_optional_field($name, Type::Int).unwrap()
    };
    ($b:expr, $name:expr, Bool) => {
        $b.add_optional_field($name, Type::Bool).unwrap()
    };
    ($b:expr, $name:expr, Ip) => {
        $b.add_optional_field($name, Type::Ip).unwrap()
    };
    ($b:expr, $name:expr, Arr<Str>) => {
        $b.add_optional_field($name, Type::Array(Type::Bytes.into()))
            .unwrap()
    };
    ($b:expr, $name:expr, Arr<Int>) => {
        $b.add_optional_field($name, Type::Array(Type::Int.into()))
            .unwrap()
    };
    ($b:expr, $name:expr, Arr<Arr<Str>>) => {
        $b.add_optional_field($name, Type::Array(Type::Array(Type::Bytes.into()).into()))
            .unwrap()
    };
    ($b:expr, $name:expr, Map<Arr<Str>>) => {
        $b.add_optional_field($name, Type::Map(Type::Array(Type::Bytes.into()).into()))
            .unwrap()
    };
    ($b:expr, $name:expr, Map<Arr<Int>>) => {
        $b.add_optional_field($name, Type::Map(Type::Array(Type::Int.into()).into()))
            .unwrap()
    };
}

/// Wirefilter has no boolean literals, so `true` and `false` are registered
/// as fields that [`new_context`] sets on every execution context.
pub const CONSTANTS: [(&str, bool); 2] = [("true", true), ("false", false)];

/// JWT claims exposed as `http.request.jwt.claims.{name}`, keyed by token
/// configuration ID.
pub const JWT_STRING_CLAIMS: [&str; 4] = ["aud", "iss", "jti", "sub"];
/// JWT timestamp claims exposed as `http.request.jwt.claims.{name}.sec`.
pub const JWT_TIME_CLAIMS: [&str; 2] = ["iat", "nbf"];

/// `token_ids` are the configured token configuration IDs.
pub fn build(score_names: &[String], token_ids: &[String]) -> Scheme {
    let mut b = SchemeBuilder::new();

    // constants
    for (name, _) in CONSTANTS {
        b.add_field(name, Type::Bool).unwrap();
    }

    // fields
    opt!(b, "ip.src", Ip);
    opt!(b, "ip.src.allowlisted", Bool);
    opt!(b, "ip.src.has_country", Bool);
    opt!(b, "ip.src.has_asnum", Bool);
    opt!(b, "ip.src.asnum", Int);
    opt!(b, "ip.src.city", Str);
    opt!(b, "ip.src.continent", Str);
    opt!(b, "ip.src.country", Str);
    opt!(b, "ip.src.is_in_european_union", Bool);
    opt!(b, "ip.src.lat", Str);
    opt!(b, "ip.src.lon", Str);
    opt!(b, "ip.src.metro_code", Str);
    opt!(b, "ip.src.postal_code", Str);
    opt!(b, "ip.src.region", Str);
    opt!(b, "ip.src.region_code", Str);
    opt!(b, "ip.src.timezone.name", Str);

    opt!(b, "http.cookie", Str);
    opt!(b, "http.host", Str);
    opt!(b, "http.referer", Str);
    opt!(b, "http.user_agent", Str);
    opt!(b, "http.x_forwarded_for", Str);
    opt!(b, "http.request.method", Str);
    opt!(b, "http.request.version", Str);
    opt!(b, "http.request.full_uri", Str);
    opt!(b, "http.request.uri", Str);
    opt!(b, "http.request.uri.path", Str);
    opt!(b, "http.request.uri.path.extension", Str);
    opt!(b, "http.request.uri.path.normalized", Str);
    opt!(b, "http.request.uri.query", Str);
    opt!(b, "http.request.timestamp.sec", Int);
    opt!(b, "http.request.timestamp.msec", Int);

    opt!(b, "http.request.headers", Map<Arr<Str>>);
    opt!(b, "http.request.headers.names", Arr<Str>);
    opt!(b, "http.request.headers.values", Arr<Str>);
    opt!(b, "http.request.cookies", Map<Arr<Str>>);
    opt!(b, "http.request.cookies.names", Arr<Str>);
    opt!(b, "http.request.cookies.values", Arr<Str>);
    opt!(b, "http.request.uri.args", Map<Arr<Str>>);
    opt!(b, "http.request.uri.args.names", Arr<Str>);
    opt!(b, "http.request.uri.args.values", Arr<Str>);
    opt!(b, "http.request.accepted_languages", Arr<Str>);

    opt!(b, functions::VALID_FIELD, Arr<Str>);
    opt!(b, functions::PRESENT_FIELD, Arr<Str>);
    for claim in JWT_STRING_CLAIMS {
        let name = format!("http.request.jwt.claims.{claim}");
        opt!(b, &name, Map<Arr<Str>>);
        opt!(b, &format!("{name}.names"), Arr<Str>);
        opt!(b, &format!("{name}.values"), Arr<Str>);
    }
    for claim in JWT_TIME_CLAIMS {
        let name = format!("http.request.jwt.claims.{claim}.sec");
        opt!(b, &name, Map<Arr<Int>>);
        opt!(b, &format!("{name}.names"), Arr<Str>);
        opt!(b, &format!("{name}.values"), Arr<Int>);
    }

    {
        use crate::waf::populate::schema::{LOCATIONS, PREFIX};
        opt!(b, &format!("{PREFIX}.schema"), Str);
        opt!(b, &format!("{PREFIX}.operation.matched"), Bool);
        opt!(b, &format!("{PREFIX}.operation.template"), Str);
        opt!(b, &format!("{PREFIX}.violated"), Bool);
        for (_, segment) in LOCATIONS {
            opt!(
                b,
                &format!("{PREFIX}.{segment}.violated_parameters"),
                Arr<Str>
            );
        }
        opt!(
            b,
            &format!("{PREFIX}.query.undeclared_parameters"),
            Arr<Str>
        );
        for field in ["location", "error_class", "error_detail", "target"] {
            opt!(b, &format!("{PREFIX}.violation_details.{field}"), Str);
        }
    }

    opt!(b, "http.request.body.raw", Str);
    opt!(b, "http.request.body.size", Int);
    opt!(b, "http.request.body.truncated", Bool);
    opt!(b, "http.request.body.mime", Str);
    opt!(b, "http.request.body.form", Map<Arr<Str>>);
    opt!(b, "http.request.body.form.names", Arr<Str>);
    opt!(b, "http.request.body.form.values", Arr<Str>);
    opt!(b, "http.request.body.multipart", Map<Arr<Str>>);
    opt!(b, "http.request.body.multipart.values", Arr<Str>);
    opt!(b, "http.request.body.multipart.names", Arr<Arr<Str>>);
    opt!(
        b,
        "http.request.body.multipart.content_types",
        Arr<Arr<Str>>
    );
    opt!(
        b,
        "http.request.body.multipart.content_dispositions",
        Arr<Arr<Str>>
    );
    opt!(
        b,
        "http.request.body.multipart.content_transfer_encodings",
        Arr<Arr<Str>>
    );
    opt!(b, "http.request.body.multipart.filenames", Arr<Arr<Str>>);

    opt!(b, "http.response.code", Int);
    opt!(b, "http.response.content_type.media_type", Str);
    opt!(b, "http.response.headers", Map<Arr<Str>>);
    opt!(b, "http.response.headers.names", Arr<Str>);
    opt!(b, "http.response.headers.values", Arr<Str>);

    opt!(b, "http.response.body.raw", Str);
    opt!(b, "http.response.body.size", Int);
    opt!(b, "http.response.body.truncated", Bool);

    opt!(b, "ssl", Bool);

    for name in score_names {
        opt!(b, &format!("score.{name}"), Int);
    }

    // functions
    functions::register_all(&mut b, token_ids);

    // lists
    b.add_list(Type::Ip, IpListDefinition).unwrap();
    b.add_list(Type::Bytes, BytesListDefinition).unwrap();

    b.build()
}

pub fn new_context(scheme: &Scheme) -> ExecutionContext<'static> {
    let mut ctx = ExecutionContext::new(scheme);
    for (name, value) in CONSTANTS {
        let field = scheme.get_field(name).unwrap();
        ctx.set_field_value(field, value).unwrap();
    }
    ctx
}

#[cfg(test)]
mod tests {
    use super::{build, new_context};

    fn eval(expr: &str) -> bool {
        let scheme = build(&[], &[]);
        let filter = scheme.parse(expr).expect("should parse").compile();
        filter
            .execute(&new_context(&scheme))
            .expect("should execute")
    }

    #[test]
    fn boolean_constants_evaluate() {
        assert!(eval("true"));
        assert!(!eval("false"));
        assert!(eval("not false"));
        assert!(eval("(true) and (not false)"));
        // `http.host` is unset, so only the constant can make this match.
        assert!(eval(r#"true or http.host == "x""#));
        assert!(!eval(r#"false or http.host == "x""#));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let scheme = build(&[], &[]);
        assert!(scheme.get_field("does.not.exist").is_err());
    }

    #[test]
    fn score_fields_use_score_prefix() {
        let scheme = build(&["sqli".to_string(), "xss".to_string()], &[]);
        assert!(scheme.get_field("score.sqli").is_ok());
        assert!(scheme.get_field("score.xss").is_ok());
        // Scores not declared in config are not registered.
        assert!(scheme.get_field("score.undeclared").is_err());
    }

    #[test]
    fn no_score_fields_without_config() {
        let scheme = build(&[], &[]);
        assert!(scheme.get_field("score.sqli").is_err());
    }
}
