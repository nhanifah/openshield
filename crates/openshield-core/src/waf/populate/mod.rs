mod jwt;
mod request_body;
mod request_headers;
mod response_body;
mod response_headers;
pub mod schema;

use std::collections::HashMap;

pub use jwt::jwt_fields;
pub use request_body::{body_fields, multipart_fields};
pub use request_headers::request_fields;
pub use response_body::response_body_fields;
pub use response_headers::response_fields;
pub use schema::{schema_body_fields, schema_fields};
use wirefilter_engine::{Bytes as WfBytes, TypedArray, TypedMap};

macro_rules! set_field {
    ($ctx:expr, $scheme:expr, $name:expr, Str, $val:expr) => {
        set_field!($ctx, $scheme, $name, Bytes, ($val).as_bytes())
    };
    ($ctx:expr, $scheme:expr, $name:expr, Bytes, $val:expr) => {
        set_field!($ctx, $scheme, $name, LhsValue::Bytes($val.to_vec().into()))
    };
    ($ctx:expr, $scheme:expr, $name:expr, Int, $val:expr) => {
        set_field!($ctx, $scheme, $name, LhsValue::Int($val as i64))
    };
    ($ctx:expr, $scheme:expr, $name:expr, Bool, $val:expr) => {
        set_field!($ctx, $scheme, $name, LhsValue::Bool($val))
    };
    ($ctx:expr, $scheme:expr, $name:expr, Ip, $val:expr) => {
        set_field!($ctx, $scheme, $name, LhsValue::Ip($val))
    };
    ($ctx:expr, $scheme:expr, $name:expr, Arr, $val:expr) => {
        set_field!(
            $ctx,
            $scheme,
            $name,
            $crate::waf::populate::owned_array($val)
        )
    };
    ($ctx:expr, $scheme:expr, $name:expr, MapArr, $val:expr) => {
        set_field!(
            $ctx,
            $scheme,
            $name,
            $crate::waf::populate::owned_map_of_arrays($val)
        )
    };
    ($ctx:expr, $scheme:expr, $name:expr, $value:expr) => {
        if let Ok(field) = $scheme.get_field($name) {
            let _ = $ctx.set_field_value(field, $value);
        }
    };
}

pub(crate) use set_field;

pub fn owned_array(
    items: impl IntoIterator<Item = String>,
) -> TypedArray<'static, WfBytes<'static>> {
    TypedArray::from_iter(items.into_iter().map(|s| WfBytes::from(s.into_bytes())))
}

pub fn owned_map_of_arrays<K: AsRef<str>, V: AsRef<str>>(
    pairs: impl IntoIterator<Item = (K, V)>,
) -> TypedMap<'static, TypedArray<'static, WfBytes<'static>>> {
    let mut groups: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    for (k, v) in pairs {
        groups
            .entry(k.as_ref().to_string())
            .or_default()
            .push(v.as_ref().as_bytes().to_vec());
    }
    let mut map = TypedMap::new();
    for (k, values) in groups {
        let arr: TypedArray<'static, WfBytes<'static>> =
            TypedArray::from_iter(values.into_iter().map(WfBytes::from));
        map.insert(k.into_bytes().into_boxed_slice(), arr);
    }
    map
}

pub fn parse_form_urlencoded(input: &[u8]) -> Vec<(String, String)> {
    form_urlencoded::parse(input)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

pub fn get_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub(crate) fn dedup(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::with_capacity(items.len());
    items
        .into_iter()
        .filter(|s| seen.insert(s.clone()))
        .collect()
}

pub(crate) fn split_pairs(pairs: &[(String, String)]) -> (Vec<String>, Vec<String>) {
    let names = dedup(pairs.iter().map(|(k, _)| k.clone()).collect());
    let values = pairs.iter().map(|(_, v)| v.clone()).collect();
    (names, values)
}

#[cfg(test)]
pub(crate) mod test_support {
    use wirefilter_engine::{ExecutionContext, Scheme};

    use crate::waf::data::RequestData;

    pub fn scheme() -> Scheme {
        crate::waf::scheme::build(&[], &[])
    }

    /// A fresh context for populating fields. The scheme is cloned internally,
    /// so the returned context is self-contained (`'static` values).
    pub fn context(scheme: &Scheme) -> ExecutionContext<'static> {
        crate::waf::scheme::new_context(scheme)
    }

    /// A `RequestData` with everything empty/defaulted — tests set only the
    /// fields they care about.
    pub fn empty_request() -> RequestData {
        RequestData {
            client_ip: None,
            is_tls: false,
            method: String::new(),
            version: String::new(),
            host: String::new(),
            full_uri: String::new(),
            uri: String::new(),
            path: String::new(),
            query: String::new(),
            extension: String::new(),
            headers: Vec::new(),
            geo: None,
            allowlisted: false,
        }
    }

    /// Evaluate a boolean expression against a populated context.
    pub fn check(scheme: &Scheme, ctx: &ExecutionContext<'static>, expr: &str) -> bool {
        scheme
            .parse(expr)
            .expect("expression should parse")
            .compile()
            .execute(ctx)
            .expect("filter should execute")
    }
}
