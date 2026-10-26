use std::net::IpAddr;

use maxminddb::{Reader, geoip2};

#[derive(Clone)]
pub struct GeoIpLookup {
    pub as_num: Option<u32>,
    pub country_name: Option<String>,
    pub is_in_european_union: bool,
    pub as_org: Option<String>,
    pub city: Option<String>,
    pub continent: Option<String>,
    pub country: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub metro_code: Option<u16>,
    pub postal_code: Option<String>,
    pub region: Option<String>,
    pub region_code: Option<String>,
    pub timezone: Option<String>,
}

/// City (or country) and ASN databases in MaxMind DB format: GeoLite2 or
/// DB-IP Lite. Either may be absent; lookups then leave those fields empty.
pub struct GeoIp {
    city_reader: Option<Reader<Vec<u8>>>,
    asn_reader: Option<Reader<Vec<u8>>>,
}

/// What a loaded database file is.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GeoDbInfo {
    pub kind: &'static str,
    pub database_type: String,
    /// Unix seconds when the file was built.
    pub build_epoch: u64,
    pub ip_version: u16,
    pub node_count: u32,
}

impl GeoIp {
    pub fn open(
        city_path: impl AsRef<std::path::Path>,
        asn_path: impl AsRef<std::path::Path>,
    ) -> Result<Self, maxminddb::MaxMindDbError> {
        let city_reader = Reader::open_readfile(city_path)?;
        let asn_reader = Reader::open_readfile(asn_path)?;

        Ok(Self {
            city_reader: Some(city_reader),
            asn_reader: Some(asn_reader),
        })
    }

    /// Open whichever databases are given. A file that is not a location
    /// (City/Country) or ASN database is refused.
    pub fn open_parts(
        city_path: Option<&std::path::Path>,
        asn_path: Option<&std::path::Path>,
    ) -> Result<Self, String> {
        let open = |p: &std::path::Path, want: &[&str]| -> Result<Reader<Vec<u8>>, String> {
            let r = Reader::open_readfile(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let t = r.metadata.database_type.to_ascii_lowercase();
            if !want.iter().any(|w| t.contains(w)) {
                return Err(format!(
                    "{}: database type {:?} is not a {} database",
                    p.display(),
                    r.metadata.database_type,
                    want.join("/")
                ));
            }
            Ok(r)
        };
        Ok(Self {
            city_reader: city_path.map(|p| open(p, &["city", "country", "location"])).transpose()?,
            asn_reader: asn_path.map(|p| open(p, &["asn", "isp"])).transpose()?,
        })
    }

    pub fn info(&self) -> Vec<GeoDbInfo> {
        let mut out = Vec::new();
        for (kind, r) in [("location", &self.city_reader), ("asn", &self.asn_reader)] {
            if let Some(r) = r {
                out.push(GeoDbInfo {
                    kind,
                    database_type: r.metadata.database_type.clone(),
                    build_epoch: r.metadata.build_epoch,
                    ip_version: r.metadata.ip_version,
                    node_count: r.metadata.node_count,
                });
            }
        }
        out
    }

    pub fn lookup(&self, ip: IpAddr) -> GeoIpLookup {
        let mut result = GeoIpLookup {
            as_num: None,
            country_name: None,
            is_in_european_union: false,
            as_org: None,
            city: None,
            continent: None,
            country: None,
            lat: None,
            lon: None,
            metro_code: None,
            postal_code: None,
            region: None,
            region_code: None,
            timezone: None,
        };

        if let Some(r) = &self.asn_reader
            && let Ok(lookup) = r.lookup(ip)
            && let Ok(Some(asn)) = lookup.decode::<geoip2::Asn>()
        {
            result.as_num = asn.autonomous_system_number;
            result.as_org = asn.autonomous_system_organization.map(String::from);
        }

        if let Some(r) = &self.city_reader
            && let Ok(lookup) = r.lookup(ip)
            && let Ok(Some(city)) = lookup.decode::<geoip2::City>()
        {
            {
                result.city = city.city.names.english.map(String::from);
                result.continent = city.continent.code.map(String::from);
                result.country = city.country.iso_code.map(String::from);
                result.country_name = city.country.names.english.map(String::from);
                result.is_in_european_union =
                    is_in_european_union(city.country.iso_code, city.country.is_in_european_union);
                result.lat = city.location.latitude;
                result.lon = city.location.longitude;
                result.metro_code = city.location.metro_code;
                result.timezone = city.location.time_zone.map(String::from);
                result.postal_code = city.postal.code.map(String::from);

                if let Some(first) = city.subdivisions.first() {
                    result.region = first.names.english.map(String::from);
                    result.region_code = first.iso_code.map(String::from);
                }
            }
        }

        result
    }
}

/// How events and geo rules name a region: `ID-JK` from an ISO 3166-2
/// code, or `ID:Jakarta` when the database names regions without codes.
pub fn region_key(country: Option<&str>, code: Option<&str>, name: Option<&str>) -> Option<String> {
    let c = country?;
    match (code, name) {
        (Some(r), _) if !r.is_empty() => Some(format!("{c}-{r}")),
        (_, Some(n)) if !n.is_empty() => Some(format!("{c}:{n}")),
        _ => None,
    }
}

/// Country and territory codes that count as the European Union
pub const EU_COUNTRY_CODES: &[&str] = &[
    "AT", "AX", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GF", "GP", "GR", "HR",
    "HU", "IE", "IT", "LT", "LU", "LV", "MF", "MQ", "MT", "NL", "PL", "PT", "RE", "RO", "SE", "SI",
    "SK", "YT",
];

pub fn is_in_european_union(iso_code: Option<&str>, maxmind_flag: Option<bool>) -> bool {
    maxmind_flag.unwrap_or(false) || iso_code.is_some_and(|code| EU_COUNTRY_CODES.contains(&code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_states_and_outermost_regions_are_eu() {
        assert!(is_in_european_union(Some("DE"), Some(true)));
        assert!(is_in_european_union(Some("DE"), None));
        assert!(is_in_european_union(Some("RE"), Some(false)));
        assert!(is_in_european_union(Some("YT"), None));
    }

    #[test]
    fn others_are_not() {
        assert!(!is_in_european_union(Some("GB"), Some(false)));
        assert!(!is_in_european_union(Some("CH"), None));
        assert!(!is_in_european_union(Some("US"), None));
        assert!(!is_in_european_union(None, None));
    }

    #[test]
    fn maxmind_flag_wins_even_for_unlisted_codes() {
        assert!(is_in_european_union(Some("XX"), Some(true)));
    }
}
