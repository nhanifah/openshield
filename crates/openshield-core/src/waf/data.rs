use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct RequestData {
    pub client_ip: Option<IpAddr>,
    pub is_tls: bool,
    pub method: String,
    pub version: String,
    pub host: String,
    pub full_uri: String,
    pub uri: String,
    pub path: String,
    pub query: String,
    pub extension: String,
    pub headers: Vec<(String, String)>,
    pub geo: Option<GeoData>,
}

#[derive(Debug, Clone)]
pub struct GeoData {
    pub asn: Option<u32>,
    pub is_in_european_union: bool,
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

#[derive(Debug, Clone)]
pub struct ResponseData {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

pub struct MultipartPartData {
    pub name: Option<String>,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub content_disposition: Option<String>,
    pub content_transfer_encoding: Option<String>,
    pub value: String,
}

impl From<&crate::geoip::GeoIpLookup> for GeoData {
    fn from(g: &crate::geoip::GeoIpLookup) -> Self {
        Self {
            asn: g.as_num,
            is_in_european_union: g.is_in_european_union,
            city: g.city.clone(),
            continent: g.continent.clone(),
            country: g.country.clone(),
            lat: g.lat,
            lon: g.lon,
            metro_code: g.metro_code,
            postal_code: g.postal_code.clone(),
            region: g.region.clone(),
            region_code: g.region_code.clone(),
            timezone: g.timezone.clone(),
        }
    }
}
