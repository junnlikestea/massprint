use crate::Result;
use regex::{RegexSet, RegexSetBuilder};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use reqwest::{Client, Response};
use serde::Deserialize;
use std::fs;
use tracing::info;

// Currently only supports supplying one template as input.
// heavly catered to my usecase
#[derive(Deserialize, Debug)]
struct Template {
    info: Info,
    requests: Vec<Request>,
}

// the indexing on self.requests works because you can only supply one template per run
impl Template {
    /// Returns the ports declared in the config file.
    pub fn ports(&self) -> &[i32] {
        self.requests[0].ports.as_slice()
    }

    /// Returns the request method declared in the config file.
    pub fn method(&self) -> String {
        self.requests[0].method.to_owned()
    }

    /// Returns the paths declared in the config file.
    pub fn paths(&self) -> &[String] {
        self.requests[0].paths.as_slice()
    }

    /// Returns the string identifiers declared in the config file.
    pub fn identifiers(&self) -> &[String] {
        self.requests[0].identifiers.as_slice()
    }

    /// Returns a request body if specified in the config file
    pub fn body(&self) -> Option<String> {
        let body = &self.requests[0].body;
        if let Some(b) = body {
            Some(b.to_owned())
        } else {
            None
        }
    }

    /// Returns the service name
    pub fn service(&self) -> String {
        self.info.service.to_string()
    }

    /// Returns the header defined in the template
    pub fn headers(&self) -> Option<Vec<Header>> {
        if let Some(header) = &self.requests[0].headers {
            Some(header.to_owned())
        } else {
            None
        }
    }
}

#[derive(Deserialize, Debug)]
struct Info {
    service: String,
    description: String,
}

#[derive(Deserialize, Debug)]
struct Request {
    method: String,
    body: Option<String>,
    json: Option<bool>,
    headers: Option<Vec<Header>>,
    paths: Vec<String>,
    identifiers: Vec<String>,
    ports: Vec<i32>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// A Identifiable FingerPrint for a particular service.
#[derive(Debug, Clone)]
pub struct FingerPrint {
    /// The name of the Service we want to discover
    pub service: String,
    /// The request method
    pub method: Method,
    /// Request body
    pub body: Option<String>,
    /// Request body in json
    pub json: bool,
    /// Headers if supplied
    pub headers: HeaderMap,
    /// The collection of ports you want to check for
    pub ports: Vec<i32>,
    /// The paths you want to check for the fingerprint
    pub paths: Vec<String>, // this should be an optional field, if it's empty just request the `/`
    /// The collection of regex used to discover a positive result
    pub identifiers: RegexSet,
}

impl FingerPrint {
    /// Builds a new `FingerPrint` given a `name` and a Vec of identifiabled strings.
    #[allow(clippy::all)]
    pub fn new(
        service: String,
        method: String,
        body: Option<String>,
        json: Option<bool>,
        headers: Option<Vec<Header>>,
        ports: Vec<i32>,
        paths: Vec<String>,
        identifiers: Vec<String>,
    ) -> FingerPrint {
        let regexs = RegexSetBuilder::new(
            identifiers
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>(),
        )
        .build()
        .unwrap();

        let json = json.is_some();
        let mut header_map = HeaderMap::new();
        header_map.insert(
            HeaderName::from_static("x-bugbounty-tool"),
            HeaderValue::from_static("massprint"),
        );

        if let Some(h) = headers {
            h.into_iter()
                .map(|s| {
                    let name = HeaderName::from_bytes(s.name.as_bytes()).unwrap();
                    let value = HeaderValue::from_bytes(s.value.as_bytes()).unwrap();
                    header_map.insert(name, value)
                })
                .for_each(drop);
        }

        FingerPrint {
            service,
            method: Method::from_bytes(method.as_bytes()).unwrap(),
            body,
            json,
            headers: header_map,
            ports,
            paths,
            identifiers: regexs,
        }
    }
    /// Reads the contents of a json file containing fingerprints to a Vec of `FingerPrint`
    pub fn from_yaml(path: &str) -> Result<FingerPrint> {
        // A temporary struct to deserialize into
        let contents = fs::read_to_string(path)?;
        let template: Template = serde_yaml::from_str(&contents).unwrap();
        let fingerprint = FingerPrint::new(
            template.service(),
            template.method(),
            template.body(),
            template.requests[0].json,
            template.headers(), // think we need to createa  map of headers not a vec of Header
            template.ports().to_vec(),
            template.paths().to_vec(),
            template.identifiers().to_vec(),
        );

        Ok(fingerprint)
    }

    /// Returns a copy of the service
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Returns a copy of the headers
    fn headers(&self) -> HeaderMap {
        // requestbuilder needs ownership of headers
        self.headers.clone()
    }

    /// Returns a copy of the method
    fn method(&self) -> reqwest::Method {
        // client.request needs ownership of method
        self.method.clone()
    }

    /// Returns a copy of the method
    fn body(&self) -> String {
        if let Some(b) = &self.body {
            b.to_string()
        } else {
            String::new()
        }
    }

    /// A simple wrapper around a request client.
    pub async fn fetch(
        &self,
        client: Client,
        uri: &str,
    ) -> std::result::Result<Response, reqwest::Error> {
        info!(message = "polling", uri = %uri);
        if self.json {
            let body: serde_json::Value = serde_json::from_str(&self.body()).unwrap();
            client
                .request(self.method(), uri)
                .headers(self.headers())
                .json(&body)
                .send()
                .await
        } else {
            client
                .request(self.method(), uri)
                .headers(self.headers())
                .body(self.body())
                .send()
                .await
        }
    }
}

/// Represents a collection of services you want to fingerprint.
#[derive(Debug)]
pub struct FingerPrintSet {
    pub fingerprints: Vec<FingerPrint>,
}

impl FingerPrintSet {
    pub fn new(paths: Vec<&str>) -> Self {
        let fingerprints = paths
            .into_iter()
            .map(FingerPrint::from_yaml)
            .flatten()
            .collect();

        Self { fingerprints }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    // If we can read the template
    #[test]
    fn from_yaml() {
        let fingerprint = FingerPrint::from_yaml("./templates/tech/graphql.yaml").unwrap();
        assert_eq!(fingerprint.service.to_string(), "GraphQL");
    }

    // Test if a the template contains header
    #[test]
    fn with_headers() {
        let fingerprint = FingerPrint::from_yaml("./templates/tech/graphql.yaml").unwrap();
        assert!(fingerprint.headers.get("Content-Type").is_some());
    }

    // Test if we can read the ports of a template
    #[test]
    fn with_ports() {
        let fingerprint = FingerPrint::from_yaml("./templates/tech/graphql.yaml").unwrap();
        assert!(!fingerprint.ports.is_empty() && !fingerprint.headers.is_empty());
    }

    // Test if we can read the body of a template
    #[test]
    fn with_body() {
        let fingerprint = FingerPrint::from_yaml("./templates/tech/graphql.yaml").unwrap();
        assert!(fingerprint.body.is_some());
    }
    // Test if we can read the body of a template
    #[test]
    fn with_paths() {
        let fingerprint = FingerPrint::from_yaml("./templates/tech/graphql.yaml").unwrap();
        assert!(!fingerprint.paths.is_empty());
    }
}
