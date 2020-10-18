use crate::{FingerPrint, FingerPrintSet, Result};

use chrono::prelude::*;
use colored::Colorize;
use reqwest::{Client, Response};
use serde::Serialize;
use slack_hook2::{PayloadBuilder, Slack};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace};

#[derive(Default, Debug)]
struct SlackConfig {
    channel: String,
    webhook: String,
    username: String,
}

/// A structure used to log the responses
#[derive(Debug, Serialize)]
pub struct InspectResult {
    location: String,
    service: String,
    status: u16,
    body: String,
    is_match: bool,
}

impl InspectResult {
    pub fn new(location: String, service: &str, status: u16, body: String, is_match: bool) -> Self {
        InspectResult {
            location,
            service: service.to_string(),
            status,
            body,
            is_match,
        }
    }
}

/// An Inspector takes a collection of Fingerprints and a targets, and then runs an inspection
/// for all Fingerprints against all targets.
#[derive(Debug)]
pub struct Inspector {
    /// The collection of targets that you want to do an inspection of. These targets can be Ipv4
    /// addresses, or hostnames in the format `hackerone.com`
    targets: Vec<String>,
    /// The `set` is the collection of templates that you want to search for across the targets.
    set: FingerPrintSet,
    /// The `combinations` are the different permutations of each port/path combination.
    combinations: HashMap<String, Vec<String>>,
    slack: SlackConfig,
    notifications: bool,
}

impl Inspector {
    /// Builds a new instance of an Inspector
    pub fn new(targets: Vec<String>, set: FingerPrintSet) -> Inspector {
        Inspector {
            targets,
            set,
            combinations: HashMap::new(),
            slack: SlackConfig::default(),
            notifications: false,
        }
    }

    /// Configure the Inspector to send alerts to Slack when it has found a match to one of the
    /// identifiers.
    pub fn slack(mut self, channel: &str, webhook: &str) -> Inspector {
        self.notifications = true;
        self.slack.webhook = webhook.into();
        self.slack.channel = channel.into();
        self.slack.username = "massprint".into(); // give option to pass username.
        self
    }

    /// Sends an alert to slack.
    async fn slack_alert(&self, fingerprint: Arc<FingerPrint>, target: &str) {
        let slack = Slack::new(&self.slack.webhook).unwrap();
        let msg = format!(
            ":tada: Found a potential match for `{}` at `{}`\n",
            &fingerprint.service(),
            &target
        );

        let p = PayloadBuilder::new()
            .text(msg)
            .channel(&self.slack.channel)
            .username(&self.slack.username)
            .build()
            .unwrap();

        let res = slack.send(&p).await;
        match res {
            Ok(_) => info!("successfully sent slack notification"),
            Err(_) => error!("failed to send slack notification"),
        }
    }

    /// Builds all the target + port/path combinations so we don't have to create a O(n^4) loop inside
    /// the async function body. Build once, use forever.
    pub fn combinations(mut self) -> Inspector {
        // this is ok for now, we could avoid this completely if we just hardcoded the port into
        // the path inside the template.
        trace!("building port/path combinations");
        for f in self.set.fingerprints.iter() {
            let mut perms = Vec::new();
            for t in self.targets.iter() {
                for port in f.ports.iter() {
                    for path in f.paths.iter() {
                        let uri = Inspector::build_uri(t, port, path);
                        perms.push(uri);
                    }
                }
            }
            info!("built {} paths for {}", perms.len(), f.service);
            self.combinations.insert(f.service.clone(), perms);
        }

        debug!("finished building combinations");
        self
    }

    /// Builds a URI given a particular target/port/path combination.
    fn build_uri(target: &str, port: &i32, path: &str) -> String {
        match (path, port) {
            (path, 443) => {
                if path.eq("/") {
                    format!("https://{}/", target)
                } else {
                    format!("https://{}/{}", target, path)
                }
            }
            (path, port) => {
                if path.eq("/") {
                    format!("http://{}:{}/", target, port)
                } else {
                    format!("http://{}:{}/{}", target, port, path)
                }
            }
        }
    }

    /// Iterates over the paths constructed by `generate_combinations`
    async fn inspect(
        self: Arc<Inspector>,
        combinations: &[String],
        fingerprint: Arc<FingerPrint>,
        sender: mpsc::Sender<InspectResult>,
        client: Client,
        concurrency: usize,
    ) -> Result<()> {
        use futures::StreamExt;

        let identifiers = Arc::new(fingerprint.identifiers.clone());
        let streams = futures::stream::iter(combinations).map(|uri| {
                //let span = span!(Level::DEBUG, "inspect", current_fingerprint = ?fingerprint.service,uri = %uri);
                // cloning some arcs
                let identifiers = Arc::clone(&identifiers);
                let fingerprint = Arc::clone(&fingerprint);
                let inspector = Arc::clone(&self);
                let client = client.clone();
                let sender = sender.clone();
                // not cloning arc
                let uri = uri.clone();
                debug!(message = "creating inspection task;", uri = %uri, service = %fingerprint.service);
                tokio::spawn(async move {
                    let resp = fingerprint.fetch(client, &uri).await;
                    match resp {
                        Ok(r) => {
                            info!("got {} requesting {}", r.status(), uri);
                            //TODO: create custom error type, return that instead of just map_err
                            //into option.
                            inspector
                                .handle_response(fingerprint, sender.clone(), r, uri, identifiers)
                                .await.map_err(|e| error!("tried to handle response, but got error {}",e)).ok();
                        }

                        Err(e) => error!("{} requesting {}", e, uri),
                    }
                })
            }).buffer_unordered(concurrency).map(|r| r).collect::<Vec<_>>();
        streams.await;
        Ok(())
    }

    /// Sends a request and inspects if the FingerPrint regex matches the response.
    pub async fn inspect_all(
        self: Arc<Self>,
        client: Client,
        sender: mpsc::Sender<InspectResult>,
        concurrency: usize,
    ) -> Result<()> {
        // HERE BE DRAGONS!
        info!("spawning inspections");
        let inspector = Arc::clone(&self);
        let fingerprints = inspector.set.fingerprints.clone();

        for fingerprint in fingerprints.into_iter() {
            let fingerprint = Arc::new(fingerprint);
            let combinations = inspector.combinations.get(&fingerprint.service).unwrap();
            let inspector = Arc::clone(&inspector);
            inspector
                .inspect(
                    combinations,
                    fingerprint.clone(),
                    sender.clone(),
                    client.clone(),
                    concurrency,
                )
                .await?;
        }

        Ok(())
    }

    /// This method Determines if the response contains a match or not, if it is, we send a slack notification.
    /// All aggregated responses are logged into a file regardless of if they were a match or not.
    async fn handle_response(
        &self,
        fingerprint: Arc<FingerPrint>,
        mut sender: mpsc::Sender<InspectResult>,
        response: Response,
        uri: String,
        regexset: Arc<regex::RegexSet>,
    ) -> Result<()> {
        let status = response.status().as_u16();
        let body = self.aggregate_response(response).await.unwrap();

        if regexset.is_match(&body) {
            info!("found a match for {} at {}", fingerprint.service(), &uri);
            if self.notifications {
                self.slack_alert(Arc::clone(&fingerprint), &uri).await;
            }

            sender
                .send(InspectResult::new(
                    uri,
                    fingerprint.service(),
                    status,
                    body,
                    true,
                ))
                .await?
        } else {
            sender
                .send(InspectResult::new(
                    uri,
                    fingerprint.service(),
                    status,
                    body,
                    false,
                ))
                .await?
        }
        Ok(())
    }

    /// Takes a reqwest `Response` and aggregates the headers and response body into one string,
    /// that is then used to match against a fingerprint regex.
    async fn aggregate_response(&self, mut response: Response) -> Result<String> {
        let mut agg = String::new();
        response
            .headers_mut()
            .drain()
            .map(|(k, v)| {
                let v = v.to_str();
                // only add the header if both the name and value can be parsed
                if k.is_some() && v.is_ok() {
                    agg.push_str(&format!("{}:{}\n", k.unwrap(), v.unwrap()));
                }
            })
            .for_each(drop);

        // add the body
        agg.push_str(&format!("\n\n{}", response.text().await?));
        Ok(agg)
    }

    /// Inspects every target for any of the fingerprints.
    pub async fn run(self, concurrency: usize, timeout: u64) -> Result<()> {
        use tokio::prelude::*;
        trace!("starting inspection on all targets");

        let beg = Instant::now();
        // the `buffer` size of the channel is the maximum number of messages before calls to
        // `.send` start waiting for things to be received
        let (sender, mut receiver) = mpsc::channel::<InspectResult>(50);
        let inspector = Arc::new(self);
        let now: DateTime<Local> = Local::now();
        let filepath = format!(
            "{}-{}-{}-{}-mp_results.json",
            now.year(),
            now.month(),
            now.day(),
            now.minute()
        );
        let mut out = fs::File::create(filepath).await?;
        let client = reqwest::ClientBuilder::new()
            .timeout(Duration::from_secs(timeout))
            .pool_idle_timeout(Duration::from_secs(timeout))
            .build()?;

        let manager = tokio::spawn(async move {
            while let Some(r) = receiver.recv().await {
                if r.is_match {
                    println!(
                        "found a match for {} at {}",
                        r.service.bright_green(),
                        r.location.bright_yellow()
                    );
                };

                let json = serde_json::to_vec(&r).unwrap();
                match out.write_all(&json).await {
                    Err(e) => {
                        error!(
                            "couldn't write {} bytes to output file; got error {}",
                            json.len(),
                            e
                        );
                    }

                    Ok(_) => info!("wrote {} bytes to the output file", json.len()),
                }
            }
        });

        inspector
            .inspect_all(client.clone(), sender, concurrency)
            .await?;

        manager.await?;
        let end = Instant::now();
        info!("inspections done in {:?} seconds", (end - beg).as_secs());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ip with a port
    #[test]
    fn ip_with_port() {
        let res = Inspector::build_uri("127.0.0.1", &8080, "/");
        assert_eq!(res, "http://127.0.0.1:8080/");
    }

    // ip with a port and a path
    #[test]
    fn ip_with_port_path() {
        let res = Inspector::build_uri("127.0.0.1", &8080, "metrics");
        assert_eq!(res, "http://127.0.0.1:8080/metrics");
    }

    // ip with a port and a path
    #[test]
    fn ip_with_https() {
        let res = Inspector::build_uri("127.0.0.1", &443, "/");
        assert_eq!(res, "https://127.0.0.1/");
    }

    // host with a port and a path
    #[test]
    fn host_with_port() {
        let res = Inspector::build_uri("hackerone.com", &80, "/");
        assert_eq!(res, "http://hackerone.com:80/");
    }

    // host with a port and a path
    #[test]
    fn host_with_port_path() {
        let res = Inspector::build_uri("hackerone.com", &8080, "hacktivity");
        assert_eq!(res, "http://hackerone.com:8080/hacktivity");
    }

    // host with a port and a path
    #[test]
    fn host_with_https() {
        let res = Inspector::build_uri("hackerone.com", &443, "hacktivity");
        assert_eq!(res, "https://hackerone.com/hacktivity");
    }
}
