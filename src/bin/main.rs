use clap::{App, Arg};
use massprint::FingerPrintSet;
use massprint::Input;
use massprint::Inspector;
use massprint::Result;

fn create_clap_app(version: &str) -> clap::App {
    App::new("massprint")
        .version(version)
        .about("Fingerprinting Services en masse")
        .usage("massprint -i <targets.txt> -t <template.yaml>")
        .arg(
            Arg::with_name("input-file")
                .help("massprint -i <targets.txt>")
                .short("i")
                .long("input-file")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("template")
                .help("massprint -t <template.yaml>")
                .short("t")
                .long("template")
                .takes_value(true)
                .multiple(true)
                .required(true),
        ).arg(
            Arg::with_name("num-batch")
                .help("massprint --num-batch 4 -b <batch-id>")
                .short("n")
                .long("num-batch")
                .takes_value(true)
                .requires("batch"),
        )
        .arg(
            Arg::with_name("batch")
                .help("massprint --num-batch 4 -b <batch-id>")
                .short("b")
                .long("batch")
                .takes_value(true)
                .requires("num-batch"),
        )
        .arg(
            Arg::with_name("verbosity")
                .help("verbosity of output")
                .short("v")
                .long("verbosity")
                .takes_value(true)
                .default_value(""),
        )
        .arg(
            Arg::with_name("notifications")
                .help("turn on slack notifications")
                .long("notifications")
                .requires("channel")
                .requires("webhook")
                .required(false)
        )
        .arg(
            Arg::with_name("channel")
                .help("the slack channel you want to send the alerts to")
                .long("channel")
                .requires("notifications")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("webhook")
                .help("the slack webhook you want to send notifications to")
                .long("webhook")
                .takes_value(true)
                .requires("notifications")
        )
        .arg(
            Arg::with_name("concurrency")
                .help("the number of tasks you want to concurrently. This is technically the size of the channel.")
                .short("c")
                .long("concurrency")
                .takes_value(true)
                .default_value("200"),
        )
        .arg(
            Arg::with_name("timeout")
                .help("request timeout")
                .long("timeout")
                .takes_value(true)
                .default_value("15"),
        )
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = create_clap_app("0.1.0");
    let matches = args.get_matches();
    let verbosity = matches.value_of("verbosity").unwrap();
    let templates: Vec<&str> = matches.values_of("template").unwrap().collect();
    let concurrency = matches.value_of("concurrency").unwrap().parse::<usize>()?;
    let timeout = matches.value_of("timeout").unwrap().parse::<u64>()?;
    // tracing_subscriber::fmt()
    //     .with_max_level(tracing::Level::TRACE)
    //     .try_init()?;
    if !verbosity.is_empty() {
        let builder = tracing_subscriber::fmt()
            .with_env_filter(verbosity)
            .with_filter_reloading();
        let _handle = builder.reload_handle();
        builder.try_init()?;
    }

    let path = if let Some(path) = matches.value_of("input-file") {
        Some(path)
    } else {
        None
    };

    let targets = if matches.is_present("num-batch") {
        let num_batches: usize = matches.value_of("num-batch").unwrap().parse()?;
        let mut batch_id: usize = matches.value_of("batch").unwrap().parse()?;
        // indexing starts at 0;
        if batch_id.eq(&num_batches) {
            batch_id -= 1;
        }

        let mut input = Input::new(path);
        input
            .build_batches(num_batches)
            .batch(batch_id)
            .expect("batch index out of bounds")
    } else {
        Input::new(path).lines()
    };

    let fingerprints = FingerPrintSet::new(templates);
    let inspector = Inspector::new(targets, fingerprints);

    if matches.is_present("notifications") {
        let webhook = matches.value_of("webhook").unwrap();
        let channel = matches.value_of("channel").unwrap();
        inspector
            .combinations()
            .slack(channel, webhook)
            .run(concurrency, timeout)
            .await?;
    } else {
        inspector.combinations().run(concurrency, timeout).await?;
    }

    Ok(())
}
