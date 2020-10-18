# Massprint
![release](https://github.com/junnlikestea/massprint/workflows/release/badge.svg)
[![Build status](https://github.com/junnlikestea/massprint/workflows/Continuous%20integration/badge.svg)](https://github.com/junnlikestea/massprint/actions)

Massprint tool to do light-weight fingerprinting across a large number of hosts, that is heavily
inspired by tools like [ProjectDiscovery's Nuclei](https://github.com/projectdiscovery/nuclei) and
[StaticFlow's go-fingerprint](https://github.com/Static-Flow/gofingerprint).


### Installation
Precompiled binaries for massprint are available in the [releases](https://github.com/junnlikestea/massprint/releases) 
tab. Just pick your platform and extract the archive that contains the binary.

## Building it yourself 
If you want to build it yourself you will need to install Rust, you can get the
[official installation](https://www.rust-lang.org/tools/install) from the Rust website.

To build Massprint:
```
$ git clone https://github.com/junnlikestea/massprint
$ cd massprint
$ cargo build --release
$ ./target/release/massprint --version
```

### Usage
**Creating a Template to use**

The massprint templates are very similar to the basic [Nuclei](https://github.com/projectdiscovery/nuclei-templates)
templates. For example, here is a template to discover Microsoft IIS servers that I created after watching
[@shubs](https://twitter.com/infosec_au) video [Hacking IIS servers](https://youtu.be/HrJW6Y9kHC4).
```yaml
info:
  service: Microsoft IIS
  description: Detect instances of Microsoft IIS servers.
  # Fingerprint identifiers taken from Shub's Video on IIS.

requests:
  - method: GET
    paths:
      - '/' # If you have no specific paths, specify the root path.
    identifiers: 
      - '<input[^>]+name="__VIEWSTATE' 
      - 'X-AspNet-Version:(.+);version:1,'
      - 'X-AspNet-Version:(.+)'
      - 'X-AspNetMvc-Version:(.+)'
      - 'X-Powered-By:^ASP\.NET'
      - 'ASP\.NET_SessionId'
      - 'ASPSESSION'
    ports: [80, 443]
```
check the templates directory for more examples.

**Running a single template across a list of hosts or IPs'**

The targets file can be a list of IP Addresses or subdomains, massprint doesn't 
currently take input in the form of `http://something.domain.com`.
```
massprint -i targets.txt -t templates/tech/graphql.yaml

```
or output from other tools
```
vita -d hackerone.com | massprint -t templates/tech/graphql.yaml
```

**Running multiple templates across a list of targets**
```
massprint -i targets.txt -t iis.yaml application-wadl.yaml
```
**Checking the output**

massprint will print the matches to stdout and write all responses into a json file, 
to quickly check for a match you could use `jq`
```json
~$jq -r 'select(.is_match==true)' 2020-9-29-0-mp_results.json

{
  "location": "https://hackerone.com/graphql",
  "service": "GraphQL",
  "status": 200,
  "body": "date:Tue, 29 Sep 2020 11:00:51 GMT\ncontent-type:application/json; charset=utf-8\ntransfer-encoding:chunked\nconnection:keep-alive\nset-cookie:__cfduid=d6655f3a6d558fe82609cf42e70d799a11601377251; expires=Thu, 29-Oct-20 11:00:51 GMT; path=/; domain=.hackerone.com; HttpOnly; SameSite=Lax; Secure\ncache-control:no-cache, no-store\ncontent-disposition:inline; filename=\"response.\"\nx-request-id:3d29a9e0-eb99-45e7-85ab-4274aa30f5bb\netag:W/\"d8d486d100c24abe1a9b0959ab0e593a\"\nstrict-transport-security:max-age=31536000; includeSubDomains; preload\nx-frame-options:DENY\nx-content-type-options:nosniff\nx-xss-protection:1; mode=block\nx-download-options:noopen\nx-permitted-cross-domain-policies:none\nreferrer-policy:strict-origin-when-cross-origin\nexpect-ct:enforce, max-age=86400\ncontent-security-policy:default-src 'none'; base-uri 'self'; block-all-mixed-content; child-src www.youtube-nocookie.com b5s.hackerone-ext-content.com; connect-src 'self' www.google-analytics.com errors.hackerone.net; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data: cover-photos.hackerone-user-content.com hackathon-photos.hackerone-user-content.com profile-photos.hackerone-user-content.com hackerone-us-west-2-production-attachments.s3.us-west-2.amazonaws.com; media-src 'self' hackerone-us-west-2-production-attachments.s3.us-west-2.amazonaws.com; script-src 'self' www.google-analytics.com; style-src 'self' 'unsafe-inline'; report-uri https://errors.hackerone.net/api/30/csp-report/?sentry_key=61c1e2f50d21487c97a071737701f598\ncf-cache-status:DYNAMIC\ncf-request-id:057b1ec8f80000e9bb1327d200000001\nserver:cloudflare\ncf-ray:5da533ee5820e9bb-BNE\n\n\n{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"}}}}",
  "is_match": true
}
```

**Splitting a large file into batches and running massprint over a batch**

this setting can be useful when you want to split the workload between multiple 
nodes or droplets.
```
massprint -i large-file.txt -t iis.yaml --num-batch 10 --batch 1
```

**Send notifications to a Slack webhook when discovering a match**
```
massprint -i targets.txt -t iis.yaml --notifications \
	--webhook "https://hooks.slack.com/services/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b29r" \
	--channel "#beep"
```

If you would like some more verbose output you can use the `-v` flag. There are
different levels of verbosity ranging from noisy to informational, most of the
time I just use `info`. This is all printing to stderr, so it won't be captured
in the results.
* `info`: General information like how many results each source returned.
* `debug`: Lots and lots of information about what's going on under the hood.
```
massprint -i targets.txt -t graphql.yaml -v info
```

### Common error - Too many open files
Massprint uses async concurrent http requests under the hood. If you encounter an error 
similar to *"Too many open files"* it means that there isn't enough available file descriptors on 
your system. You can fix this by increasing the hard and soft limits. There are 
lots of different guides available to increase the limits [but here is one for linux](https://www.tecmint.com/increase-set-open-file-limits-in-linux/). 

### A note on tuning the concurrency
Massprint will limit itself to `200` concurrent and parallel tasks, you can change this using
the `-c` flag. 

```
massprint -i tagets -t iis.yaml -c 500
``` 

### Thanks
[StaticFlow](https://twitter.com/_StaticFlow_) & [Nahamsec](https://twitter.com/NahamSec) 
For `gofingerprint` which was an inspiration to build my own version of a fingerprinting tool.

[0xatul](https://twitter.com/0xatul) For feedback and improvement ideas.

[ProjectDiscovery Team & Contributors](https://github.com/projectdiscovery/nuclei-templates/tree/master/technologies) 
For nuclei-templates which was a great reference for templates.



### Disclaimer
Developers have/has no responsibility or authority over any kind of:
* Legal or Law infringement by third parties and users.
* Malicious use capable of causing damage to third parties.
* Illegal or unlawful use of massprint.

