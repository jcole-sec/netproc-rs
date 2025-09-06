[![Build and Release](https://github.com/jcole-sec/netproc-rs/actions/workflows/release.yml/badge.svg)](https://github.com/jcole-sec/netproc-rs/actions/workflows/release.yml)
[![Dependabot Updates](https://github.com/jcole-sec/netproc-rs/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/jcole-sec/netproc-rs/actions/workflows/dependabot/dependabot-updates)


# netproc-rs

Rust implementation of NetProc (https://github.com/jcole-sec/netproc)

## Usage

Run with `--help` to see available options:

```
usage: netproc-rs(.exe) [-h] [-t | --tsv | --no-tsv] [-j | --json | --no-json] [-d | --display | --no-display] [-p | --public | --no-public] [--debug | --no-debug]

netproc is a tool that will:
    * Retrieve a list of all currently running processes
    * Display and/or log process details such as status, user, path, and parent process
    * Display and/or log network connection details related to each process

options:
  -h, --help            show this help message and exit
  -t, --tsv, --no-tsv   Enable output logging to tab-separate value (TSV) file.
                        File will be written to netproc_hostname_YYYYmmDD.HHMM.tsv

  -j, --json, --no-json
                        Enable output logging to a new-line delimited JSON file.
                        File will be written to netproc_hostname_YYYYmmDD.HHMM.json

  -d, --display, --no-display
                        Enable table display for process details.

  -p, --public, --no-public
                        Filter for processes with connections to or from public IPs.

  --debug, --no-debug   Enable additional console output for debugging purposes.
```

For support, contact https://github.com/jcole-sec.

Build with Cargo:

```
cargo build --release
sudo ./target/release/netproc-rs
```
