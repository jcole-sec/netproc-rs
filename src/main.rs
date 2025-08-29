use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};
use dns_lookup::lookup_addr;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use rayon::{prelude::*, ThreadPoolBuilder};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;

use chrono::Local;
use hostname::get;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
struct ConnRow {
    process_name: String,
    pid: i32,
    parent: String, // "parent_name (ppid)" or just "ppid"
    local_port: u16,
    remote_host: String, // reverse DNS or "-"
    remote_ip: String,
    remote_port: u16,
    cmdline: String,
}

#[derive(Parser, Debug)]
#[command(
    name = "netproc.exe",
    about = "netproc is a tool that will:\n    * Retrieve a list of all currently running processes\n    * Display and/or log process details such as status, user, path, and parent process\n    * Display and/or log network connection details related to each process",
    after_help = "For support, contact https://github.com/jcole-sec."
)]
struct Args {
    /// Enable output logging to tab-separate value (TSV) file.
    #[arg(short = 't', long = "tsv", action = ArgAction::SetTrue)]
    #[arg(long = "no-tsv", action = ArgAction::SetFalse)]
    tsv: bool,

    /// Enable output logging to a new-line delimited JSON file.
    #[arg(short = 'j', long = "json", action = ArgAction::SetTrue)]
    #[arg(long = "no-json", action = ArgAction::SetFalse)]
    json: bool,

    /// Enable table display for process details.
    #[arg(short = 'd', long = "display", action = ArgAction::SetTrue, default_value_t = true)]
    #[arg(long = "no-display", action = ArgAction::SetFalse)]
    display: bool,

    /// Filter for processes with connections to or from public IPs.
    #[arg(short = 'p', long = "public", action = ArgAction::SetTrue)]
    #[arg(long = "no-public", action = ArgAction::SetFalse)]
    public: bool,

    /// Enable additional console output for debugging purposes.
    #[arg(long = "debug", action = ArgAction::SetTrue)]
    #[arg(long = "no-debug", action = ArgAction::SetFalse)]
    debug: bool,
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_unspecified())
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Collect rows per-OS
    let mut rows = collect_rows()?;

    // Filter for public IPs before expensive DNS work
    if args.public {
        rows.retain(|r| {
            r.remote_ip
                .parse::<IpAddr>()
                .map(is_public_ip)
                .unwrap_or(false)
        });
    }

    // Best-effort reverse DNS, deduped
    let unique_ips: Vec<IpAddr> = rows
        .iter()
        .filter_map(|r| r.remote_ip.parse::<IpAddr>().ok())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let pb = ProgressBar::new(unique_ips.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} lookups")?
            .progress_chars("=>-"),
    );

    // Limit DNS lookup concurrency to avoid overwhelming resolver
    let pool = ThreadPoolBuilder::new()
        .num_threads(32)
        .build()
        .context("building DNS thread pool")?;

    let cache: HashMap<IpAddr, String> = pool.install(|| {
        unique_ips
            .par_iter()
            .progress_with(pb.clone())
            .map(|ip| {
                let name = lookup_addr(ip)
                    .map(|s| s.trim_end_matches('.').to_string())
                    .unwrap_or_else(|_| "-".to_string());
                (*ip, name)
            })
            .collect()
    });
    pb.finish_with_message("DNS lookups complete");

    for r in rows.iter_mut() {
        r.remote_host = r
            .remote_ip
            .parse::<IpAddr>()
            .ok()
            .and_then(|ip| cache.get(&ip).cloned())
            .unwrap_or_else(|| "-".into());
    }

    // Sort for stable, readable output
    rows.sort_by(|a, b| {
        a.pid
            .cmp(&b.pid)
            .then(a.remote_ip.cmp(&b.remote_ip))
            .then(a.remote_port.cmp(&b.remote_port))
    });

    if args.debug {
        eprintln!("{} rows after processing", rows.len());
    }

    if args.display {
        print_table(&rows);
    }

    if args.tsv || args.json {
        let hostname = get().unwrap_or_default();
        let hostname = hostname.to_string_lossy();
        let timestamp = Local::now().format("%Y%m%d.%H%M");

        if args.tsv {
            let fname = format!("netproc_{}_{}.tsv", hostname, timestamp);
            let mut file = File::create(&fname)?;
            writeln!(
                file,
                "process_name\tpid\tparent\tlocal_port\tremote_host\tremote_ip\tremote_port\tcmdline"
            )?;
            for r in &rows {
                writeln!(
                    file,
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    r.process_name,
                    r.pid,
                    r.parent,
                    r.local_port,
                    r.remote_host,
                    r.remote_ip,
                    r.remote_port,
                    r.cmdline
                )?;
            }
            if args.debug {
                eprintln!("Wrote TSV to {fname}");
            }
        }

        if args.json {
            let fname = format!("netproc_{}_{}.json", hostname, timestamp);
            let mut file = File::create(&fname)?;
            for r in &rows {
                serde_json::to_writer(&mut file, r)?;
                writeln!(file)?;
            }
            if args.debug {
                eprintln!("Wrote JSON to {fname}");
            }
        }
    }

    Ok(())
}

fn print_table(rows: &[ConnRow]) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Process Name").fg(Color::Green),
            Cell::new("Process ID").fg(Color::Green),
            Cell::new("Parent Process").fg(Color::Green),
            Cell::new("Local Port").fg(Color::Green),
            Cell::new("Remote Host Name").fg(Color::Green),
            Cell::new("Remote IP").fg(Color::Green),
            Cell::new("Remote Port").fg(Color::Green),
            Cell::new("Process Command Line").fg(Color::Green),
        ]);

    for r in rows {
        table.add_row(vec![
            Cell::new(r.process_name.as_str()),
            Cell::new(&r.pid.to_string()),
            Cell::new(r.parent.as_str()),
            Cell::new(&r.local_port.to_string()),
            Cell::new(r.remote_host.as_str()),
            Cell::new(r.remote_ip.as_str()),
            Cell::new(&r.remote_port.to_string()),
            Cell::new(r.cmdline.as_str()),
        ]);
    }

    println!("{table}");
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use procfs::{
        net::{tcp, tcp6, TcpState},
        process::{all_processes, FDTarget},
    };
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    struct InodeConn {
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
    }

    pub fn collect_rows() -> Result<Vec<ConnRow>> {
        // Build inode -> connection map from /proc/net/tcp{,6}
        let inode_to_conn = build_inode_map()?;
 
        // Collect all processes into a Vec to iterate over it multiple times.
        let processes: Vec<_> = all_processes()
            .context("listing processes")?
            .collect::<Result<_, _>>()?;

        // pid -> name (for parent display)
        let pid_to_name: HashMap<i32, String> = processes
            .iter()
            .filter_map(|p| p.stat().ok())
            .map(|s| (s.pid, s.comm.clone())) // Correctly uses `s` from the map
            .collect();

        // Walk processes; map their FDs to socket inodes
        let mut rows: Vec<ConnRow> = Vec::with_capacity(inode_to_conn.len());
        for pr in &processes { // Correctly iterates over the collected Vec
            let stat = match pr.stat() {
                Ok(s) => s,
                Err(_) => continue,
            };
            let pid = stat.pid;
            let proc_name = stat.comm.clone();
            let ppid = stat.ppid;

            let cmdline = pr
                .cmdline()
                .ok()
                .and_then(|v| {
                    if v.is_empty() {
                        None
                    } else {
                        Some(v.join(" "))
                    }
                })
                .unwrap_or_else(|| format!("[{}]", proc_name));

            let parent = match pid_to_name.get(&ppid) {
                Some(pname) => format!("{pname} ({ppid})"),
                None => format!("{ppid}"),
            };

            let fds = match pr.fd() {
                Ok(v) => v,
                Err(_) => continue,
            };

            for fd in fds {
                let Ok(fdinfo) = fd else { continue };
                if let FDTarget::Socket(inode) = fdinfo.target {
                    if let Some(c) = inode_to_conn.get(&inode) {
                        rows.push(ConnRow {
                            process_name: proc_name.clone(),
                            pid,
                            parent: parent.clone(),
                            local_port: c.local_port,
                            remote_host: String::new(), // fill after DNS
                            remote_ip: c.remote_ip.to_string(),
                            remote_port: c.remote_port,
                            cmdline: cmdline.clone(),
                        });
                    }
                }
            }
        }

        Ok(rows)
    }

    fn build_inode_map() -> Result<HashMap<u64, InodeConn>> {
        let mut map: HashMap<u64, InodeConn> = HashMap::new();

        for e in tcp()
            .context("reading /proc/net/tcp")?
            .into_iter()
            .chain(tcp6().context("reading /proc/net/tcp6")?.into_iter())
        {
            if is_useful_state(e.state)
                && is_real_remote(e.remote_address.ip(), e.remote_address.port())
            {
                map.insert(
                    e.inode,
                    InodeConn {
                        local_port: e.local_address.port(),
                        remote_ip: e.remote_address.ip(),
                        remote_port: e.remote_address.port(),
                    },
                );
            }
        }
        Ok(map)
    }

    fn is_useful_state(state: TcpState) -> bool {
        matches!(
            state,
            TcpState::Established
                | TcpState::SynSent
                | TcpState::SynRecv
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::LastAck
                | TcpState::Closing
        )
    }

    fn is_real_remote(ip: IpAddr, port: u16) -> bool {
        if port == 0 {
            return false;
        }
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                !(o == [0, 0, 0, 0] || o[0] == 127)
            }
            IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_loopback()),
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
    use sysinfo::{Pid, System};

    pub fn collect_rows() -> Result<Vec<ConnRow>> {
        // Enumerate TCP sockets (IPv4+IPv6) with owning PIDs
        let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let sockets = get_sockets_info(af, ProtocolFlags::TCP).context("enumerating sockets")?;

        // Snapshot of running processes
        let mut sys = System::new_all();
        sys.refresh_all();

        let mut rows = Vec::with_capacity(sockets.len());

        for si in sockets {
            let (local_port, remote_ip, remote_port) = match si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(t) => (t.local_port, t.remote_addr, t.remote_port),
                _ => continue,
            };

            // Ignore listeners and local/unspecified remotes
            if remote_port == 0 || remote_ip.is_loopback() || remote_ip.is_unspecified() {
                continue;
            }

            // One socket can be associated with multiple PIDs on Windows
            for pid_u32 in si.associated_pids {
                let pid = Pid::from_u32(pid_u32);

                if let Some(p) = sys.process(pid) {
                    let name = p.name().to_string_lossy().to_string();

                    let cmdline = if p.cmd().is_empty() {
                        format!("[{}]", name)
                    } else {
                        p.cmd()
                            .iter()
                            .map(|s| s.to_string_lossy())
                            .collect::<Vec<_>>()
                            .join(" ")
                    };

                    let parent_display = if let Some(ppid) = p.parent() {
                        if let Some(pp) = sys.process(ppid) {
                            format!("{} ({})", pp.name().to_string_lossy(), ppid.as_u32())
                        } else {
                            format!("{}", ppid.as_u32())
                        }
                    } else {
                        "-".to_string()
                    };

                    rows.push(ConnRow {
                        process_name: name,
                        pid: pid.as_u32() as i32,
                        parent: parent_display,
                        local_port,
                        remote_host: String::new(), // filled by reverse DNS later
                        remote_ip: remote_ip.to_string(),
                        remote_port,
                        cmdline,
                    });
                } else {
                    // Process ended between snapshots—still report the socket
                    rows.push(ConnRow {
                        process_name: "-".into(),
                        pid: pid.as_u32() as i32,
                        parent: "-".into(),
                        local_port,
                        remote_host: String::new(),
                        remote_ip: remote_ip.to_string(),
                        remote_port,
                        cmdline: "-".into(),
                    });
                }
            }
        }

        Ok(rows)
    }
}

#[cfg(target_os = "linux")]
use platform::collect_rows;

#[cfg(target_os = "windows")]
use platform::collect_rows;

// Fallback for other OSes
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn collect_rows() -> Result<Vec<ConnRow>> {
    anyhow::bail!("Unsupported OS")
}
