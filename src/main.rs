use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{self, BufRead};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    /// Run in foreground
    #[arg(short, long)]
    foreground: bool,

    /// PID file
    #[arg(short, long, default_value = "/var/run/dhcpleasemon.pid")]
    pid_file: String,

    /// Root directory
    #[arg(short, long, default_value = "/")]
    root_dir: String,

    /// Directory with trigger scripts
    #[arg(short, long, default_value = "/etc/dhcpleasemon")]
    scripts_dir: String,

    /// Directory monitored for lease changes
    #[arg(short, long, default_value = "/var/db/dhcpleased")]
    dhcp_lease_dir: String,

    /// Scan interval
    #[arg(short = 't', long, default_value_t = 1)]
    interval: u8,

    /// Interfaces to monitor
    #[arg(short, long)]
    interfaces: Vec<String>,
}

struct Monitor {
    args: Args,
    timestamps: HashMap<String, SystemTime>,
}

impl Monitor {
    fn new(args: Args) -> Self {
        Self {
            args,
            timestamps: HashMap::new(),
        }
    }

    /// Was the file modified since the last check?
    fn check_file_modified(&mut self, lease_file_path: &str) -> bool {
        println!("Checking: file {}", lease_file_path);

        let metadata = fs::metadata(&lease_file_path);
        let current_timestamp = metadata
            .expect("Unsupported platform")
            .modified()
            .expect("Error getting modification timestamp");

        let last_timestamp = self
            .timestamps
            .get(lease_file_path)
            .copied()
            .unwrap_or(SystemTime::from(UNIX_EPOCH));

        if current_timestamp > last_timestamp {
            // Store the new timestamp
            self.timestamps
                .insert(lease_file_path.to_string(), current_timestamp);

            return true;
        }

        false
    }

    /// Generates the lease file path
    fn get_lease_file_path(&self, iface_name: &str) -> String {
        let dhcp_lease_dir = &self.args.dhcp_lease_dir;
        format!("{dhcp_lease_dir}/{iface_name}")
    }

    fn get_trigger_script_path(&self, iface_name: &str) -> String {
        let trigger_scripts_path = &self.args.scripts_dir;
        format!("{trigger_scripts_path}/lease_trigger_{iface_name}")
    }

    /// Gets the default route for iface from netstat
    fn get_default_route(&self, iface_name: &str) -> Option<String> {
        let output = Command::new("netstat")
            .arg("-rn")
            .arg("-f")
            .arg("inet")
            .output()
            .expect("Failed to execute netstat");

        if !output.status.success() {
            println!(
                "Failed to obtain route (iface: {}): {}",
                iface_name,
                output.status.to_string()
            );
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() == 8 {
                let route_iface = cols[7];
                let route_dest = cols[0];
                if route_iface == iface_name && route_dest == "default" {
                    let route_ip = cols[1];
                    println!("{} {}", route_dest, route_ip);
                    return Some(route_ip.to_string());
                }
            }
        }

        return None;
    }

    /// Extracts the IP address from the lease file
    fn get_lease_ip_addr(&self, lease_file_path: &str) -> Option<String> {
        if let Ok(f) = File::open(lease_file_path) {
            let lines = io::BufReader::new(f).lines();
            for line in lines.flatten() {
                if let Some((ident, value)) = line.split_once(":") {
                    if ident.trim() == "ip" {
                        return Some(value.trim().to_string());
                    }
                }
            }
        }
        None
    }

    /// Execute the trigger script
    fn trigger_script(&mut self, iface_name: &str, lease_file_path: &str) {

        let default_route = self
            .get_default_route(iface_name)
            .unwrap_or(String::from(""));
        let lease_ip_addr = self
            .get_lease_ip_addr(lease_file_path)
            .unwrap_or(String::from(""));

        let trigger_script_path = self.get_trigger_script_path(iface_name);
        println!(
            "EXEC: {} {} -> script |{}| IP: {:?} Route: {}",
            iface_name, lease_file_path, trigger_script_path, lease_ip_addr, default_route
        );

        let output = Command::new(trigger_script_path)
            .env("DHCP_IFACE", iface_name)
            .env("DHCP_IP_ADDR", lease_ip_addr)
            .env("DHCP_IP_ROUTE", default_route)
            .output()
            .expect("Failed to execute trigger script");

        if !output.status.success() {
            println!("Trigger script execution was unsuccessful: {}", output.status.to_string());
        }
    }

    /// The main monitoring loop
    fn run(&mut self) {
        loop {
            for iface_name in self.args.interfaces.clone() {
                let lease_file_path = self.get_lease_file_path(&iface_name);
                if self.check_file_modified(&lease_file_path) {
                    println!("Was modified!");
                    self.trigger_script(&iface_name, &lease_file_path);
                }
            }
            sleep(Duration::new(self.args.interval.into(), 0));
            println!("{:?}", self.args);
            println!("hello");
        }
    }
}

fn main() {
    let args = Args::parse();
    let mut monitor = Monitor::new(args.clone());

    if args.interfaces.is_empty() {
        panic!("No interfaces to monitor");
    }

    monitor.run();
}

// EOF
