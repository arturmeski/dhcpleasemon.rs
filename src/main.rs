use clap::Parser;
use std::thread::sleep;
use std::time::Duration;

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

struct Monitor{
    args: Args,
}

impl Monitor {
    fn new(args: Args) -> Self {
        Self { args }
    }

    fn check_iface(&self, iface_name: String) {
        println!("Checking: {}", iface_name);
    }

    fn run(&mut self) {

        loop {
            for iface in &self.args.interfaces {
                self.check_iface(iface.to_string());
            }
            sleep(Duration::new(self.args.interval.into(), 0));
            println!("{:?}", self.args);
            println!("hello");
        }
    }
}

fn main() {
    let args = Args::parse();
    // let mut monitor = Monitor::new(&args);
    let mut monitor = Monitor::new(args.clone());

    if args.interfaces.is_empty() {
        eprintln!("No interfaces to monitor");
    }

    monitor.run();
}

// EOF
