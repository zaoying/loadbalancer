use std::io::Error;

use bytes::BytesMut;
use aya::maps::AsyncPerfEventArray;
use aya::programs::{CgroupSkb, CgroupSkbAttachType};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use loadbalancer_common::Payload;
use log::{warn, info};
use tokio::{signal, task};
use rlimit::Resource;

const DEFAULT_SOFT_LIMIT: u64 = 4 * 1024 * 1024;
const DEFAULT_HARD_LIMIT: u64 = 8 * 1024 * 1024;

pub fn set_relimit() -> Result<(), Error>{
    Resource::MEMLOCK.set(DEFAULT_SOFT_LIMIT, DEFAULT_HARD_LIMIT)
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup/unified")]
    cgroup_path: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/loadbalancer"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/loadbalancer"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    set_relimit().unwrap();
    let program: &mut CgroupSkb = bpf.program_mut("loadbalancer").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup, CgroupSkbAttachType::Egress)?;

    let tcp_payload_map = bpf.take_map("PAYLOAD").expect("can not find map: PAYLOAD");
    let mut payloads = AsyncPerfEventArray::try_from(tcp_payload_map)?;

    for cpu_id in online_cpus()? {
        let mut buf = payloads.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const Payload;
                    let data = unsafe { ptr.read_unaligned() };
                    let payload = String::from_utf8_lossy(&data.buff[..data.len]);
                    info!("payload: {}", payload);
                }
            }
        });
    }

    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
