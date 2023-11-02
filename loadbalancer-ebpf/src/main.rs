#![no_std]
#![no_main]

use aya_bpf::{
    macros::{cgroup_skb, map},
    programs::SkBuffContext, maps::PerfEventArray};
use aya_log_ebpf::{info, error};

use loadbalancer_common::Payload;
use network_types::{ip::{IpProto, Ipv4Hdr}, tcp::TcpHdr};

const ETH_P_IP: u32 = 8;

#[map(name = "PAYLOAD")]
static mut PAYLOAD: PerfEventArray<Payload> = PerfEventArray::with_max_entries(1024, 0);

#[cgroup_skb(name="loadbalancer")]
pub fn loadbalancer(ctx: SkBuffContext) -> i32 {
    match try_loadbalancer(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_loadbalancer(ctx: SkBuffContext) -> Result<i32, ()> {
    let protocol = unsafe { (*ctx.skb.skb).protocol };
    if protocol != ETH_P_IP {
        return Ok(1);
    }

    let ip = ctx.load::<Ipv4Hdr>(0).map_err(|_| ())?;
    let src_ip = u32::from_be(ip.src_addr);
    let dest_ip = u32::from_be(ip.dst_addr);

    match ip.proto {
        IpProto::Tcp => {}
        _ => return Ok(1),
    }

    let tcp  = ctx.load::<TcpHdr>(Ipv4Hdr::LEN).map_err(|_| ())?;
    let src_port = u16::from_be(tcp.source);
    let dest_port = u16::from_be(tcp.dest);

    if src_port == 80 || src_port == 443 || dest_port == 80 || dest_port == 443 {
        info!(&ctx, "source: {:i}:{}, dest: {:i}:{}", src_ip, src_port, dest_ip, dest_port);

        let start = Ipv4Hdr::LEN + TcpHdr::LEN;
        let end = ctx.len() as usize;
        if end - start <= 0 {
            info!(&ctx, "no payload");
            return Ok(1);
        }
        
        let mut buff = [0 as u8; 128];
        match ctx.load_bytes(start, &mut buff) {
            Ok(size) => unsafe {
                PAYLOAD.output(&ctx, &Payload{buff, len: size}, 0)
            }
            Err(err) => error!(&ctx, "load bytes failed: {}", err)
        }
    }
    Ok(1)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
