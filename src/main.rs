#![feature(duration_extras)] //enables Duration.subsec_millis

extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate pnet;
#[macro_use]
extern crate structopt;
extern crate time;

use structopt::StructOpt;
use std::process;
use failure::Error;

use pnet::datalink::MacAddr;
use pnet::datalink;
use pnet::packet::ethernet;
use pnet::packet::Packet;

use std::time::{Duration, SystemTime};
use time::precise_time_ns;

#[derive(StructOpt, Debug)]
#[structopt(name = "annoyr", about = "an ethernet packet spammer")]
struct Conf {
    //mandatory
    #[structopt(name = "iface")]
    iface: String,
    #[structopt(name = "dst mac")]
    /// Files to process
    dstmac: String,

    //opts
    #[structopt(short = "d", long = "duration", default_value = "10")]
    dur: u64,

    #[structopt(short = "i", long = "itt", help = "itt in ms", default_value = "100")]
    itt: u64,

    #[structopt(short = "e", long = "ethertype", help = "itt in ms, defaults to 0x0801 i.e.",
                default_value = "2049")]
    ethtype: u16,
}

fn run(conf: &Conf) -> Result<(), Error> {
    let dst: MacAddr = conf.dstmac.parse().expect("Wrong Mac");
    let iface = datalink::interfaces()
        .into_iter()
        .filter(|ref iface| iface.name == conf.iface)
        .nth(0)
        .unwrap();

    println!(
        "Opening {:?} to send Packets to {} every {}ms for {}s",
        iface.name, conf.dstmac, conf.itt, conf.dur
    );

    let (mut tx, _) = match datalink::channel(&iface, datalink::Config::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    // prep the packet
    let template = ethernet::Ethernet {
        destination: dst,
        source: dst.clone(), //this will be changed later
        ethertype: ethernet::EtherType::new(conf.ethtype),
        payload: (1u8..19u8).collect::<Vec<u8>>(),
    };

    let start = SystemTime::now();
    let end = start + Duration::from_secs(conf.dur);
    let mut packet_count = 0u64;

    while SystemTime::now() < end {
        // this will overflow but the 1 prevents all zero macs, which is meh
        let addr = packet_count * 10 + 1;

        let (b1, b2, b3, b4, b5) = (
            (addr >> 36) & 0xFF,
            (addr >> 24) & 0xFF,
            (addr >> 16) & 0xFF,
            (addr >> 8) & 0xFF,
            (addr >> 0) & 0xFF,
        );
        let addr_string = format!("00:{:X}:{:X}:{:X}:{:X}:{:X}", b1, b2, b3, b4, b5);
        let src: MacAddr = addr_string
            .parse()
            .expect("Failed to create faked src addr");

        // OPT: there is probably a more efficient way of making these
        let mut packet_to_tx = ethernet::MutableEthernetPacket::owned(vec![0u8; 64])
            .expect("Failed to create faked packet");
        packet_to_tx.populate(&template);
        packet_to_tx.set_source(src);

        match tx.send_to(
            packet_to_tx.packet(), // dump the underlying vec
            None,
        ) {
            Some(Ok(())) => (),
            Some(Err(e)) => println!("Failed to send because {}", e),
            None => (),
        }

        //unfortunately this must be done with a busyloop
        //because thread::sleep(itt) sleeps at least 5ms
        let t_stop = precise_time_ns() + 1_000_000 * conf.itt;
        while precise_time_ns() < t_stop {}

        packet_count += 1;
    }
    let real_duration = start.elapsed().unwrap();
    let estimated_packets =
        (real_duration.as_secs() * 1_000 + real_duration.subsec_millis() as u64) / conf.itt;

    println!(
        "Sent {}/{} packets in {:?}s",
        packet_count,
        estimated_packets,
        start.elapsed()?.as_secs()
    );
    Ok(())
}

fn main() {
    let conf = Conf::from_args();
    match run(&conf) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    }
    process::exit(0)
}
