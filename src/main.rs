use pcap_parser::*;
use pcap_parser::data::PacketData;
use pcap_parser::traits::PcapReaderIterator;
use regex::Regex;
use std::fs::File;
use std::process::{Command, Stdio};
use std::io;
use std::io::prelude::*;

#[macro_use]
extern crate dotenv_codegen;

fn pause() {
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    write!(stdout, "Waiting for call...").unwrap();
    stdout.flush().unwrap();

    let _ = stdin.read(&mut [0u8]).unwrap();
}

fn main() {
    let ip = dotenv!("IP_ADDRESS"); // Why this error? But it's not an error
    Command::new("pktmon").args(vec!["filter", "remove"]).stdout(Stdio::inherit()).spawn().unwrap().wait().unwrap();
    Command::new("pktmon").args(vec!["filter", "add", "-i", ip, "-t", "tcp", "-p", "80"]).stdout(Stdio::inherit()).spawn().unwrap().wait().unwrap();
    Command::new("pktmon").args(vec!["filter", "add", "-i", ip, "-t", "tcp", "-p", "443"]).stdout(Stdio::inherit()).spawn().unwrap().wait().unwrap();
    Command::new("pktmon").args(vec!["start", "--etw", "-c", "--pkt-size", "0"]).stdout(Stdio::inherit()).spawn().unwrap().wait().unwrap();

    pause();
    Command::new("pktmon").args(vec!["stop"]).stdout(Stdio::inherit()).spawn().unwrap().wait().unwrap();
    Command::new("pktmon").args(vec!["etl2pcap", "PktMon.etl", "-o", "capture.pcapng"]).stdout(Stdio::inherit()).spawn().unwrap().wait().unwrap();


    let file = File::open("capture.pcapng").unwrap();
    let input = read(file);

    println!("{:?}", &input);
}

fn parse_http(value: String) -> Result<Vec<u8>, &'static str> {
    let param_start = dotenv!("PARAM_START");
    let method_start = dotenv!("METHOD_START");
    if value.starts_with(param_start) {
        return match parse_data(value) {
            Ok(data) => Ok(data),
            Err(msg) => Err(msg)
        }
    } else if value.starts_with(method_start) {
        let regex = Regex::new(&format!("{}.*", param_start)).unwrap();
        let unescape = value.replace("\r", "").replace("\n", "");
        let captured_option = regex.find(&unescape);
        if let Some(captured) = captured_option {
            return match parse_data(String::from(captured.as_str())) {
                Ok(data) => Ok(data),
                Err(msg) => Err(msg)
            }
        }
    }
    Err("No Please")
}

fn parse_data(value: String) -> Result<Vec<u8>, &'static str> {
    let data_target = dotenv!("DATA_TARGET");
    let split_a = dotenv!("SPLIT_A");
    let split_b = dotenv!("SPLIT_B");
    let split_c = dotenv!("SPLIT_C");
    for component in value.split("&") {
        if component.starts_with(data_target) {
            let raw_value = component.replace(&format!("{}=", data_target), "");
            let answers = raw_value.split(split_a);
            let vec = answers.map(|data| {
                data.replace(split_b, "").replace(split_c, "").parse::<u8>().unwrap()
            }).collect::<Vec<u8>>();
            return Ok(vec)
        }
    }
    Err("No data found!")
}

fn read(file: File) -> Vec<u8> {
    let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
    let mut if_linktypes = Vec::new();
    let mut answers = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                        if_linktypes = Vec::new();
                    },
                    PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                        if_linktypes.push(idb.linktype);
                    },
                    PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                        assert!((epb.if_id as usize) < if_linktypes.len());
                        let linktype = if_linktypes[epb.if_id as usize];
                        let res = pcap_parser::data::get_packetdata(epb.data, linktype, epb.caplen as usize);
                        let data = res.unwrap();
                        match data {
                            PacketData::L2(data) => {
                                // let string_data = std::str::from_utf8(data_vec.as_slice()).unwrap_or("Not A String");
                                let mut data_vec = data.to_vec();
                                data_vec.drain(0..54);
                                if let Ok(string_value) = std::str::from_utf8(data_vec.as_slice()) {
                                    if let Ok(data) = parse_http(String::from(string_value)) {
                                        answers = data;
                                    }
                                };
                            },
                            _ => {}
                        };
                    },
                    _ => {}
                }
                reader.consume(offset);
            },
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            },
            Err(e) => panic!("Error while reading: {:?}", e),
        }
    }
    answers
}