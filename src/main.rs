use pcap_parser::*;
use pcap_parser::data::PacketData;
use pcap_parser::traits::PcapReaderIterator;
use regex::Regex;
use winapi::um::winuser::{SW_NORMAL, SW_SHOWDEFAULT};
use std::ffi::CString;
use std::fs::File;
use std::process::{Command, Stdio};
use std::io;
use std::io::prelude::*;
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    nocapture: bool,

    #[clap(short, long, default_value_t = String::from("capture.pcapng"))]
    file: String
}

fn pause() {
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    write!(stdout, "Waiting for call...").unwrap();
    stdout.flush().unwrap();

    let _ = stdin.read(&mut [0u8]).unwrap();
}

fn capture_packet(default: &str) {
    let ip = "115.68.13.56"; 
    Command::new("pktmon").args(vec!["filter", "remove"]).stdout(Stdio::inherit()).spawn().unwrap().wait().unwrap();
    Command::new("pktmon").args(vec!["filter", "add", "-i", ip, "-t", "tcp", "-p", "80"]).stdout(Stdio::inherit()).spawn().unwrap().wait().unwrap();
    Command::new("pktmon").args(vec!["filter", "add", "-i", ip, "-t", "tcp", "-p", "443"]).stdout(Stdio::inherit()).spawn().unwrap().wait().unwrap();
    Command::new("pktmon").args(vec!["start", "--etw", "-c", "--pkt-size", "0"]).stdout(Stdio::inherit()).spawn().unwrap().wait().unwrap();

    pause();
    Command::new("pktmon").args(vec!["stop"]).stdout(Stdio::inherit()).spawn().unwrap().wait().unwrap();
    Command::new("pktmon").args(vec!["etl2pcap", "PktMon.etl", "-o", default]).stdout(Stdio::inherit()).spawn().unwrap().wait().unwrap();
}

fn elevate() {
    println!("Reached");
    use winapi::um::shellapi::ShellExecuteA;
    use winapi::um::wincon::GetConsoleWindow;
    let runas = CString::new("runas").unwrap();
    let program = CString::new(std::env::current_exe().unwrap().as_os_str().to_str().unwrap()).unwrap();
    let args = CString::new(std::env::args().collect::<Vec<String>>()[1..].join(" ")).unwrap();

    println!("{}", args.to_str().unwrap());

    unsafe {
        ShellExecuteA(
            GetConsoleWindow(), 
            runas.as_ptr(), 
            program.as_ptr(), 
            args.as_ptr(), 
            std::ptr::null_mut(), 
            SW_NORMAL);
    };
}

fn main() {
    use device_query::{DeviceQuery, DeviceState, Keycode};
    use is_elevated::is_elevated;

    if !is_elevated() {
        elevate();
        return;
    }

    let args = Args::parse();

    if !args.nocapture {
        capture_packet(args.file.as_str());
    }

    let file = File::open(args.file.as_str()).unwrap();
    let input = read(file);

    println!("{:?}", &input);

    let device_state = DeviceState::new();
    loop {
        let keys: Vec<Keycode> = device_state.get_keys();
        if keys.iter().any(|key| { key == &Keycode::LControl }) && keys.iter().any(|key| { key == &Keycode::Q }) {
            tell(&input);
            break;
        }
    }
}

fn parse_http(value: String) -> Result<Vec<u8>, &'static str> {
    let param_start = "mem_seq";
    let method_start = "POST /Player/StudyResultSave";
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
    for component in value.split("&") {
        if component.starts_with("itemsAnswer") {
            let raw_value = component.replace("itemsAnswer=", "");
            let answers = raw_value.split("%40%23%400%40%2F%40");
            let vec = answers.map(|data| {
                data.replace("0%40%2F%40", "").replace("%40%23%40", "").parse::<u8>().unwrap()
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

fn tell(answers: &Vec<u8>) {
    use soloud::*;

    let one = include_bytes!("../assets/one.mp3");
    let two = include_bytes!("../assets/two.mp3");
    let three = include_bytes!("../assets/three.mp3");
    let four = include_bytes!("../assets/four.mp3");
    let five = include_bytes!("../assets/five.mp3");

    for answer in answers.iter() {
        let sl = Soloud::default().unwrap();
        let mut wav = audio::Wav::default();
        
        wav.load_mem(match answer {
            1 => one,
            2 => two,
            3 => three,
            4 => four,
            5 => five,
            _ => panic!("Error!")
        }).unwrap();

        sl.play(&wav);
        while sl.voice_count() > 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        std::thread::sleep(std::time::Duration::from_millis(1500));
    }
}