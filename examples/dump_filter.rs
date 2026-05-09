//! Print the BPF program produced by a filter expression.
//!
//! Usage:  cargo run --example dump_filter -- "tcp port 80"
//!         cargo run --example dump_filter -- --ebpf "tcp port 80"

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let ebpf = args
        .iter()
        .position(|a| a == "--ebpf")
        .map(|i| {
            args.remove(i);
            i
        })
        .is_some();
    let filter = args
        .into_iter()
        .next()
        .unwrap_or_else(|| "tcp port 80".to_owned());

    let target = if ebpf {
        pktbaffle::Target::Extended
    } else {
        pktbaffle::Target::Classic
    };

    match pktbaffle::compile(&filter, pktbaffle::LinkType::Ethernet, target) {
        Ok(prog) => {
            eprintln!(
                "Filter: {filter:?}  ({} instructions)  target={target:?}",
                prog.len()
            );
            match &prog {
                pktbaffle::Program::Classic(p) => print!("{p}"),
                pktbaffle::Program::Extended(p) => {
                    for (i, insn) in p.instructions().iter().enumerate() {
                        println!(
                            "({i:03}) code=0x{:02x} regs=0x{:02x} off={} imm={}",
                            insn.code, insn.regs, insn.off, insn.imm
                        );
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
