//! Fuzz the full compile pipeline: lex → parse → codegen.
//!
//! The compiler must never panic regardless of input — it should always
//! return Ok(program) or Err(…).  Any panic is a bug.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pktbaffle::{compile, LinkType, Target};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Exercise all three link types and both targets — none may panic.
    for &link in &[LinkType::Ethernet, LinkType::RawIp, LinkType::LinuxSll] {
        let _ = compile(s, link, Target::Classic);
        let _ = compile(s, link, Target::Extended);
    }
});
