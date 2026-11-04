#![no_main]

use ipfix_parser::parse_message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary data as a self-contained IPFIX Message.
    // The parser should never panic, only return errors.

    // An IPFIX Message is at most 65535 octets (16-bit Length field)
    if data.len() > 65535 {
        return;
    }

    let _ = parse_message(data);
});
