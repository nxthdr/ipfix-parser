#![no_main]

use ipfix_parser::{Decoder, DecoderConfig, Transport};
use libfuzzer_sys::{
    arbitrary::{Arbitrary, Unstructured},
    fuzz_target,
};

/// A Transport Session: several Messages decoded in order by one Decoder, so
/// that Templates defined (or withdrawn) in one Message affect the next ones.
/// This exercises the Template cache: redefinition, withdrawal (applied over
/// TCP/SCTP, ignored over UDP), expiry (UDP lifetime), and the `max_templates`
/// bound.
#[derive(Debug)]
struct Session<'a> {
    transport: Transport,
    template_lifetime: Option<u32>,
    messages: Vec<&'a [u8]>,
}

impl<'a> Arbitrary<'a> for Session<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let transport = *u.choose(&[
            Transport::Udp,
            Transport::Tcp,
            Transport::Sctp,
            Transport::File,
        ])?;
        let template_lifetime = match u.arbitrary::<bool>()? {
            true => Some(u.int_in_range(0..=600)?),
            false => None,
        };
        let count = u.int_in_range(1..=8)?;
        let mut messages = Vec::with_capacity(count);
        for _ in 0..count {
            let len = u.int_in_range(0..=4096)?;
            messages.push(u.bytes(len.min(u.len()))?);
        }
        Ok(Session {
            transport,
            template_lifetime,
            messages,
        })
    }
}

const MAX_TEMPLATES: usize = 16;

fuzz_target!(|session: Session| {
    let mut decoder = Decoder::with_config(DecoderConfig {
        transport: session.transport,
        template_lifetime: session.template_lifetime,
        max_templates: MAX_TEMPLATES,
        ..DecoderConfig::default()
    });
    for message in session.messages {
        let _ = decoder.decode_all(message);
        // The Template cache must stay bounded whatever the input
        assert!(decoder.template_count() <= MAX_TEMPLATES);
    }
});
