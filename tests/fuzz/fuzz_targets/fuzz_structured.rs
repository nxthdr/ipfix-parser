#![no_main]

use ipfix_parser::Decoder;
use libfuzzer_sys::{
    arbitrary::{Arbitrary, Unstructured},
    fuzz_target,
};

/// One IANA Information Element per abstract data type, so the fuzzer reaches
/// every value decoder (including the RFC 6313 structured data types)
const INFORMATION_ELEMENTS: &[u16] = &[
    70,  // mplsTopLabelStackSection (octetArray)
    4,   // protocolIdentifier (unsigned8)
    7,   // sourceTransportPort (unsigned16)
    10,  // ingressInterface (unsigned32)
    1,   // octetDeltaCount (unsigned64)
    515, // ipv6ExtensionHeadersFull (unsigned256)
    434, // mibObjectValueInteger (signed32)
    311, // samplingProbability (float64)
    276, // dataRecordsReliability (boolean)
    56,  // sourceMacAddress (macAddress)
    82,  // interfaceName (string)
    150, // flowStartSeconds (dateTimeSeconds)
    152, // flowStartMilliseconds (dateTimeMilliseconds)
    154, // flowStartMicroseconds (dateTimeMicroseconds)
    156, // flowStartNanoseconds (dateTimeNanoseconds)
    8,   // sourceIPv4Address (ipv4Address)
    27,  // sourceIPv6Address (ipv6Address)
    291, // basicList
    292, // subTemplateList
    293, // subTemplateMultiList
];

/// Private Enterprise Numbers of enterprise-specific fields, shared with the
/// generated RFC 5610 type records so that learned types get used
const ENTERPRISE_NUMBERS: &[u32] = &[1, 2];

/// Field lengths: reduced sizes, native sizes, and variable-length
const FIELD_LENGTHS: &[u16] = &[1, 2, 3, 4, 6, 8, 16, 32, 65535];

/// Template IDs drawn from a small range so Data Sets and nested lists
/// reference existing Templates
const TEMPLATE_IDS: std::ops::RangeInclusive<u16> = 256..=260;

#[derive(Debug)]
struct FieldSpec {
    id: u16,
    length: u16,
    enterprise_number: Option<u32>,
}

impl<'a> Arbitrary<'a> for FieldSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let id = *u.choose(INFORMATION_ELEMENTS)?;
        let length = *u.choose(FIELD_LENGTHS)?;
        // Mostly IANA, sometimes reverse (RFC 5103) or enterprise-specific
        let enterprise_number = match u.int_in_range(0..=9)? {
            0 => Some(29305),
            1 => Some(u.arbitrary()?),
            2 | 3 => Some(*u.choose(ENTERPRISE_NUMBERS)?),
            _ => None,
        };
        Ok(FieldSpec {
            id,
            length,
            enterprise_number,
        })
    }
}

#[derive(Debug)]
enum SetInput<'a> {
    Template {
        template_id: u16,
        fields: Vec<FieldSpec>,
    },
    OptionsTemplate {
        template_id: u16,
        scope_field_count: u16,
        fields: Vec<FieldSpec>,
    },
    Withdrawal {
        set_id: u16,
        template_id: u16,
    },
    Data {
        template_id: u16,
        content: &'a [u8],
    },
    /// RFC 5610 type record Options Template and one Data Set of type records
    TypeRecords {
        template_id: u16,
        records: Vec<TypeRecord<'a>>,
    },
}

/// An RFC 5610 Information Element type record
#[derive(Debug)]
struct TypeRecord<'a> {
    enterprise_number: u32,
    id: u16,
    data_type: u8,
    semantics: u8,
    name: &'a [u8],
}

impl<'a> Arbitrary<'a> for TypeRecord<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // PEN 0 (IANA) and 29305 (reverse) exercise the rejection rules
        let enterprise_number = *u.choose(&[0, 1, 2, 29305])?;
        let id = *u.choose(INFORMATION_ELEMENTS)?;
        // Slightly beyond the registries, to reach unknown values
        let data_type = u.int_in_range(0..=25)?;
        let semantics = u.int_in_range(0..=10)?;
        let len = u.int_in_range(0..=16)?;
        let name = u.bytes(len.min(u.len()))?;
        Ok(TypeRecord {
            enterprise_number,
            id,
            data_type,
            semantics,
            name,
        })
    }
}

impl<'a> Arbitrary<'a> for SetInput<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let fields = |u: &mut Unstructured<'a>| -> arbitrary::Result<Vec<FieldSpec>> {
            let n = u.int_in_range(1..=6)?;
            (0..n).map(|_| u.arbitrary()).collect()
        };
        Ok(match u.int_in_range(0..=6)? {
            0 => SetInput::Template {
                template_id: u.int_in_range(TEMPLATE_IDS)?,
                fields: fields(u)?,
            },
            1 => SetInput::OptionsTemplate {
                template_id: u.int_in_range(TEMPLATE_IDS)?,
                scope_field_count: u.int_in_range(0..=3)?,
                fields: fields(u)?,
            },
            2 => SetInput::Withdrawal {
                set_id: u.int_in_range(2..=3)?,
                // 2 and 3 are the "withdraw all" IDs
                template_id: *u.choose(&[2, 3, 256, 257, 258])?,
            },
            3 => {
                let n = u.int_in_range(1..=4)?;
                SetInput::TypeRecords {
                    template_id: u.int_in_range(TEMPLATE_IDS)?,
                    records: (0..n)
                        .map(|_| u.arbitrary())
                        .collect::<arbitrary::Result<_>>()?,
                }
            }
            _ => {
                let len = u.int_in_range(0..=256)?;
                SetInput::Data {
                    template_id: u.int_in_range(TEMPLATE_IDS)?,
                    content: u.bytes(len.min(u.len()))?,
                }
            }
        })
    }
}

impl SetInput<'_> {
    fn to_bytes(&self) -> Vec<u8> {
        fn specs(fields: &[FieldSpec], out: &mut Vec<u8>) {
            for f in fields {
                let raw = if f.enterprise_number.is_some() {
                    f.id | 0x8000
                } else {
                    f.id
                };
                out.extend_from_slice(&raw.to_be_bytes());
                out.extend_from_slice(&f.length.to_be_bytes());
                if let Some(pen) = f.enterprise_number {
                    out.extend_from_slice(&pen.to_be_bytes());
                }
            }
        }

        let (set_id, content) = match self {
            SetInput::Template {
                template_id,
                fields,
            } => {
                let mut c = template_id.to_be_bytes().to_vec();
                c.extend_from_slice(&(fields.len() as u16).to_be_bytes());
                specs(fields, &mut c);
                (2, c)
            }
            SetInput::OptionsTemplate {
                template_id,
                scope_field_count,
                fields,
            } => {
                let mut c = template_id.to_be_bytes().to_vec();
                c.extend_from_slice(&(fields.len() as u16).to_be_bytes());
                c.extend_from_slice(&scope_field_count.to_be_bytes());
                specs(fields, &mut c);
                (3, c)
            }
            SetInput::Withdrawal {
                set_id,
                template_id,
            } => {
                let mut c = template_id.to_be_bytes().to_vec();
                c.extend_from_slice(&0u16.to_be_bytes());
                (*set_id, c)
            }
            SetInput::Data {
                template_id,
                content,
            } => (*template_id, content.to_vec()),
            SetInput::TypeRecords {
                template_id,
                records,
            } => {
                // Options Template: privateEnterpriseNumber and
                // informationElementId as Scope Fields, then
                // informationElementDataType, informationElementSemantics and
                // informationElementName (variable-length)
                let mut out = Vec::new();
                let mut template = template_id.to_be_bytes().to_vec();
                template.extend_from_slice(&5u16.to_be_bytes()); // Field Count
                template.extend_from_slice(&2u16.to_be_bytes()); // Scope Field Count
                for (id, length) in [(346u16, 4u16), (303, 2), (339, 1), (344, 1), (341, 65535)] {
                    template.extend_from_slice(&id.to_be_bytes());
                    template.extend_from_slice(&length.to_be_bytes());
                }
                out.extend_from_slice(&3u16.to_be_bytes());
                out.extend_from_slice(&((template.len() + 4) as u16).to_be_bytes());
                out.extend_from_slice(&template);

                let mut data = Vec::new();
                for r in records {
                    data.extend_from_slice(&r.enterprise_number.to_be_bytes());
                    data.extend_from_slice(&r.id.to_be_bytes());
                    data.push(r.data_type);
                    data.push(r.semantics);
                    data.push(r.name.len() as u8);
                    data.extend_from_slice(r.name);
                }
                out.extend_from_slice(&template_id.to_be_bytes());
                out.extend_from_slice(&((data.len() + 4) as u16).to_be_bytes());
                out.extend_from_slice(&data);
                return out;
            }
        };

        let mut out = set_id.to_be_bytes().to_vec();
        out.extend_from_slice(&((content.len() + 4) as u16).to_be_bytes());
        out.extend_from_slice(&content);
        out
    }
}

/// Structured fuzzing input: well-framed IPFIX Messages with Templates over
/// every data type, followed by Data Sets with arbitrary content
#[derive(Debug)]
struct IpfixFuzzInput<'a> {
    messages: Vec<(u32, Vec<SetInput<'a>>)>,
}

impl<'a> Arbitrary<'a> for IpfixFuzzInput<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let n = u.int_in_range(1..=3)?;
        let mut messages = Vec::with_capacity(n);
        for _ in 0..n {
            // Two Observation Domains, to exercise Template scoping
            let domain = u.int_in_range(0..=1)?;
            let sets = u.int_in_range(1..=6)?;
            let sets = (0..sets)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?;
            messages.push((domain, sets));
        }
        Ok(IpfixFuzzInput { messages })
    }
}

fuzz_target!(|input: IpfixFuzzInput| {
    let mut decoder = Decoder::new();
    for (domain, sets) in &input.messages {
        let body: Vec<u8> = sets.iter().flat_map(|s| s.to_bytes()).collect();
        let mut data = Vec::with_capacity(body.len() + 16);
        data.extend_from_slice(&10u16.to_be_bytes());
        data.extend_from_slice(&((body.len() + 16).min(65535) as u16).to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes()); // Export Time
        data.extend_from_slice(&0u32.to_be_bytes()); // Sequence Number
        data.extend_from_slice(&domain.to_be_bytes());
        data.extend_from_slice(&body);
        let _ = decoder.decode(&data);
    }
});
