//! One test per IANA abstract data type (RFC 7011 Section 6, RFC 7012 Section 3.1)
//!
//! Each test decodes a real IANA Information Element of that type. The IANA
//! registry has no element of type float32, signed8, signed16 or signed64 yet;
//! signed decoding is covered by `mibObjectValueInteger` (signed32).

use super::helpers::{decode_one, varlen, VARIABLE};
use ipfix_parser::models::{MacAddress, NtpTimestamp};
use ipfix_parser::FieldValue;
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn test_octet_array() {
    // mplsTopLabelStackSection (70)
    assert_eq!(
        decode_one((70, 3, None), &[0x01, 0x02, 0x03]),
        FieldValue::OctetArray(vec![0x01, 0x02, 0x03])
    );
}

#[test]
fn test_unsigned8() {
    // protocolIdentifier (4)
    assert_eq!(decode_one((4, 1, None), &[6]), FieldValue::Unsigned(6));
}

#[test]
fn test_unsigned16() {
    // sourceTransportPort (7)
    assert_eq!(
        decode_one((7, 2, None), &[0x01, 0xBB]),
        FieldValue::Unsigned(443)
    );
}

#[test]
fn test_unsigned32() {
    // ingressInterface (10)
    assert_eq!(
        decode_one((10, 4, None), &[0x00, 0x01, 0x00, 0x00]),
        FieldValue::Unsigned(65536)
    );
}

#[test]
fn test_unsigned64() {
    // octetDeltaCount (1)
    assert_eq!(
        decode_one((1, 8, None), &u64::MAX.to_be_bytes()),
        FieldValue::Unsigned(u64::MAX)
    );
}

#[test]
fn test_unsigned64_reduced_size() {
    // RFC 7011 Section 6.2: an unsigned64 can be reduced to 1..7 octets
    assert_eq!(
        decode_one((1, 4, None), &[0x00, 0x00, 0x05, 0xDC]),
        FieldValue::Unsigned(1500)
    );
    assert_eq!(decode_one((1, 1, None), &[0x2A]), FieldValue::Unsigned(42));
}

#[test]
fn test_unsigned_longer_than_type_is_raw() {
    // protocolIdentifier is unsigned8: 2 octets is not a valid encoding
    assert_eq!(
        decode_one((4, 2, None), &[0x00, 0x06]),
        FieldValue::Raw(vec![0x00, 0x06])
    );
}

#[test]
fn test_unsigned256() {
    // ipv6ExtensionHeadersFull (515), reduced-size to 2 octets
    let mut expected = [0u8; 32];
    expected[30] = 0x80;
    expected[31] = 0x01;
    assert_eq!(
        decode_one((515, 2, None), &[0x80, 0x01]),
        FieldValue::Unsigned256(expected)
    );
}

#[test]
fn test_signed32() {
    // mibObjectValueInteger (434)
    assert_eq!(
        decode_one((434, 4, None), &(-123_456i32).to_be_bytes()),
        FieldValue::Signed(-123_456)
    );
}

#[test]
fn test_signed_reduced_size_is_sign_extended() {
    // RFC 7011 Errata 7875: leading ones are dropped for negative values
    assert_eq!(decode_one((434, 1, None), &[0xFF]), FieldValue::Signed(-1));
    assert_eq!(
        decode_one((434, 2, None), &[0xFF, 0x38]),
        FieldValue::Signed(-200)
    );
    assert_eq!(decode_one((434, 1, None), &[0x7F]), FieldValue::Signed(127));
}

#[test]
fn test_float64() {
    // samplingProbability (311)
    assert_eq!(
        decode_one((311, 8, None), &0.25f64.to_be_bytes()),
        FieldValue::Float64(0.25)
    );
}

#[test]
fn test_float64_reduced_to_float32() {
    // RFC 7011 Section 6.2: float64 may be encoded as float32
    assert_eq!(
        decode_one((311, 4, None), &0.5f32.to_be_bytes()),
        FieldValue::Float64(0.5)
    );
}

#[test]
fn test_boolean() {
    // dataRecordsReliability (276): RFC 7011 Section 6.1.5, 1 = true, 2 = false
    assert_eq!(decode_one((276, 1, None), &[1]), FieldValue::Boolean(true));
    assert_eq!(decode_one((276, 1, None), &[2]), FieldValue::Boolean(false));
}

#[test]
fn test_boolean_invalid_is_raw() {
    assert_eq!(decode_one((276, 1, None), &[0]), FieldValue::Raw(vec![0]));
}

#[test]
fn test_mac_address() {
    // sourceMacAddress (56)
    let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let value = decode_one((56, 6, None), &mac);
    assert_eq!(value, FieldValue::MacAddress(MacAddress::new(mac)));
    if let FieldValue::MacAddress(m) = value {
        assert_eq!(m.to_string(), "00:11:22:33:44:55");
    }
}

#[test]
fn test_string_variable_length() {
    // interfaceName (82)
    assert_eq!(
        decode_one((82, VARIABLE, None), &varlen(b"eth0")),
        FieldValue::String("eth0".to_string())
    );
}

#[test]
fn test_string_three_octet_length() {
    // RFC 7011 Section 7: lengths >= 255 use 255 followed by a 2-octet length
    let long = "x".repeat(300);
    let encoded = varlen(long.as_bytes());
    assert_eq!(encoded[0], 255);
    assert_eq!(
        decode_one((82, VARIABLE, None), &encoded),
        FieldValue::String(long)
    );
}

#[test]
fn test_string_three_octet_length_short_value() {
    // The 3-octet form MAY also be used for lengths < 255
    let mut encoded = vec![255, 0x00, 0x02];
    encoded.extend_from_slice(b"lo");
    assert_eq!(
        decode_one((82, VARIABLE, None), &encoded),
        FieldValue::String("lo".to_string())
    );
}

#[test]
fn test_string_invalid_utf8_is_raw() {
    assert_eq!(
        decode_one((82, 2, None), &[0xFF, 0xFE]),
        FieldValue::Raw(vec![0xFF, 0xFE])
    );
}

#[test]
fn test_date_time_seconds() {
    // flowStartSeconds (150)
    assert_eq!(
        decode_one((150, 4, None), &1_700_000_000u32.to_be_bytes()),
        FieldValue::DateTimeSeconds(1_700_000_000)
    );
}

#[test]
fn test_date_time_milliseconds() {
    // flowStartMilliseconds (152)
    assert_eq!(
        decode_one((152, 8, None), &1_700_000_000_123u64.to_be_bytes()),
        FieldValue::DateTimeMilliseconds(1_700_000_000_123)
    );
}

#[test]
fn test_date_time_microseconds() {
    // flowStartMicroseconds (154): NTP timestamp
    let seconds = 1_700_000_000u32.wrapping_add(NtpTimestamp::UNIX_EPOCH_OFFSET as u32);
    let mut encoded = seconds.to_be_bytes().to_vec();
    encoded.extend_from_slice(&0x8000_0000u32.to_be_bytes()); // 0.5 s
    let value = decode_one((154, 8, None), &encoded);
    let expected = NtpTimestamp {
        seconds,
        fraction: 0x8000_0000,
    };
    assert_eq!(value, FieldValue::DateTimeMicroseconds(expected));
    assert_eq!(
        expected.unix_nanos(),
        Some(1_700_000_000 * 1_000_000_000 + 500_000_000)
    );
}

#[test]
fn test_date_time_nanoseconds() {
    // flowStartNanoseconds (156)
    let value = decode_one((156, 8, None), &[0xE9, 0x00, 0x00, 0x00, 0, 0, 0, 1]);
    assert_eq!(
        value,
        FieldValue::DateTimeNanoseconds(NtpTimestamp {
            seconds: 0xE900_0000,
            fraction: 1,
        })
    );
}

#[test]
fn test_ntp_before_unix_epoch() {
    let ts = NtpTimestamp {
        seconds: 0,
        fraction: 0,
    };
    assert_eq!(ts.unix_nanos(), None);
}

#[test]
fn test_ipv4_address() {
    // sourceIPv4Address (8)
    assert_eq!(
        decode_one((8, 4, None), &[192, 0, 2, 1]),
        FieldValue::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1))
    );
}

#[test]
fn test_ipv4_address_wrong_length_is_raw() {
    assert_eq!(
        decode_one((8, 3, None), &[192, 0, 2]),
        FieldValue::Raw(vec![192, 0, 2])
    );
}

#[test]
fn test_ipv6_address() {
    // sourceIPv6Address (27)
    let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    assert_eq!(
        decode_one((27, 16, None), &addr.octets()),
        FieldValue::Ipv6Address(addr)
    );
}

#[test]
fn test_enterprise_specific_is_raw() {
    // Unknown enterprise element: the type is unknown
    assert_eq!(
        decode_one((1, 4, Some(9)), &[0, 0, 0, 1]),
        FieldValue::Raw(vec![0, 0, 0, 1])
    );
}

#[test]
fn test_unassigned_element_is_raw() {
    assert_eq!(
        decode_one((32000, 2, None), &[0xAB, 0xCD]),
        FieldValue::Raw(vec![0xAB, 0xCD])
    );
}

#[test]
fn test_reverse_element_uses_forward_type() {
    // RFC 5103: reverseOctetDeltaCount is octetDeltaCount with PEN 29305
    assert_eq!(
        decode_one((1, 8, Some(29305)), &1000u64.to_be_bytes()),
        FieldValue::Unsigned(1000)
    );
}
