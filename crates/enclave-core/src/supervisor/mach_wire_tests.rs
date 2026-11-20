//! Portable synthetic wire fixtures; no Mach ports, sends or authentication.
//! Offsets/widths/NDR bind to retained SDK27.2/MIG and actual layout observer:
//! mach_excServer.c SHA256618f8aaca815a50094b7e34c348d82c224a2db3273ec5aeeea6c9ffff921c98b;
//! native-mach-layout-observer-attempt1.stdout SHA2560198f2b70f1a44cb5b8325ae50ddf6d6a7af894e7cf473ffb1a2c9c2d3f6aae4.
//! This literal is authored from those layouts, not an actually delivered fault.
use super::*;

const FIXTURE: [u8; 136] = [
    0x12, 0x11, 0x00, 0x80, 0x54, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 0x55, 0x44, 0x33, 0x22, 0, 0, 0,
    0, 0x65, 0x09, 0, 0, 2, 0, 0, 0, 0x66, 0x55, 0x44, 0x33, 0, 0, 0, 0, 0, 0, 17, 0, 0x77, 0x66,
    0x55, 0x44, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 52, 0, 0, 0,
    0x88, 0x77, 0x66, 0x55, 1, 1, 1, 1, 2, 2, 2, 2, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];
fn set_u32(frame: &mut [u8], offset: usize, value: u32) {
    frame[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn refused(frame: &[u8], expected: WireError) {
    assert_eq!(decode_wide_raise(frame).unwrap_err(), expected);
}

#[test]
fn source_bound_pack4_fixture_preserves_every_untrusted_field() {
    assert_eq!(
        (REQUEST_BYTES, AUDIT_TRAILER_BYTES, FRAME_BYTES, REPLY_BYTES),
        (84, 52, 136, 36)
    );
    let parsed = decode_wide_raise(&FIXTURE).unwrap();
    assert_eq!(
        parsed.names(),
        [0x11223344, 0x22334455, 0x33445566, 0x44556677]
    );
    assert_eq!(parsed.exception(), 1);
    assert_eq!(parsed.codes(), [-2, 0x0102030405060708]);
    assert_eq!(parsed.sequence(), 0x55667788);
    assert_eq!(parsed.security_token_bytes(), &[1, 1, 1, 1, 2, 2, 2, 2]);
    assert_eq!(parsed.audit().bytes(), &FIXTURE[104..136]);
}

#[test]
fn every_truncation_and_extra_tail_is_refused_without_stale_fields() {
    let parsed = decode_wide_raise(&FIXTURE).unwrap();
    for length in 0..FIXTURE.len() {
        refused(&FIXTURE[..length], WireError::FrameLength);
    }
    let mut extra = FIXTURE.to_vec();
    extra.push(0);
    refused(&extra, WireError::FrameLength);
    refused(&[0; 136], WireError::HeaderBits);
    assert_eq!(parsed.codes(), [-2, 0x0102030405060708]);
}

#[test]
fn hostile_body_sizes_never_drive_offset_or_rounding_arithmetic() {
    for size in [0, 1, 23, 24, 67, 68, 76, 83, 85, 136, u32::MAX] {
        let mut frame = FIXTURE;
        set_u32(&mut frame, 4, size);
        refused(&frame, WireError::MessageSize);
    }
}

#[test]
fn only_exact_wide_raise_id_is_supported_and_reply_id_cannot_overflow() {
    for id in [0, 2401, 2404, 2406, 2407, 2505, i32::MIN, i32::MAX] {
        let mut frame = FIXTURE;
        set_u32(&mut frame, 20, id as u32);
        refused(&frame, WireError::MessageId);
    }
}

#[test]
fn header_requires_complex_received_send_and_reply_send_once_without_extra_variants() {
    for bits in [
        0,
        18,
        0x80001111,
        0x80001012,
        0x80001312,
        0x80001113,
        0x80011112,
        0xa0001112,
        0x90001112,
        0xc0001112,
        u32::MAX,
    ] {
        let mut frame = FIXTURE;
        set_u32(&mut frame, 0, bits);
        refused(&frame, WireError::HeaderBits);
    }
}

#[test]
fn absent_or_dead_header_names_and_any_voucher_name_are_refused() {
    for (offset, reason) in [(8, WireError::ReplyName), (12, WireError::ReceiveName)] {
        for value in [0, u32::MAX] {
            let mut frame = FIXTURE;
            set_u32(&mut frame, offset, value);
            refused(&frame, reason);
        }
    }
    for voucher in [1, 17, u32::MAX] {
        let mut frame = FIXTURE;
        set_u32(&mut frame, 16, voucher);
        refused(&frame, WireError::Voucher);
    }
}

#[test]
fn descriptor_count_is_exact_not_a_loop_or_allocation_length() {
    for count in [0, 1, 3, u32::MAX] {
        let mut frame = FIXTURE;
        set_u32(&mut frame, 24, count);
        refused(&frame, WireError::DescriptorCount);
    }
}

#[test]
fn both_descriptors_reject_ool_unknown_types_and_wrong_received_dispositions() {
    for offset in [28, 40] {
        for kind in [1, 2, 3, 255] {
            let mut frame = FIXTURE;
            frame[offset + 11] = kind;
            refused(&frame, WireError::DescriptorType);
        }
        for disposition in [0, 16, 18, 19, 20, 21, 255] {
            let mut frame = FIXTURE;
            frame[offset + 10] = disposition;
            refused(&frame, WireError::DescriptorDisposition);
        }
    }
}

#[test]
fn descriptor_names_must_be_present_but_wire_padding_has_no_identity_meaning() {
    for offset in [28, 40] {
        for name in [0, u32::MAX] {
            let mut frame = FIXTURE;
            set_u32(&mut frame, offset, name);
            refused(&frame, WireError::DescriptorName);
        }
        let mut frame = FIXTURE;
        frame[offset + 4..offset + 10].fill(0xa5);
        assert_eq!(
            decode_wide_raise(&frame).unwrap().names(),
            decode_wide_raise(&FIXTURE).unwrap().names()
        );
    }
}

#[test]
fn every_ndr_byte_is_required_and_foreign_integer_representation_is_not_converted() {
    for offset in 52..60 {
        let mut frame = FIXTURE;
        frame[offset] ^= 0xff;
        refused(&frame, WireError::Ndr);
    }
    let mut frame = FIXTURE;
    frame[56] = 0;
    refused(&frame, WireError::Ndr);
}

#[test]
fn exact_two_codes_refuse_mig_valid_short_variants_and_hostile_counts() {
    for count in [0, 1, 3, u32::MAX] {
        let mut frame = FIXTURE;
        set_u32(&mut frame, 64, count);
        refused(&frame, WireError::CodeCount);
    }
    for (count, size) in [(0, 68usize), (1, 76)] {
        let mut frame = FIXTURE.to_vec();
        set_u32(&mut frame, 4, size as u32);
        set_u32(&mut frame, 64, count);
        drop(frame.drain(size..84));
        refused(&frame, WireError::FrameLength);
    }
}

#[test]
fn signed_codes_and_unknown_exception_numbers_are_data_not_fault_authority() {
    let mut frame = FIXTURE;
    set_u32(&mut frame, 60, i32::MIN as u32);
    frame[68..76].copy_from_slice(&i64::MIN.to_le_bytes());
    frame[76..84].copy_from_slice(&i64::MAX.to_le_bytes());
    let parsed = decode_wide_raise(&frame).unwrap();
    assert_eq!(parsed.exception(), i32::MIN);
    assert_eq!(parsed.codes(), [i64::MIN, i64::MAX]);
}

#[test]
fn audit_requires_complete_exact_format_and_size_not_token_sized_prefix() {
    for kind in [1, u32::MAX] {
        let mut frame = FIXTURE;
        set_u32(&mut frame, 84, kind);
        refused(&frame, WireError::TrailerFormat);
    }
    for size in [0, 8, 12, 20, 32, 51, 53, 60, u32::MAX] {
        let mut frame = FIXTURE;
        set_u32(&mut frame, 88, size);
        refused(&frame, WireError::TrailerSize);
    }
}

#[test]
fn audit_bytes_remain_opaque_even_for_kernel_shaped_and_invalid_shaped_tokens() {
    for value in [0, 0xff] {
        let mut frame = FIXTURE;
        frame[104..136].fill(value);
        let parsed = decode_wide_raise(&frame).unwrap();
        assert_eq!(parsed.audit().bytes(), &[value; 32]);
        assert_eq!(
            format!("{:?}", parsed.audit()),
            "OpaqueAuditToken([UNAUTHENTICATED; REDACTED])"
        );
        assert_eq!(
            format!("{parsed:?}"),
            "ParsedWideRaise([UNAUTHENTICATED WIRE; REDACTED])"
        );
    }
}

#[test]
fn unaligned_input_uses_checked_copies_and_parse_does_not_borrow_a_reused_frame() {
    let mut storage = vec![0xcc];
    storage.extend_from_slice(&FIXTURE);
    let parsed = decode_wide_raise(&storage[1..]).unwrap();
    storage.fill(0);
    assert_eq!(parsed.codes(), [-2, 0x0102030405060708]);
    assert_eq!(parsed.audit().bytes(), &FIXTURE[104..136]);
}

#[test]
fn reply_is_exact_generated_mig_shape_with_masked_bits_and_canonical_ndr() {
    let reply = encode_wire_reply(decode_wide_raise(&FIXTURE).unwrap(), 5);
    assert_eq!(
        reply,
        [
            18, 0, 0, 0, 36, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0xc9, 0x09,
            0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0,
        ]
    );
}

#[test]
fn reply_preserves_chosen_signed_status_without_copying_ports_codes_or_audit_tail() {
    for status in [0, -1, i32::MIN, i32::MAX] {
        let reply = encode_wire_reply(decode_wide_raise(&FIXTURE).unwrap(), status);
        assert_eq!(reply.len(), 36);
        assert_eq!(
            i32::from_le_bytes(reply[32..36].try_into().unwrap()),
            status
        );
        assert_eq!(&reply[12..20], &[0; 8]);
        assert_eq!(&reply[24..32], &[0, 0, 0, 0, 1, 0, 0, 0]);
    }
}
