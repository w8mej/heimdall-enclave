//! Bounded byte codec for one deliberately narrow, unauthenticated Mach ABI.
//!
//! SDK27.2's generated `mach_excServer.c` (SHA256 618f8aaca815a50094b7e34c348d82c224a2db3273ec5aeeea6c9ffff921c98b)
//! and the retained native layout observer establish pack4, request84/NDR8,
//! reply36, and audit trailer52. This supports only little-endian default wide
//! raise2405 with exactly two codes, no voucher or importance-header variants.
//! MIG-valid zero/one-code requests and other exception RPCs are unsupported.
//!
//! These bytes cannot establish kernel origin, task/thread relationship, PID,
//! incarnation, selected code identity, or a fault classification. Audit token
//! bytes stay opaque: interpreting their identity requires the supported BSM
//! APIs and an independently authenticated native receive/authority path.
//! Numeric names below neither own nor validate any Mach right. No Mach API,
//! cleanup, registration, listener, reply send, or runtime activation lives here.
//! A native receiver must retain every received resource independently through
//! parse failure and reply/cleanup, and provide fresh initialized receive storage.

use std::fmt;

pub(super) const REQUEST_BYTES: usize = 84;
pub(super) const AUDIT_TRAILER_BYTES: usize = 52;
pub(super) const FRAME_BYTES: usize = REQUEST_BYTES + AUDIT_TRAILER_BYTES;
pub(super) const REPLY_BYTES: usize = 36;
const REQUEST_ID: i32 = 2405;
const REPLY_ID: i32 = 2505;
const NDR: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];
const REMOTE_MASK: u32 = 0x1f;
const MOVE_SEND_ONCE: u32 = 18;
// Received SEND rights are17, not the sender's COPY_SEND19 encoding.
const RECEIVED_SEND: u8 = 17;
// Independently bind the received header LOCAL disposition to the destination
// send right, not to the receive right the listener owns. Pinned public XNU
// f6217f8 ipc_kmsg.c:5004-5047 applies ipc_object_copyin_type; ipc_object.c:489
// maps COPY_SEND19 to PORT_SEND17 and MAKE_SEND_ONCE21 to PORT_SEND_ONCE18.
// ipc_kmsg_copyout_header:3279,3636 swaps (reply_type,dest_type) into
// (REMOTE,LOCAL). SDK message.h:241-245,673 binds the numeric type aliases.
// This source contract does not qualify actual delivery on the installed OS.
const LOCAL_DESTINATION_SEND: u32 = 17;
const SUPPORTED_HEADER_BITS: u32 = 0x8000_0000 | MOVE_SEND_ONCE | (LOCAL_DESTINATION_SEND << 8);

/// Refusal stage only; never include untrusted names, codes or audit contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WireError {
    FrameLength,
    HeaderBits,
    MessageSize,
    MessageId,
    ReplyName,
    ReceiveName,
    Voucher,
    DescriptorCount,
    DescriptorType,
    DescriptorDisposition,
    DescriptorName,
    Ndr,
    CodeCount,
    TrailerFormat,
    TrailerSize,
}

/// Opaque wire bytes, without any interpreted identity or authentication bit.
pub(super) struct OpaqueAuditToken([u8; 32]);
impl OpaqueAuditToken {
    pub(super) fn bytes(&self) -> &[u8; 32] { &self.0 }
}
impl fmt::Debug for OpaqueAuditToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueAuditToken([UNAUTHENTICATED; REDACTED])")
    }
}

/// A structural parse only. Intentionally has no Clone, authority conversion,
/// classifier, right destructor, or public constructor.
pub(super) struct ParsedWideRaise {
    header_bits: u32,
    reply_name: u32,
    receive_name: u32,
    thread_name: u32,
    task_name: u32,
    exception: i32,
    codes: [i64; 2],
    sequence: u32,
    security_token: [u8; 8],
    audit: OpaqueAuditToken,
}
impl ParsedWideRaise {
    /// Numeric names, not owned or authenticated rights: reply, receive,
    /// thread descriptor, task descriptor. Native ownership stays separate.
    pub(super) fn names(&self) -> [u32; 4] {
        [self.reply_name, self.receive_name, self.thread_name, self.task_name]
    }
    pub(super) fn exception(&self) -> i32 { self.exception }
    pub(super) fn codes(&self) -> [i64; 2] { self.codes }
    pub(super) fn sequence(&self) -> u32 { self.sequence }
    pub(super) fn security_token_bytes(&self) -> &[u8; 8] { &self.security_token }
    pub(super) fn audit(&self) -> &OpaqueAuditToken { &self.audit }
}
impl fmt::Debug for ParsedWideRaise {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ParsedWideRaise([UNAUTHENTICATED WIRE; REDACTED])")
    }
}

fn bytes<const N: usize>(frame: &[u8], offset: usize) -> Result<[u8; N], WireError> {
    let end = offset.checked_add(N).ok_or(WireError::FrameLength)?;
    frame.get(offset..end).ok_or(WireError::FrameLength)?
        .try_into().map_err(|_| WireError::FrameLength)
}
fn u32_at(frame: &[u8], offset: usize) -> Result<u32, WireError> {
    Ok(u32::from_le_bytes(bytes(frame, offset)?))
}
fn valid_name(name: u32) -> bool { name != 0 && name != u32::MAX }
fn descriptor_name(frame: &[u8], offset: usize) -> Result<u32, WireError> {
    // Padding is ignored, as in the generated MIG checker; it is not data.
    if bytes::<1>(frame, offset + 11)?[0] != 0 { return Err(WireError::DescriptorType); }
    if bytes::<1>(frame, offset + 10)?[0] != RECEIVED_SEND {
        return Err(WireError::DescriptorDisposition);
    }
    let name = u32_at(frame, offset)?;
    if !valid_name(name) { return Err(WireError::DescriptorName); }
    Ok(name)
}

/// Decode exactly one84-byte body plus the requested full audit trailer at
/// round_msg(84)=84. No allocator, native API, packed reference, unaligned load,
/// or untrusted-length arithmetic is used. Extra capacity/tail is not a frame.
/// A valid parse is still untrusted and must never directly authorize a fault.
pub(super) fn decode_wide_raise(frame: &[u8]) -> Result<ParsedWideRaise, WireError> {
    if frame.len() != FRAME_BYTES { return Err(WireError::FrameLength); }
    let header_bits = u32_at(frame, 0)?;
    if header_bits != SUPPORTED_HEADER_BITS { return Err(WireError::HeaderBits); }
    if u32_at(frame, 4)? != REQUEST_BYTES as u32 { return Err(WireError::MessageSize); }
    if i32::from_le_bytes(bytes(frame, 20)?) != REQUEST_ID { return Err(WireError::MessageId); }
    let reply_name = u32_at(frame, 8)?;
    if !valid_name(reply_name) { return Err(WireError::ReplyName); }
    let receive_name = u32_at(frame, 12)?;
    if !valid_name(receive_name) { return Err(WireError::ReceiveName); }
    if u32_at(frame, 16)? != 0 { return Err(WireError::Voucher); }
    if u32_at(frame, 24)? != 2 { return Err(WireError::DescriptorCount); }
    let thread_name = descriptor_name(frame, 28)?;
    let task_name = descriptor_name(frame, 40)?;
    if bytes::<8>(frame, 52)? != NDR { return Err(WireError::Ndr); }
    if u32_at(frame, 64)? != 2 { return Err(WireError::CodeCount); }
    if u32_at(frame, REQUEST_BYTES)? != 0 { return Err(WireError::TrailerFormat); }
    if u32_at(frame, REQUEST_BYTES + 4)? != AUDIT_TRAILER_BYTES as u32 {
        return Err(WireError::TrailerSize);
    }
    Ok(ParsedWideRaise {
        header_bits, reply_name, receive_name, thread_name, task_name,
        exception: i32::from_le_bytes(bytes(frame, 60)?),
        codes: [i64::from_le_bytes(bytes(frame, 68)?), i64::from_le_bytes(bytes(frame, 76)?)],
        sequence: u32_at(frame, 92)?,
        security_token: bytes(frame, 96)?,
        audit: OpaqueAuditToken(bytes(frame, 104)?),
    })
}

fn write_u32(reply: &mut [u8; REPLY_BYTES], offset: usize, value: u32) {
    reply[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Encode bytes only. Consuming this parse neither consumes a real send-once
/// right nor proves one reply per message: callers can parse the same bytes
/// again. A native resource owner must enforce actual send/cleanup ownership.
/// `return_code` is a separately chosen outcome, not a wire authentication fact.
pub(super) fn encode_wire_reply(request: ParsedWideRaise, return_code: i32) -> [u8; REPLY_BYTES] {
    let mut reply = [0; REPLY_BYTES];
    write_u32(&mut reply, 0, request.header_bits & REMOTE_MASK);
    write_u32(&mut reply, 4, REPLY_BYTES as u32);
    write_u32(&mut reply, 8, request.reply_name);
    // Only exact admitted ID2405 can reach here; never add100 to an attacker ID.
    write_u32(&mut reply, 20, REPLY_ID as u32);
    reply[24..32].copy_from_slice(&NDR);
    write_u32(&mut reply, 32, return_code as u32);
    reply
}

#[cfg(test)]
#[path = "mach_wire_tests.rs"]
mod tests;
