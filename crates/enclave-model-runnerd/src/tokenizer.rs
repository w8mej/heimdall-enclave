//! Closed byte-level BPE tokenizer (GPT-2 family, as used by SmolLM2/Qwen).
//!
//! Built from a Hugging Face `tokenizer.json` that is carried inside the
//! authenticated model artifact. A BPE model without byte fallback or
//! subword affixes, in exactly one of three admitted shapes:
//! - SmolLM2: no normalizer; `Digits` (individual) then `ByteLevel` (GPT-2
//!   regex, no prefix space).
//! - Qwen2/Qwen3: `NFC` normalizer; `Split` with the exact Qwen2 pattern
//!   (`Isolated`) then `ByteLevel` without its regex.
//! - LLaDA (Llama-3 split): as Qwen2 with the exact Llama-3 pattern.
//! Anything else is refused rather than approximated. No tokenizer code from
//! the publisher runs.

use std::collections::HashMap;

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde_json::Value;

/// GPT-2 byte-level split pattern used by the `ByteLevel` pre-tokenizer.
const SPLIT_PATTERN: &str =
    r"'s|'t|'re|'ve|'m|'ll|'d| ?\p{L}+| ?\p{N}+| ?[^\s\p{L}\p{N}]+|\s+(?!\S)|\s+";
/// Qwen2 split pattern (`Split` pre-tokenizer, `Isolated`), admitted verbatim.
const QWEN2_PATTERN: &str = r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+";
/// Llama-3 split pattern (LLaDA), admitted verbatim; possessive quantifiers.
const LLAMA3_PATTERN: &str = r"'(?i:[sdmt]|ll|ve|re)|[^\r\n\p{L}\p{N}]?+\p{L}+|\p{N}| ?[^\s\p{L}\p{N}]++[\r\n]*|\s*[\r\n]|\s+(?!\S)|\s+";
/// Largest accepted vocabulary.
const MAX_VOCAB: usize = 1 << 20;
/// Marks a byte the vocabulary has no token for (ids stay below `MAX_VOCAB`).
const NO_TOKEN: u32 = u32::MAX;

/// A loaded tokenizer.
///
/// Kept compact because it lives inside the runner's memory ceiling: token
/// bytes are one flat buffer, and merges are keyed by token-id pairs.
#[derive(Debug)]
pub struct Tokenizer {
    /// Concatenated raw bytes of every token, in id order.
    bytes: Vec<u8>,
    /// `offsets[id]..offsets[id + 1]` is token `id` in `bytes`.
    offsets: Vec<u32>,
    /// Single byte -> token id, or `NO_TOKEN` when the vocabulary lacks it.
    byte_ids: [u32; 256],
    /// (left id, right id) -> (rank, merged id); lower ranks merge first.
    merges: HashMap<(u32, u32), (u32, u32)>,
    /// Added (special) tokens, longest first for matching.
    specials: Vec<(String, u32)>,
    split: fancy_regex::Regex,
    shape: Shape,
}

/// The admitted normalizer + pre-tokenizer combinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Digits isolated, then the GPT-2 byte-level split.
    Gpt2Digits,
    /// NFC, then the Qwen2 split with gaps kept as pieces.
    Qwen2,
    /// NFC, then the Llama-3 split with gaps kept as pieces.
    Llama3,
}

fn shape_of(normalizer: &Value, pre: &Value) -> EnclaveResult<Shape> {
    let steps = pre["pretokenizers"].as_array().filter(|_| pre["type"] == "Sequence")
        .filter(|s| s.len() == 2)
        .ok_or_else(|| err!(EINVAL, "TOKENIZER_UNSUPPORTED", "pre-tokenizer"))?;
    let byte_level = |regex: bool| steps[1]["type"] == "ByteLevel" && steps[1]["add_prefix_space"] == false
        && steps[1]["use_regex"] == regex;
    if normalizer.is_null() && steps[0]["type"] == "Digits" && steps[0]["individual_digits"] == true
        && byte_level(true)
    {
        return Ok(Shape::Gpt2Digits);
    }
    let split = &steps[0];
    let nfc_split = |pattern: &str| *normalizer == serde_json::json!({"type": "NFC"}) && split["type"] == "Split"
        && split["pattern"]["Regex"] == pattern && split["behavior"] == "Isolated"
        && split["invert"] == false && byte_level(false);
    if nfc_split(QWEN2_PATTERN) {
        return Ok(Shape::Qwen2);
    }
    if nfc_split(LLAMA3_PATTERN) {
        return Ok(Shape::Llama3);
    }
    fail!(EINVAL, "TOKENIZER_UNSUPPORTED", "pre-tokenizer")
}

/// GPT-2 `bytes_to_unicode`: the printable-character alphabet for bytes.
fn byte_alphabet() -> [char; 256] {
    let mut table = ['\0'; 256];
    let mut next = 256u32;
    for b in 0..=255u8 {
        let printable = matches!(b, b'!'..=b'~' | 0xA1..=0xAC | 0xAE..=0xFF);
        table[b as usize] = if printable {
            b as char
        } else {
            let c = char::from_u32(next).expect("valid code point");
            next += 1;
            c
        };
    }
    table
}

/// Code point -> byte for the alphabet (all its code points are below 324).
fn reverse_alphabet() -> [Option<u8>; 324] {
    let mut table = [None; 324];
    for (b, c) in byte_alphabet().iter().enumerate() {
        table[*c as usize] = Some(b as u8);
    }
    table
}

/// Append the raw bytes an alphabet-encoded token stands for.
fn push_token_bytes<E: serde::de::Error>(token: &str, table: &[Option<u8>; 324], out: &mut Vec<u8>) -> Result<(), E> {
    for c in token.chars() {
        out.push(table.get(c as usize).copied().flatten().ok_or_else(|| E::custom("TOKENIZER_ALPHABET"))?);
    }
    Ok(())
}

fn require(condition: bool, what: &str) -> EnclaveResult<()> {
    if !condition {
        fail!(EINVAL, "TOKENIZER_UNSUPPORTED", "{what}");
    }
    Ok(())
}

// Streaming wire format. The vocabulary and merges are decoded straight
// into flat byte buffers as they are read, never into a JSON tree, so a
// 150k-token tokenizer fits inside the runner's memory ceiling.

/// `model.vocab`: (id, start, end) spans into one byte buffer.
#[derive(Default)]
struct VocabWire {
    bytes: Vec<u8>,
    entries: Vec<(u32, u32, u32)>,
}

impl<'de> serde::Deserialize<'de> for VocabWire {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = VocabWire;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a token -> id map")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<VocabWire, A::Error> {
                use serde::de::Error;
                let table = reverse_alphabet();
                let mut out = VocabWire::default();
                while let Some((token, id)) = map.next_entry::<String, u32>()? {
                    if out.entries.len() >= MAX_VOCAB {
                        return Err(A::Error::custom("TOKENIZER_VOCAB_SIZE"));
                    }
                    let start = out.bytes.len() as u32;
                    push_token_bytes(&token, &table, &mut out.bytes)?;
                    out.entries.push((id, start, out.bytes.len() as u32));
                }
                Ok(out)
            }
        }
        d.deserialize_map(V)
    }
}

/// `model.merges`: `"a b"` strings or `["a", "b"]` pairs, as (start, mid, end).
#[derive(Default)]
struct MergesWire {
    bytes: Vec<u8>,
    spans: Vec<(u32, u32, u32)>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum MergeEntry {
    Joined(String),
    Pair(String, String),
}

impl<'de> serde::Deserialize<'de> for MergesWire {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = MergesWire;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a merge list")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<MergesWire, A::Error> {
                use serde::de::Error;
                let table = reverse_alphabet();
                let mut out = MergesWire::default();
                while let Some(entry) = seq.next_element::<MergeEntry>()? {
                    let (a, b) = match &entry {
                        MergeEntry::Joined(m) => m.split_once(' ').ok_or_else(|| A::Error::custom("TOKENIZER_MERGE"))?,
                        MergeEntry::Pair(a, b) => (a.as_str(), b.as_str()),
                    };
                    let start = out.bytes.len() as u32;
                    push_token_bytes(a, &table, &mut out.bytes)?;
                    let mid = out.bytes.len() as u32;
                    push_token_bytes(b, &table, &mut out.bytes)?;
                    out.spans.push((start, mid, out.bytes.len() as u32));
                }
                Ok(out)
            }
        }
        d.deserialize_seq(V)
    }
}

#[derive(serde::Deserialize)]
struct AddedWire {
    id: u64,
    content: String,
}

#[derive(serde::Deserialize)]
struct ModelWire {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    byte_fallback: Option<bool>,
    #[serde(default)]
    ignore_merges: Option<bool>,
    #[serde(default)]
    dropout: Option<f64>,
    #[serde(default)]
    continuing_subword_prefix: Option<String>,
    #[serde(default)]
    end_of_word_suffix: Option<String>,
    #[serde(default)]
    vocab: Option<VocabWire>,
    #[serde(default)]
    merges: Option<MergesWire>,
}

#[derive(serde::Deserialize)]
struct FileWire {
    #[serde(default)]
    normalizer: Value,
    #[serde(default)]
    pre_tokenizer: Value,
    #[serde(default)]
    added_tokens: Vec<AddedWire>,
    model: ModelWire,
}

impl Tokenizer {
    /// Parse the admitted `tokenizer.json` shape.
    pub fn from_hf_json(json: &str) -> EnclaveResult<Self> {
        let t: FileWire = serde_json::from_str(json).map_err(|e| {
            let text = e.to_string();
            let code = ["TOKENIZER_ALPHABET", "TOKENIZER_MERGE", "TOKENIZER_VOCAB_SIZE"]
                .into_iter().find(|c| text.contains(c)).unwrap_or("TOKENIZER_JSON");
            err!(EINVAL, code)
        })?;
        let model = &t.model;
        require(model.kind == "BPE", "model type")?;
        require(model.byte_fallback != Some(true), "byte fallback")?;
        require(model.ignore_merges != Some(true), "ignore_merges")?;
        require(model.dropout.is_none(), "dropout")?;
        for affix in [&model.continuing_subword_prefix, &model.end_of_word_suffix] {
            require(affix.as_deref().is_none_or(str::is_empty), "subword affix")?;
        }
        let shape = shape_of(&t.normalizer, &t.pre_tokenizer)?;
        let vocab = model.vocab.as_ref().ok_or_else(|| err!(EINVAL, "TOKENIZER_VOCAB"))?;
        let merges_wire = model.merges.as_ref().ok_or_else(|| err!(EINVAL, "TOKENIZER_MERGES"))?;
        let n = vocab.entries.len();
        require(n > 0, "vocabulary size")?;
        let span = |(s, e): (u32, u32)| &vocab.bytes[s as usize..e as usize];

        // id -> span, then bytes -> id (borrowing the flat buffer).
        let mut by_id = vec![None; n];
        for (id, start, end) in &vocab.entries {
            let slot = by_id.get_mut(*id as usize).ok_or_else(|| err!(EINVAL, "TOKENIZER_VOCAB_ID"))?;
            if slot.replace((*start, *end)).is_some() {
                fail!(EINVAL, "TOKENIZER_VOCAB_DUPLICATE");
            }
        }
        let by_id: Vec<(u32, u32)> = by_id.into_iter().collect::<Option<_>>()
            .ok_or_else(|| err!(EINVAL, "TOKENIZER_VOCAB_GAP"))?;
        let mut encoder: HashMap<&[u8], u32> = HashMap::with_capacity(n);
        for (id, s) in by_id.iter().enumerate() {
            if encoder.insert(span(*s), id as u32).is_some() {
                fail!(EINVAL, "TOKENIZER_VOCAB_DUPLICATE");
            }
        }
        let id_of = |bytes: &[u8]| encoder.get(bytes).copied().ok_or_else(|| err!(EINVAL, "TOKENIZER_MERGE_OUT_OF_VOCAB"));
        let mut byte_ids = [NO_TOKEN; 256];
        for (b, slot) in byte_ids.iter_mut().enumerate() {
            *slot = encoder.get([b as u8].as_slice()).copied().unwrap_or(NO_TOKEN);
        }
        require(merges_wire.spans.len() < u32::MAX as usize, "merge count")?;
        let mut merges = HashMap::with_capacity(merges_wire.spans.len());
        let mut joined = Vec::new();
        for (rank, (start, mid, end)) in merges_wire.spans.iter().enumerate() {
            let a = &merges_wire.bytes[*start as usize..*mid as usize];
            let b = &merges_wire.bytes[*mid as usize..*end as usize];
            joined.clear();
            joined.extend_from_slice(&merges_wire.bytes[*start as usize..*end as usize]);
            let merged = id_of(&joined)?;
            // First occurrence wins, as in the reference implementation.
            merges.entry((id_of(a)?, id_of(b)?)).or_insert((rank as u32, merged));
        }
        drop(encoder);

        // Added tokens may sit beyond the BPE vocabulary (Qwen's specials);
        // they must then fill it contiguously.
        let mut added: Vec<(u32, &str)> = Vec::with_capacity(t.added_tokens.len());
        for entry in &t.added_tokens {
            if entry.content.is_empty() || entry.id as usize >= MAX_VOCAB {
                fail!(EINVAL, "TOKENIZER_ADDED");
            }
            added.push((entry.id as u32, entry.content.as_str()));
        }
        added.sort();
        let mut bytes = Vec::with_capacity(vocab.bytes.len() + added.iter().map(|(_, c)| c.len()).sum::<usize>());
        let mut offsets = Vec::with_capacity(n + added.len() + 1);
        offsets.push(0u32);
        for s in &by_id {
            bytes.extend_from_slice(span(*s));
            offsets.push(bytes.len() as u32);
        }
        for (id, content) in &added {
            let count = offsets.len() - 1;
            match (*id as usize).cmp(&count) {
                std::cmp::Ordering::Less => require(span(by_id[*id as usize]) == content.as_bytes(), "added token text")?,
                std::cmp::Ordering::Equal => {
                    bytes.extend_from_slice(content.as_bytes());
                    offsets.push(u32::try_from(bytes.len()).map_err(|_| err!(EINVAL, "TOKENIZER_VOCAB_BYTES"))?);
                }
                std::cmp::Ordering::Greater => fail!(EINVAL, "TOKENIZER_VOCAB_GAP"),
            }
        }
        let mut specials: Vec<(String, u32)> = added.into_iter().map(|(id, c)| (c.to_owned(), id)).collect();
        specials.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        let pattern = match shape {
            Shape::Gpt2Digits => SPLIT_PATTERN,
            Shape::Qwen2 => QWEN2_PATTERN,
            Shape::Llama3 => LLAMA3_PATTERN,
        };
        let split = fancy_regex::Regex::new(pattern).map_err(|_| err!(EIO, "TOKENIZER_PATTERN"))?;
        Ok(Self { bytes, offsets, byte_ids, merges, specials, split, shape })
    }

    /// Vocabulary size.
    pub fn vocab(&self) -> usize {
        self.offsets.len() - 1
    }

    /// Raw bytes of one token.
    pub fn token(&self, id: u32) -> Option<&[u8]> {
        let id = id as usize;
        let (start, end) = (*self.offsets.get(id)?, *self.offsets.get(id + 1)?);
        Some(&self.bytes[start as usize..end as usize])
    }

    /// Id of an added token such as `<|im_end|>`.
    pub fn special(&self, content: &str) -> Option<u32> {
        self.specials.iter().find(|(c, _)| c == content).map(|(_, id)| *id)
    }

    /// Whether `id` is an added (special) token rather than ordinary text.
    pub fn is_special(&self, id: u32) -> bool {
        self.specials.iter().any(|(_, s)| *s == id)
    }

    /// Decode ids to raw bytes (byte-level: exact inverse of encoding).
    pub fn decode(&self, ids: &[u32]) -> EnclaveResult<Vec<u8>> {
        ids.iter().try_fold(Vec::new(), |mut out, id| {
            out.extend_from_slice(self.token(*id).ok_or_else(|| err!(EINVAL, "TOKEN_ID_RANGE"))?);
            Ok(out)
        })
    }

    /// Encode text, recognizing added tokens as single ids.
    pub fn encode(&self, text: &str) -> EnclaveResult<Vec<u32>> {
        let mut ids = Vec::new();
        let mut rest = text;
        while !rest.is_empty() {
            let next = self.specials.iter()
                .filter_map(|(c, id)| rest.find(c.as_str()).map(|at| (at, c.len(), *id)))
                .min_by_key(|(at, len, _)| (*at, usize::MAX - len));
            let (plain, after) = match next {
                Some((at, len, id)) => {
                    self.encode_plain(&rest[..at], &mut ids)?;
                    ids.push(id);
                    ("", &rest[at + len..])
                }
                None => (rest, ""),
            };
            self.encode_plain(plain, &mut ids)?;
            rest = after;
        }
        Ok(ids)
    }

    /// Normalize and pre-tokenize per the admitted shape, then BPE.
    fn encode_plain(&self, text: &str, ids: &mut Vec<u32>) -> EnclaveResult<()> {
        if matches!(self.shape, Shape::Qwen2 | Shape::Llama3) {
            use unicode_normalization::UnicodeNormalization;
            let normalized: String = text.nfc().collect();
            return self.encode_split(&normalized, ids);
        }
        let mut start = 0;
        for (at, c) in text.char_indices() {
            if c.is_numeric() {
                self.encode_split(&text[start..at], ids)?;
                self.encode_split(&text[at..at + c.len_utf8()], ids)?;
                start = at + c.len_utf8();
            }
        }
        self.encode_split(&text[start..], ids)
    }

    /// Split into regex matches; text between matches is its own piece
    /// (`Isolated` behaviour), so no input byte is ever dropped.
    fn encode_split(&self, text: &str, ids: &mut Vec<u32>) -> EnclaveResult<()> {
        let mut last = 0;
        for piece in self.split.find_iter(text) {
            let piece = piece.map_err(|_| err!(EIO, "TOKENIZER_SPLIT"))?;
            if piece.start() > last {
                self.bpe(text[last..piece.start()].as_bytes(), ids)?;
            }
            self.bpe(piece.as_str().as_bytes(), ids)?;
            last = piece.end();
        }
        if last < text.len() {
            self.bpe(text[last..].as_bytes(), ids)?;
        }
        Ok(())
    }

    fn bpe(&self, piece: &[u8], ids: &mut Vec<u32>) -> EnclaveResult<()> {
        let mut parts: Vec<u32> = piece.iter().map(|b| self.byte_ids[*b as usize]).collect();
        if parts.contains(&NO_TOKEN) {
            fail!(EINVAL, "TOKENIZER_UNKNOWN_PIECE");
        }
        loop {
            let best = parts.windows(2).enumerate()
                .filter_map(|(i, w)| self.merges.get(&(w[0], w[1])).map(|(rank, merged)| (*rank, i, *merged)))
                .min();
            let Some((_, i, merged)) = best else { break };
            parts.splice(i..i + 2, [merged]);
        }
        ids.extend_from_slice(&parts);
        Ok(())
    }
}

/// A tiny byte-level BPE tokenizer for unit tests elsewhere in the crate.
#[cfg(test)]
pub(crate) fn tiny_for_tests() -> Tokenizer {
    tests::tiny()
}

/// `tokenizer.json` of the byte-only test tokenizer with one added token
/// named `special` (id 256).
#[cfg(test)]
pub(crate) fn tiny_json_for_tests(special: &str) -> String {
    tests::json_with(&[], &[], special)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every byte token (ids 0..256 in alphabet order), then `extra` tokens.
    fn json(extra: &[&str], merges: &[&str]) -> String {
        json_with(extra, merges, "<|end|>")
    }

    /// As `json`, with the single added token named `special`.
    pub(super) fn json_with(extra: &[&str], merges: &[&str], special: &str) -> String {
        let alphabet = byte_alphabet();
        let mut vocab = serde_json::Map::new();
        for c in alphabet {
            vocab.insert(c.to_string(), vocab.len().into());
        }
        for t in extra {
            vocab.insert((*t).into(), vocab.len().into());
        }
        let end = vocab.len();
        vocab.insert(special.into(), end.into());
        serde_json::json!({"normalizer": null,
            "pre_tokenizer": {"type": "Sequence", "pretokenizers": [
                {"type": "Digits", "individual_digits": true},
                {"type": "ByteLevel", "add_prefix_space": false, "trim_offsets": true, "use_regex": true}]},
            "added_tokens": [{"id": end, "content": special}],
            "model": {"type": "BPE", "byte_fallback": false, "vocab": vocab, "merges": merges}}).to_string()
    }

    pub(super) fn tiny() -> Tokenizer {
        Tokenizer::from_hf_json(&json(&["ab", "Ġab"], &["a b", "Ġ ab"])).unwrap()
    }

    #[test]
    fn merges_apply_by_rank_and_specials_stay_whole() {
        let t = tiny();
        let [ab, space_ab, end] = [256, 257, 258];
        let [one, two] = [t.byte_ids[b'1' as usize], t.byte_ids[b'2' as usize]];
        assert_eq!(t.encode("ab ab<|end|>12").unwrap(), vec![ab, space_ab, end, one, two]);
        assert_eq!(t.decode(&[ab, space_ab, end]).unwrap(), b"ab ab<|end|>");
        assert_eq!(t.encode("c").unwrap(), vec![t.byte_ids[b'c' as usize]]);
        assert_eq!(t.vocab(), 259);
    }

    #[test]
    fn unsupported_shapes_and_out_of_vocab_merges_are_refused() {
        let normalized = r#"{"normalizer":{"type":"NFC"},"model":{"type":"BPE"}}"#;
        assert!(Tokenizer::from_hf_json(normalized).unwrap_err().is("TOKENIZER_UNSUPPORTED"));
        let merge_target_missing = json(&["ab"], &["a b", "ab ab"]);
        assert!(Tokenizer::from_hf_json(&merge_target_missing).unwrap_err().is("TOKENIZER_MERGE_OUT_OF_VOCAB"));
        let byte_missing = Tokenizer::from_hf_json(&json(&[], &[]).replacen("\"!\":33", "\"zz\":33", 1)).unwrap();
        assert!(byte_missing.encode("a!").unwrap_err().is("TOKENIZER_UNKNOWN_PIECE"));
    }

    #[test]
    fn parse_failures_carry_their_specific_reason_code() {
        assert!(Tokenizer::from_hf_json("not json").unwrap_err().is("TOKENIZER_JSON"));
        let bad_merge = json(&["ab"], &["ab"]);
        assert!(Tokenizer::from_hf_json(&bad_merge).unwrap_err().is("TOKENIZER_MERGE"));
    }

    #[test]
    fn byte_alphabet_is_a_bijection() {
        let a = byte_alphabet();
        let unique: std::collections::HashSet<char> = a.iter().copied().collect();
        assert_eq!(unique.len(), 256);
        assert_eq!(a[b' ' as usize], 'Ġ');
    }
}
