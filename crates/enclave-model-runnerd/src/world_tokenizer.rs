//! Closed RWKV World tokenizer (`rwkv_world_trie_v1`).
//!
//! Greedy longest-prefix matching over a fixed byte vocabulary, as the
//! reference `TRIE_TOKENIZER` of `rwkv` 0.8.32 does. The vocabulary arrives
//! inside the authenticated artifact as `{"type":"rwkv_world_trie_v1",
//! "tokens":[hex, ...]}` (index = id; id 0 is end-of-text and empty), written
//! by scripts/convert-rwkv7.py. Token bytes live in one flat buffer and are
//! looked up through an index sorted by bytes, to keep the runner small.

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::Deserialize;

/// Format tag in the artifact.
pub const FORMAT: &str = "rwkv_world_trie_v1";
/// End-of-text id.
pub const END_OF_TEXT: u32 = 0;
const MAX_VOCAB: usize = 1 << 20;
const MAX_TOKEN_BYTES: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    #[serde(rename = "type")]
    kind: String,
    tokens: Vec<String>,
}

/// A loaded World tokenizer.
#[derive(Debug)]
pub struct WorldTokenizer {
    bytes: Vec<u8>,
    /// `offsets[id]..offsets[id + 1]` is token `id` in `bytes`.
    offsets: Vec<u32>,
    /// Non-empty token ids sorted by their bytes.
    sorted: Vec<u32>,
    longest: usize,
}

impl WorldTokenizer {
    /// Parse the artifact's tokenizer JSON.
    pub fn from_json(json: &str) -> EnclaveResult<Self> {
        let wire: Wire = serde_json::from_str(json).map_err(|_| err!(EINVAL, "TOKENIZER_JSON"))?;
        if wire.kind != FORMAT || wire.tokens.is_empty() || wire.tokens.len() > MAX_VOCAB {
            fail!(EINVAL, "TOKENIZER_UNSUPPORTED", "world vocabulary shape");
        }
        let mut bytes = Vec::new();
        let mut offsets = vec![0u32];
        for token in &wire.tokens {
            let raw = hex::decode(token).map_err(|_| err!(EINVAL, "TOKENIZER_VOCAB"))?;
            if raw.len() > MAX_TOKEN_BYTES {
                fail!(EINVAL, "TOKENIZER_VOCAB", "token too long");
            }
            bytes.extend_from_slice(&raw);
            offsets.push(u32::try_from(bytes.len()).map_err(|_| err!(EINVAL, "TOKENIZER_VOCAB_BYTES"))?);
        }
        let mut t = Self { bytes, offsets, sorted: Vec::new(), longest: 0 };
        if t.token(END_OF_TEXT) != Some(&[][..]) {
            fail!(EINVAL, "TOKENIZER_UNSUPPORTED", "id 0 must be the empty end-of-text token");
        }
        let mut sorted: Vec<u32> = (1..t.vocab() as u32).collect();
        if sorted.iter().any(|id| t.token(*id).is_some_and(<[u8]>::is_empty)) {
            fail!(EINVAL, "TOKENIZER_VOCAB", "empty token");
        }
        sorted.sort_unstable_by(|a, b| t.token(*a).cmp(&t.token(*b)));
        if sorted.windows(2).any(|w| t.token(w[0]) == t.token(w[1])) {
            fail!(EINVAL, "TOKENIZER_VOCAB_DUPLICATE");
        }
        // Every single byte must be a token, so greedy matching always advances.
        for b in 0..=255u8 {
            if t.find(&sorted, &[b]).is_none() {
                fail!(EINVAL, "TOKENIZER_UNSUPPORTED", "byte {b} missing");
            }
        }
        t.longest = sorted.iter().filter_map(|id| t.token(*id)).map(<[u8]>::len).max().unwrap_or(1);
        t.sorted = sorted;
        Ok(t)
    }

    /// Vocabulary size (including id 0).
    pub fn vocab(&self) -> usize {
        self.offsets.len() - 1
    }

    /// Raw bytes of one token.
    pub fn token(&self, id: u32) -> Option<&[u8]> {
        let id = id as usize;
        let (start, end) = (*self.offsets.get(id)?, *self.offsets.get(id + 1)?);
        Some(&self.bytes[start as usize..end as usize])
    }

    fn find(&self, sorted: &[u32], piece: &[u8]) -> Option<u32> {
        sorted.binary_search_by(|id| self.token(*id).unwrap_or_default().cmp(piece))
            .ok().map(|at| sorted[at])
    }

    /// Greedy longest-prefix encoding.
    pub fn encode(&self, text: &[u8]) -> EnclaveResult<Vec<u32>> {
        let mut ids = Vec::new();
        let mut at = 0;
        while at < text.len() {
            let max = self.longest.min(text.len() - at);
            let (len, id) = (1..=max).rev()
                .find_map(|len| self.find(&self.sorted, &text[at..at + len]).map(|id| (len, id)))
                .ok_or_else(|| err!(EINVAL, "TOKENIZER_UNKNOWN_PIECE"))?;
            ids.push(id);
            at += len;
        }
        Ok(ids)
    }

    /// Decode ids to raw bytes.
    pub fn decode(&self, ids: &[u32]) -> EnclaveResult<Vec<u8>> {
        ids.iter().try_fold(Vec::new(), |mut out, id| {
            out.extend_from_slice(self.token(*id).ok_or_else(|| err!(EINVAL, "TOKEN_ID_RANGE"))?);
            Ok(out)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny(extra: &[&[u8]]) -> String {
        let mut tokens = vec![String::new()];
        tokens.extend((0..=255u8).map(|b| hex::encode([b])));
        tokens.extend(extra.iter().map(hex::encode));
        serde_json::json!({"type": FORMAT, "tokens": tokens}).to_string()
    }

    #[test]
    fn longest_prefix_wins_and_decoding_inverts() {
        let t = WorldTokenizer::from_json(&tiny(&[b"ab", b"abc", b"bcd"])).unwrap();
        // "abcd": longest at 0 is "abc" (258), then "d"; never "ab"+"cd".
        let ids = t.encode(b"abcd").unwrap();
        assert_eq!(ids, vec![258, 1 + b'd' as u32]);
        assert_eq!(t.decode(&ids).unwrap(), b"abcd");
        assert_eq!(t.encode(b"").unwrap(), Vec::<u32>::new());
    }

    #[test]
    fn malformed_vocabularies_are_refused() {
        let duplicate = tiny(&[b"ab", b"ab"]);
        assert!(WorldTokenizer::from_json(&duplicate).unwrap_err().is("TOKENIZER_VOCAB_DUPLICATE"));
        let wrong = tiny(&[]).replace(FORMAT, "bpe");
        assert!(WorldTokenizer::from_json(&wrong).unwrap_err().is("TOKENIZER_UNSUPPORTED"));
        let missing_byte = serde_json::json!({"type": FORMAT, "tokens": ["", "61"]}).to_string();
        assert!(WorldTokenizer::from_json(&missing_byte).unwrap_err().is("TOKENIZER_UNSUPPORTED"));
    }
}
