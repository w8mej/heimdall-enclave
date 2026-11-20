//! FS-704 §3.1 strictly monotonic dual security lattice
//! `L = C x T`, where both axes increase with danger/sensitivity.
//!
//! * `l1 ⊑ l2  ⇔  c1 <= c2 ∧ t1 <= t2`
//! * `l1 ⊔ l2  =  (max(c1,c2), max(t1,t2))`   (join, least upper bound)
//! * `l1 ⊓ l2  =  (min(c1,c2), min(t1,t2))`   (meet, greatest lower bound)
//!
//! Bell-LaPadula "no write-down" on the confidentiality axis and the monotone
//! dual of Biba on the taint axis are expressed by [`Label::may_flow_to`] and
//! [`SlotKind`] admission.

use serde::{Deserialize, Serialize};

use crate::error::EnclaveResult;
use crate::fail;

/// Confidentiality sensitivity `C1 < C2 < C3 < C4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Conf {
    /// Public.
    C1 = 1,
    /// Internal.
    C2 = 2,
    /// Confidential.
    C3 = 3,
    /// Restricted PII / crown-jewel.
    C4 = 4,
}

/// Untrusted taint risk `T0 < T1 < T2 < T3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Taint {
    /// Signed system root (TUF manifests, Cedar policies, hardware-signed intents).
    T0 = 0,
    /// Short user directive (`UserTurnV1.directive_short` only).
    T1 = 1,
    /// Enclave-verified sanitizer output.
    T2 = 2,
    /// Untrusted external data (web, MCP tool output, attachments).
    T3 = 3,
}

impl Conf {
    /// All levels in ascending order.
    pub const ALL: [Conf; 4] = [Conf::C1, Conf::C2, Conf::C3, Conf::C4];
    /// Numeric rank 1..=4.
    pub fn rank(self) -> u8 {
        self as u8
    }
    /// Parse `"C1".."C4"`.
    pub fn parse(s: &str) -> EnclaveResult<Self> {
        Ok(match s {
            "C1" => Conf::C1,
            "C2" => Conf::C2,
            "C3" => Conf::C3,
            "C4" => Conf::C4,
            _ => fail!(EINVAL, "BAD_CONF_LABEL", "{s:?}"),
        })
    }
}

impl Taint {
    /// All levels in ascending order.
    pub const ALL: [Taint; 4] = [Taint::T0, Taint::T1, Taint::T2, Taint::T3];
    /// Numeric rank 0..=3.
    pub fn rank(self) -> u8 {
        self as u8
    }
    /// Parse `"T0".."T3"`.
    pub fn parse(s: &str) -> EnclaveResult<Self> {
        Ok(match s {
            "T0" => Taint::T0,
            "T1" => Taint::T1,
            "T2" => Taint::T2,
            "T3" => Taint::T3,
            _ => fail!(EINVAL, "BAD_TAINT_LABEL", "{s:?}"),
        })
    }
}

/// A point `(c, t)` of the product lattice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Label {
    /// Confidentiality.
    pub c: Conf,
    /// Taint.
    pub t: Taint,
}

impl Label {
    /// Bottom element `(C1, T0)`.
    pub const BOTTOM: Label = Label {
        c: Conf::C1,
        t: Taint::T0,
    };
    /// Top element `(C4, T3)`.
    pub const TOP: Label = Label {
        c: Conf::C4,
        t: Taint::T3,
    };
    /// Default attachment label `(C3, T3)` (FS-704 §3.1.1).
    pub const ATTACHMENT_DEFAULT: Label = Label {
        c: Conf::C3,
        t: Taint::T3,
    };
    /// Label of the short user directive `(C1, T1)`.
    pub const DIRECTIVE: Label = Label {
        c: Conf::C1,
        t: Taint::T1,
    };

    /// Construct a label.
    pub const fn new(c: Conf, t: Taint) -> Self {
        Self { c, t }
    }
    /// Partial order `self ⊑ other`.
    pub fn leq(self, other: Label) -> bool {
        self.c <= other.c && self.t <= other.t
    }
    /// Join (least upper bound).
    pub fn join(self, other: Label) -> Label {
        Label {
            c: self.c.max(other.c),
            t: self.t.max(other.t),
        }
    }
    /// Meet (greatest lower bound).
    pub fn meet(self, other: Label) -> Label {
        Label {
            c: self.c.min(other.c),
            t: self.t.min(other.t),
        }
    }
    /// Join over an iterator, starting from `floor` (the tool's intrinsic floor).
    pub fn join_all<I: IntoIterator<Item = Label>>(floor: Label, it: I) -> Label {
        it.into_iter().fold(floor, Label::join)
    }
    /// Bell-LaPadula no-write-down: a value may reach a sink only if `c_val <= c_sink`.
    pub fn may_flow_to(self, sink_clearance: Conf) -> bool {
        self.c <= sink_clearance
    }
    /// Every lattice element (16 points), for exhaustive law checking.
    pub fn all() -> impl Iterator<Item = Label> {
        Conf::ALL
            .into_iter()
            .flat_map(|c| Taint::ALL.into_iter().map(move |t| Label { c, t }))
    }
}

/// The role a value occupies in a compiled plan or tool call (FS-704 §3.1 Axis 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SlotKind {
    /// Control flow, tool-name selection, SQL/shell/path AST templates.
    AstStructural,
    /// Opaque bound literal value slot.
    BoundLiteral,
}

impl SlotKind {
    /// Biba admission: `T3` (and anything above `T2`) never occupies an
    /// `AST_STRUCTURAL` slot. Fails closed with `EPERM: T3_BIBA_VIOLATION`.
    pub fn admit(self, label: Label) -> EnclaveResult<()> {
        if self == SlotKind::AstStructural && label.t >= Taint::T3 {
            fail!(
                EPERM,
                "T3_BIBA_VIOLATION",
                "T3 value in AST_STRUCTURAL slot"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lattice_laws_hold_exhaustively() {
        for a in Label::all() {
            assert!(a.leq(a), "reflexive");
            assert_eq!(a.join(a), a, "join idempotent");
            assert_eq!(a.meet(a), a, "meet idempotent");
            assert!(Label::BOTTOM.leq(a) && a.leq(Label::TOP));
            for b in Label::all() {
                assert_eq!(a.join(b), b.join(a), "join commutative");
                assert_eq!(a.meet(b), b.meet(a), "meet commutative");
                assert!(a.leq(a.join(b)) && b.leq(a.join(b)), "join is upper bound");
                assert!(a.meet(b).leq(a) && a.meet(b).leq(b), "meet is lower bound");
                assert_eq!(a.join(a.meet(b)), a, "absorption 1");
                assert_eq!(a.meet(a.join(b)), a, "absorption 2");
                if a.leq(b) && b.leq(a) {
                    assert_eq!(a, b, "antisymmetric");
                }
                for c in Label::all() {
                    assert_eq!(a.join(b).join(c), a.join(b.join(c)), "join associative");
                    if a.leq(b) && b.leq(c) {
                        assert!(a.leq(c), "transitive");
                    }
                    // least upper bound
                    if a.leq(c) && b.leq(c) {
                        assert!(a.join(b).leq(c));
                    }
                }
            }
        }
    }

    #[test]
    fn join_is_monotone_never_decreases() {
        for a in Label::all() {
            for b in Label::all() {
                let j = a.join(b);
                assert!(j.c >= a.c && j.t >= a.t);
            }
        }
    }

    #[test]
    fn biba_rejects_t3_in_ast_slot() {
        let e = SlotKind::AstStructural
            .admit(Label::new(Conf::C1, Taint::T3))
            .unwrap_err();
        assert!(e.is("T3_BIBA_VIOLATION"));
        assert!(SlotKind::BoundLiteral.admit(Label::TOP).is_ok());
        assert!(SlotKind::AstStructural.admit(Label::DIRECTIVE).is_ok());
    }

    #[test]
    fn no_write_down() {
        assert!(!Label::new(Conf::C4, Taint::T0).may_flow_to(Conf::C3));
        assert!(Label::new(Conf::C2, Taint::T3).may_flow_to(Conf::C2));
    }

    #[test]
    fn serde_names_match_schema() {
        let j = serde_json::to_string(&Label::new(Conf::C3, Taint::T3)).unwrap();
        assert_eq!(j, r#"{"c":"C3","t":"T3"}"#);
        assert_eq!(
            serde_json::to_string(&SlotKind::AstStructural).unwrap(),
            "\"AST_STRUCTURAL\""
        );
    }
}
