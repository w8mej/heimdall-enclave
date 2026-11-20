//! Actual production ticket/replay/DPoP calls for bounded Lean correspondence.
use enclave_tool_host::ticket::{ExecutionTicket, RowFormat, TicketReplayFilter};
use std::os::unix::fs::PermissionsExt;

fn rolling_vectors() {
    use enclave_core::label::Conf;
    use enclave_core::profile::Profile;
    use enclave_core::qif::{QifCharge, QifLedger, GLOBAL_POOL_KEY, WINDOW_MS};
    let entity = |number: u8| format!("ek_{}", hex::encode([number; 16]));
    let bucket = |snapshot: &serde_json::Value, key: &str| -> String {
        let Some(events) = snapshot["buckets"][key]["events"].as_array() else {
            return "-".into();
        };
        if events.is_empty() {
            return "-".into();
        }
        events
            .iter()
            .map(|e| format!("{}:{}", e[0], e[1]))
            .collect::<Vec<_>>()
            .join(";")
    };
    let mut index = 0;
    for profile in [Profile::L2, Profile::L3] {
        for cap in [0, 4000, 12000] {
            for conf in [Conf::C2, Conf::C3, Conf::C4] {
                for unstructured in [false, true] {
                    for raw in [vec![], vec![1], vec![1, 1], vec![1, 2], vec![2, 1, 2]] {
                        let mut ledger = QifLedger::new(profile).with_entity_cap(cap).unwrap();
                        for (now, amount) in [
                            (0, 1000),
                            (1, 3000),
                            (2, 8000),
                            (WINDOW_MS - 1, 1),
                            (WINDOW_MS, 1000),
                            (0, 1000),
                            (u64::MAX - 1, 12000),
                            (u64::MAX, 1),
                            (WINDOW_MS + 1, 1),
                        ] {
                            let allowed = ledger
                                .charge(
                                    &QifCharge {
                                        entities: raw.iter().copied().map(entity).collect(),
                                        conf,
                                        unstructured,
                                        millibits: amount,
                                    },
                                    now,
                                )
                                .is_ok();
                            let snapshot = serde_json::to_value(&ledger).unwrap();
                            // Exercise the same generic validated restoration as daemon stores.
                            let restored: QifLedger =
                                serde_json::from_value(snapshot.clone()).unwrap();
                            assert_eq!(restored, ledger);
                            ledger = restored;
                            println!(
                                "L,{index},{},{},{},{},{}",
                                u8::from(allowed),
                                snapshot["high_water_ms"],
                                bucket(&snapshot, GLOBAL_POOL_KEY),
                                bucket(&snapshot, &entity(1)),
                                bucket(&snapshot, &entity(2))
                            );
                            index += 1;
                        }
                    }
                }
            }
        }
    }
}

fn egress_vectors() {
    use enclave_core::egress::EgressRegistry;
    let first = "00000000-0000-4000-8000-000000000001";
    let second = "00000000-0000-4000-8000-000000000002";
    let mut index = 0;
    for code in 0..6usize.pow(4) {
        let mut registry = EgressRegistry::ephemeral();
        for position in 0..4 {
            let result = match code / 6usize.pow(position) % 6 {
                0 => registry.issued(first, 1),
                1 => registry.released(first, 1),
                2 => registry.reserve_tombstone(first, 1),
                3 => registry.reserve_nonrelease(first, 1),
                4 => registry.released(second, 1),
                _ => registry.reserve_tombstone(second, 1),
            };
            let bits = |epoch| {
                format!(
                    "{}:{}:{}",
                    u8::from(registry.was_issued(epoch, 1)),
                    u8::from(registry.was_released(epoch, 1)),
                    u8::from(registry.was_tombstoned(epoch, 1))
                )
            };
            println!(
                "E,{index},{},{},{}",
                u8::from(result.is_ok()),
                bits(first),
                bits(second)
            );
            index += 1;
        }
    }
}

fn main() {
    let strings = ["", "a", "a\0b", "é"];
    let numbers = [
        (0, 0, 0),
        (1, 0, 1),
        (255, 255, 256),
        (256, 256, 65535),
        (65536, 4294967295, 4294967296),
        (u64::MAX, 0, u64::MAX),
        (7, u64::MAX - 1, u64::MAX),
        (1, u64::MAX, u64::MAX),
    ];
    let mut index = 0;
    for id in strings {
        for server in strings {
            for tool in strings {
                for args in strings {
                    for module in [None, Some([0; 32]), Some([255; 32])] {
                        for format in [RowFormat::JsonArray, RowFormat::Utf8Lines] {
                            for (rows, issued, expires) in numbers {
                                let t = ExecutionTicket {
                                    ticket_id: id.into(),
                                    server: server.into(),
                                    tool_name: tool.into(),
                                    args_blake3: args.into(),
                                    row_bound: rows,
                                    issued_at_unix_ns: issued,
                                    expires_at_unix_ns: expires,
                                    module_blake3: module,
                                    row_format: format,
                                    signature: String::new(),
                                };
                                println!("T,{index},{}", hex::encode(t.signing_bytes()));
                                index += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().canonicalize().unwrap().join("replay.db");
    let mut replay = TicketReplayFilter::initialize(&path, 2).unwrap();
    for (i, (id, expiry, now, reopen)) in [
        (1, 10, 0, false),
        (1, 10, 0, false),
        (2, 20, 0, false),
        (3, 20, 0, false),
        (3, 20, 11, false),
        (1, 10, 11, false),
        (2, 20, 0, false),
        (2, 20, 12, true),
        (1, 30, 21, false),
    ]
    .into_iter()
    .enumerate()
    {
        if reopen {
            drop(replay);
            replay = TicketReplayFilter::open(&path).unwrap();
        }
        println!(
            "R,{i},{}",
            u8::from(replay.consume(&id.to_string(), expiry, now).is_ok())
        );
    }
    let signed = [i64::MIN, -61, -60, -1, 0, 1, 60, 61, i64::MAX];
    let mut index = 0;
    for now in signed {
        for issued in signed {
            for skew in [-1, 0, 60, i64::MAX] {
                println!(
                    "D,{index},{}",
                    u8::from(enclave_crypto::dpop::iat_within_skew(now, issued, skew))
                );
                index += 1;
            }
        }
    }
    let mut arities: Vec<u64> = (0..=4096).collect();
    for bits in 13..=63 {
        let power = 1u64 << bits;
        arities.extend([power - 1, power, power + 1]);
    }
    arities.push(u64::MAX);
    for (index, k) in arities.into_iter().enumerate() {
        println!(
            "Q,{index},{k},{}",
            enclave_core::qif::millibits_for_outcomes(k)
        );
    }
    rolling_vectors();
    egress_vectors();
}
