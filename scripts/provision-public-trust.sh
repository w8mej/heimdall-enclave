#!/bin/sh
# Public provisioning preparation only: no installed host, account, keychain,
# firewall, launchd, service or production-key changes. Fixture keys remain in
# a separate explicitly private directory and are never packaged.
set -eu
cd "$(dirname "$0")/.."
. packaging/macos/public-trust.sh
case "${1:-}" in
--verify-public)
	[ "$#" -eq 2 ] || exit 2
	require_public_trust "$2"
	echo 'Public inventory structurally complete; runtime TUF and authentic bootstrap still required.'
	;;
--fixture)
	[ "$#" -eq 3 ] || {
		echo 'usage: provision-public-trust.sh --fixture NEW_DIRECTORY FIXTURE_DISTRIBUTION_CONFIG' >&2
		exit 2
	}
	fixture_out=$2
	fixture_config=$3
	[ -f "$fixture_config" ] && [ ! -L "$fixture_config" ] || exit 2
	fixture_cli=${MCPMAC_CLI:-target/release/mcp-enclave}
	[ -x "$fixture_cli" ] || {
		echo 'Set MCPMAC_CLI to the reviewed checkout-local CLI' >&2
		exit 2
	}
	# mkdir is exclusive: never reuse or overwrite an existing fixture's keys.
	mkdir -m 0700 "$fixture_out"
	mkdir -m 0700 "$fixture_out/private" "$fixture_out/public"
	fixture_keys="$fixture_out/private/keys.json"
	fixture_repo="$fixture_out/public"
	"$fixture_cli" --json tuf init --keys "$fixture_keys" --repo "$fixture_repo" >/dev/null
	# RFC8032 fixture public key. No possession or enrollment claim is made.
	"$fixture_cli" --json tuf host-config publish --grant-key d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a --profile-floor L1 --keys "$fixture_keys" --repo "$fixture_repo" >/dev/null
	"$fixture_cli" --json tuf policy publish --keys "$fixture_keys" --repo "$fixture_repo" >/dev/null
	"$fixture_cli" --json tuf vk publish --keys "$fixture_keys" --repo "$fixture_repo" >/dev/null
	cp "$fixture_config" "$fixture_repo/enclave-distribution-v1.json"
	"$fixture_cli" --json tuf sign --keys "$fixture_keys" --repo "$fixture_repo" --name enclave-distribution-v1.json --file "$fixture_repo/enclave-distribution-v1.json" --custom '{"media_type":"application/vnd.enclave.distribution.v1+json","min_profile":"L1","classification":"public_l1"}' >/dev/null
	chmod 0600 "$fixture_keys"
	require_public_trust "$fixture_repo"
	echo 'SYNTHETIC FIXTURE ONLY. Public inventory ready; private keys remain outside public/.'
	;;
*)
	echo 'usage: provision-public-trust.sh --verify-public PUBLIC_REPOSITORY | --fixture NEW_DIRECTORY FIXTURE_DISTRIBUTION_CONFIG' >&2
	exit 2
	;;
esac
