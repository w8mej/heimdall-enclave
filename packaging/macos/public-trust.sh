#!/usr/bin/env bash
# Public trust inventory only. No signing key is accepted or copied. Authenticity
# is established by the organizational package/bootstrap root and runtime TUF,
# never by this structural check or by the presence of signature-shaped JSON.
PUBLIC_TUF_FILES='root.json timestamp.json snapshot.json targets.json enclave-host-config.json enclave-policy.cedar.v1.json vk_manifest.json enclave-distribution-v1.json'
check_public_trust_file() {
	trust_path=$1
	[ -f "$trust_path" ] && [ ! -L "$trust_path" ] && [ -s "$trust_path" ] || {
		echo "PUBLIC_TRUST_REQUIRED: ${trust_path##*/}" >&2
		return 1
	}
	trust_size=$(wc -c <"$trust_path")
	[ "$trust_size" -le 16777216 ] || {
		echo "PUBLIC_TRUST_OVERSIZED: ${trust_path##*/}" >&2
		return 1
	}
	if grep -Eq -- '-----BEGIN .*PRIVATE KEY-----|"(private|private_key|secret|secret_key|seed|signing_seed)"[[:space:]]*:' "$trust_path"; then
		echo "PUBLIC_TRUST_PRIVATE_MATERIAL: ${trust_path##*/}" >&2
		return 1
	fi
}
require_public_trust() {
	trust_repo=$1
	[ -d "$trust_repo" ] && [ ! -L "$trust_repo" ] || {
		echo 'PUBLIC_TRUST_REPO_REQUIRED' >&2
		return 1
	}
	for trust_name in $PUBLIC_TUF_FILES; do
		check_public_trust_file "$trust_repo/$trust_name" || return 1
	done
	trust_root_count=0
	for trust_path in "$trust_repo"/* "$trust_repo"/.[!.]* "$trust_repo"/..?*; do
		[ -e "$trust_path" ] || [ -L "$trust_path" ] || continue
		trust_name=${trust_path##*/}
		case " $PUBLIC_TUF_FILES " in
		*" $trust_name "*) ;;
		*)
			case "$trust_name" in
			*.root.json)
				trust_number=${trust_name%.root.json}
				case "$trust_number" in '' | 0* | *[!0-9]*)
					echo "PUBLIC_TRUST_UNSUPPORTED_FILE: $trust_name" >&2
					return 1
					;;
				esac
				[ "${#trust_number}" -le 10 ] && [ "$trust_number" -le 2147483647 ] || {
					echo 'PUBLIC_TRUST_ROOT_VERSION' >&2
					return 1
				}
				trust_root_count=$((trust_root_count + 1))
				[ "$trust_root_count" -le 32 ] || {
					echo 'PUBLIC_TRUST_ROOT_CHAIN_LIMIT' >&2
					return 1
				}
				check_public_trust_file "$trust_path" || return 1
				;;
			*)
				echo "PUBLIC_TRUST_UNSUPPORTED_FILE: $trust_name" >&2
				return 1
				;;
			esac
			;;
		esac
	done
}
# shellcheck disable=SC2329
copy_public_trust() {
	require_public_trust "$1" || return 1
	mkdir -p "$2"
	for trust_path in "$1"/*; do cp "$trust_path" "$2/${trust_path##*/}" || return 1; done
}
