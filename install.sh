#!/bin/sh
# Served at https://kompromat.sh/cli. Downloads a prebuilt CLI; no Rust required.
set -eu

main() {
    default_release_url='https://kompromat.sh/releases/latest/download'
    release_url=${KOMPROMAT_RELEASE_BASE_URL:-$default_release_url}
    install_dir=${KOMPROMAT_INSTALL_DIR:-"$HOME/.local/bin"}

    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64) target=x86_64-unknown-linux-musl ;;
        Linux-aarch64|Linux-arm64) target=aarch64-unknown-linux-musl ;;
        Darwin-x86_64) target=x86_64-apple-darwin ;;
        Darwin-arm64) target=aarch64-apple-darwin ;;
        *) printf '%s\n' 'Unsupported platform: use Linux or macOS on x86_64 or ARM64.' >&2; exit 1 ;;
    esac

    for dependency in curl tar; do
        command -v "$dependency" >/dev/null 2>&1 || {
            printf 'Required command not found: %s\n' "$dependency" >&2
            exit 1
        }
    done
    if command -v sha256sum >/dev/null 2>&1; then
        hash_command=sha256sum
    elif command -v shasum >/dev/null 2>&1; then
        hash_command=shasum
    else
        printf '%s\n' 'Install sha256sum or shasum to verify the download.' >&2
        exit 1
    fi

    archive="kompromat-$target.tar.gz"
    work_dir=$(mktemp -d)
    staged_binary=
    trap 'rm -rf "$work_dir"; [ -z "$staged_binary" ] || rm -f "$staged_binary"' EXIT
    trap 'exit 1' HUP INT TERM
    printf 'Downloading kompromat for %s...\n' "$target"
    curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 \
        "${release_url%/}/$archive" -o "$work_dir/$archive"
    curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 \
        "${release_url%/}/$archive.sha256" -o "$work_dir/checksum"

    expected=$(awk 'NR == 1 {print $1}' "$work_dir/checksum")
    if [ "$hash_command" = sha256sum ]; then
        actual=$(sha256sum "$work_dir/$archive" | awk '{print $1}')
    else
        actual=$(shasum -a 256 "$work_dir/$archive" | awk '{print $1}')
    fi
    if [ "$expected" != "$actual" ]; then
        printf '%s\n' 'Checksum mismatch; nothing was installed.' >&2
        exit 1
    fi

    tar -xzf "$work_dir/$archive" -C "$work_dir" kompromat
    if [ ! -f "$work_dir/kompromat" ] || [ -L "$work_dir/kompromat" ]; then
        printf '%s\n' 'Release archive does not contain a regular kompromat binary.' >&2
        exit 1
    fi
    mkdir -p "$install_dir"
    if [ -d "$install_dir/kompromat" ]; then
        printf '%s\n' 'Install destination is a directory.' >&2
        exit 1
    fi
    staged_binary=$(mktemp "$install_dir/.kompromat.XXXXXX")
    cp "$work_dir/kompromat" "$staged_binary"
    chmod 755 "$staged_binary"
    mv -f "$staged_binary" "$install_dir/kompromat"
    staged_binary=
    printf 'Installed %s/kompromat\n' "$install_dir"
    case ":$PATH:" in
        *:"$install_dir":*) ;;
        *) printf 'Add %s to PATH, or run %s/kompromat directly.\n' "$install_dir" "$install_dir" ;;
    esac
}

main "$@"
