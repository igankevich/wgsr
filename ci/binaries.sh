#!/bin/sh
. ./ci/preamble.sh
export RUSTFLAGS="-Ccodegen-units=1 -Copt-level=z -Cincremental=false -Clto=yes -Cembed-bitcode=yes -Cstrip=symbols"
cargo build \
    --release \
    --target x86_64-unknown-linux-musl \
    --no-default-features
