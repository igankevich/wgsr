#!/bin/sh
exec docker run \
    --rm \
    -it \
    --name wgx-ci \
    --volume "$PWD"/:/src \
    --volume "$PWD"/../wgproto/:/wgproto \
    --workdir /src \
    --env CARGO_HOME=/src/target/.cargo \
    ghcr.io/igankevich/wgx-ci:latest \
    cargo build --release --target x86_64-unknown-linux-musl
