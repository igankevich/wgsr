#!/bin/sh
exec docker run \
    --rm \
    -it \
    --name wgx-ci \
    --volume "$PWD"/:/src \
    --workdir /src \
    --env CARGO_HOME=/tmp/.cargo \
    ghcr.io/igankevich/wgx-ci:latest \
    /bin/bash
