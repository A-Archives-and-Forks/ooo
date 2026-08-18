#!/bin/sh
set -eu

cd "$(dirname "$0")"

bun build \
    --compile \
    --target=browser \
    --minify \
    --outdir=server \
    public/index.html
