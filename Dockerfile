# syntax=docker/dockerfile:1.3
FROM rust:slim-trixie as build
WORKDIR /usr/src/koppeln

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-deb

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/koppeln/target \
    cargo build --release

FROM build as test-build
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/koppeln/target \
    cargo test

FROM build as deb-build
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/koppeln/target \
    cargo deb -v --output=./debian

FROM scratch as deb-file 
COPY --from=deb-build /usr/src/koppeln/debian/ /
