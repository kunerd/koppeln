# syntax=docker/dockerfile:experimental
FROM rust:1.57-slim-buster as build
WORKDIR /usr/src/koppeln
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-deb

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/koppeln/target \
    cargo build

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
