# syntax=docker/dockerfile:experimental
FROM rust:1.47-slim-buster as builder
WORKDIR /usr/src/koppeln
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-deb

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/koppeln/target \
    cargo deb -v --output=./debian

FROM scratch as export  
COPY --from=builder /usr/src/koppeln/debian/ /
