FROM rust:1.40.0-slim

WORKDIR /usr/src/mini-dns

COPY . .

RUN cargo install --path .
