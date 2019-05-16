FROM rust:1.34.1-slim

WORKDIR /usr/src/mini-dns

COPY . .

RUN cargo install --path .
