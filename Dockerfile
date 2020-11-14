# syntax=docker/dockerfile:experimental
FROM rust:1.47-slim-buster as builder
WORKDIR /usr/src/dyndns
RUN cargo install cargo-deb
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
	--mount=type=cache,target=/usr/src/dyndns/target \
	cargo deb --output=./debian/ 


FROM debian:buster-slim
# Add Tini
# This is a workaround until testcontainers support the --init flag
# or dyndns handles OS signals correctly 
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini

WORKDIR /tmp/dyndns
ENV DYNDNS_WEB_ADDRESS=0.0.0.0
ENV DYNDNS_DNS_ADDRESS=0.0.0.0
COPY --from=builder /usr/src/dyndns/debian/dyndns_0.1.0_amd64.deb ./
RUN dpkg -i dyndns_0.1.0_amd64.deb 

ENTRYPOINT ["/tini", "--"]
CMD ["dyndns"]
