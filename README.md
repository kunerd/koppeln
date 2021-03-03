# Koppeln
Koppeln is a minimalistic standalone dynamic DNS server.

**:warning: WARNING: not ready for production**

## Usage
At the moment Koppeln is under heavy development and therefore not yet ready for production use.
To build and run Koppeln from source you can either use `cargo` or `docker`. See instructions below. In any case the first step is to get the newest version from github:

```
git clone https://github.com/kunerd/koppeln.git
```

Keep in mind that the current version is only tested to work under the Linux operating system. Building and running it under other OS may or may not work. Anyway, feel free to create an issue, if you encounter any problem during build or while running the server. 

### Build with Cargo
To build with cargo a version of rust `>=1.47.0` is required. Take a look at [Rust docs](https://doc.rust-lang.org/cargo/getting-started/installation.html) for further information.
After installing rust and cargo you can build and run the server by the following command:

```
$ cargo run
```

This will run the server with the configuration from `config/development.toml` by default. The best way to provide a custom configuration is to create a new file in the `config` repository and set the environment variable `RUN_MODE`.

```
$ cp config/development.toml config/custom.toml
# adjust custom.toml depending on your needs
$ RUN_MODE=custom cargo run
```

### Build with Docker
To build and run Koppeln via Docker a version of Docker `>=18.09` is required, because we will use the [BuildKit](https://docs.docker.com/develop/develop-images/build_enhancements/). 

To build the image run the following command:
```
$ DOCKER_BUILDKIT=1 docker build -t koppeln .

```

To run the server inside a container but accessible from your host use the command below.
```
$ docker run \
-v $(pwd)/config:/etc/dyndns/config \
--rm \
-p 8080:80 \
-p 5353:53 \
koppeln
```

### Build .deb files
```
cargo install --force cargo-make
```

### Update a DNS entry
All configuration files under `./config` contain an entry to setup the DNS address `test.dyn.example.com`.

```
[addresses]
"test.dyn.example.com" = { token = "super_secure" }
```

At startup time there will be no IP address for this DNS entry. The IP address can be set/updated with the folling RESTful API call:

```
$ curl -X PUT \
	-H "Content-Type: application/json" \
	-H "Authorization: super_secure" \
	--data '{"ip":"12.13.14.15", "hostname":"test.dyn.example.com"}' \
	http://localhost:8088/hostname
```

## Contribution
All kinds of contributions are highly welcome. [Create tickets](https://github.com/kunerd/koppeln/issues/new) with feature requests, design ideas and so on. You can also find me on Rusts Discord channels `#rust-usage` and `#beginners`.

## License
This project is licensed under MIT license ([LICENSE](LICENSE) or https://opensource.org/licenses/MIT)

