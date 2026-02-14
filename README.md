[![CI](https://github.com/kunerd/koppeln/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kunerd/koppeln/actions/workflows/ci.yml)

# Koppeln

Koppeln is a minimalistic standalone dynamic DNS server.

**:warning: WARNING: not ready for production**

## Usage

At the moment Koppeln is under heavy development and therefore not yet ready
for production use. To build and run Koppeln from source you can either use
`cargo` or `docker`. See instructions below. In any case the first step is to
get the newest version from github:

```
git clone https://github.com/kunerd/koppeln.git
```

Keep in mind that the current version is only tested to work under the Linux
operating system. Building and running it under other OS may or may not work.
Anyway, feel free to create an issue, if you encounter any problem during build
or while running the server.

## Development

We use `cargo make` to run advanced build steps like end-to-end testing,
packaging .deb files and building in docker containers. Nevertheless, all normal
cargo commands should work fine, too.

### Run E2E tests

The E2E test setup is in an early stage and might not work as expected in some
circumstances. Please create a ticket if you have any trouble to get the tests
to run properly.

Before you can run the E2E tests you need to install the following additional software:
* docker
* docker build plugin
* lxc
* cargo make

After setting up the additional tools you just need to run:
```
$ cargo make e2e-tests
```

### Update a DNS entry

All configuration files under `./config` contain an entry to setup the DNS
address `test.dyn.example.com`.

```
[addresses]
"test.dyn.example.com" = { token = "super_secure" }
```

At startup time there will be no IP address for this DNS entry. The IP address
can be set/updated with the folling RESTful API call:

```
$ curl -X PUT \
	-H "Content-Type: application/json" \
	-H "Authorization: super_secure" \
	--data '{"ip":"12.13.14.15", "hostname":"test.dyn.example.com"}' \
	http://localhost:8088/hostname
```

## Contribution

All kinds of contributions are highly welcome. [Create
tickets](https://github.com/kunerd/koppeln/issues/new) with feature requests,
design ideas and so on. You can also find me on Rusts Discord channels
`#rust-usage` and `#beginners`.

## License

This project is licensed under MIT license ([LICENSE](LICENSE) or
https://opensource.org/licenses/MIT)

