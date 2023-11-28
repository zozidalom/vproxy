# v6p

Supports issuing each request from a random IPv6 address within the IPv6 subnet, with fallback to bind ipv4 if the request fails.

### Command Manual

```shell
$ v6p -h
Random IPv6 request proxy

Usage: v6p [options]

Options:
    -b, --bind          Proxy bind address
    -f, --fallback      Fallback ipv4
    -i, --ipv6-subnet   IPv6 Subnet: 2001:db8::/32
    -h, --help          print this help menu
```

### Compile

- Linux compile, Ubuntu machine for example:

```shell
git clone https://github.com/gngpp/v6p.git && cd v6p
cargo build --release
```

### Contributing

If you would like to submit your contribution, please open a [Pull Request](https://github.com/gngpp/v6p/pulls).

### Getting help

Your question might already be answered on the [issues](https://github.com/gngpp/v6p/issues)

## Author

**v6p** © [gngpp](https://github.com/gngpp), Released under the [MIT](./LICENSE) License.