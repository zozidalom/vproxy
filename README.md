# v6p

Make the request using a random IPv6 address within the IPv6 subnet

### Usage

Taking [tunnelbroker](https://tunnelbroker.net/) / `Debian10` as an example, make sure your server supports `IPv6` and has configured the tunnel

```shell
sysctl net.ipv6.ip_nonlocal_bind=1

# Replace your IPv6 subnet
ip route add local 2001:db8::/32 dev lo

nohup v6p -i 2001:470:e953::/48 &

while true; do curl -x http://127.0.0.1:8100 -s https://api.ip.sb/ip -A Mozilla; done
...
2001:470:e953:5b75:c862:3328:3e8f:f4d1
2001:470:e953:b84d:ad7d:7399:ade5:4c1c
2001:470:e953:4f88:d5ca:84:83fd:6faa
2001:470:e953:29f3:41e2:d3f2:4a49:1f22
2001:470:e953:98f6:cb40:9dfd:c7ab:18c4
2001:470:e953:f1d7:eb68:cc59:b2d0:2c6f
```

### Command Manual

##### Description

> If no subnet is configured, the local default network proxy request will be used. When the local machine sets the priority `Ipv4`/`Ipv6` and the priority is `Ipv4`, it will always use `Ipv4` to make requests (if any).

- `--bind`, Http service listening address, default 0.0.0.0:8100
- `--fallback`, The binding address used when IPv6 access is unreachable, must be ipv4
- `--ipv6-subnet`, IPv6 subnet

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