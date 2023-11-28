mod support;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rand::Rng;
use support::TokioIo;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};

use tokio::net::{TcpListener, TcpSocket, TcpStream};

use getopts::Options;
use std::env;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

// To try this example:
// 1. cargo run --example http_proxy
// 2. config http_proxy in command line
//    $ export http_proxy=http://127.0.0.1:8100
//    $ export https_proxy=http://127.0.0.1:8100
// 3. send requests
//    $ curl -i https://www.some_domain.com/
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("b", "bind", "Proxy bind address", "");
    opts.optopt("f", "fallback", "Fallback ipv4", "");
    opts.optopt("i", "ipv6-subnet", "IPv6 Subnet: 2001:db8::/32", "");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("{}", f.to_string())
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return Ok(());
    }

    // Listen address
    let bind_addr = matches.opt_str("b").unwrap_or("0.0.0.0:8100".to_string());
    // IPv6 subnet output
    let ipv6_subnet = matches.opt_str("i");
    // Fallback ipv4
    let interface = matches.opt_str("f");

    if let (Some(v6), Some(v4)) = (ipv6_subnet, interface) {
        let ipv4 = v4
            .parse::<std::net::Ipv4Addr>()
            .expect("invalid ipv4 address");
        let ipv6 = v6.parse::<cidr::Ipv6Cidr>().expect("invalid ipv6 subnet");
        run(bind_addr, Some(ipv6), Some(ipv4)).await?;
    } else {
        run(bind_addr, None, None).await?;
    }

    Ok(())
}

async fn run(
    bind_addr: String,
    ipv6_subnet: Option<cidr::Ipv6Cidr>,
    fallback_ipv4: Option<std::net::Ipv4Addr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(bind_addr.parse::<std::net::SocketAddr>()?);
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(
                    io,
                    service_fn(move |req| Proxy::new(ipv6_subnet, fallback_ipv4).proxy(req)),
                )
                .with_upgrades()
                .await
            {
                println!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

#[derive(Clone)]
struct Proxy {
    ipv6_subnet: Option<cidr::Ipv6Cidr>,
    fallback_ipv4: Option<Ipv4Addr>,
}

impl Proxy {
    fn new(ipv6_subnet: Option<cidr::Ipv6Cidr>, fallback_ipv4: Option<Ipv4Addr>) -> Self {
        Self {
            ipv6_subnet,
            fallback_ipv4,
        }
    }
    async fn proxy(
        self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        println!("req: {:?}", req);

        if Method::CONNECT == req.method() {
            // Received an HTTP request like:
            // ```
            // CONNECT www.domain.com:443 HTTP/1.1
            // Host: www.domain.com:443
            // Proxy-Connection: Keep-Alive
            // ```
            //
            // When HTTP method is CONNECT we should return an empty body
            // then we can eventually upgrade the connection and talk a new protocol.
            //
            // Note: only after client received an empty body with STATUS_OK can the
            // connection be upgraded, so we can't return a response inside
            // `on_upgrade` future.
            if let Some(addr) = Self::host_addr(req.uri()) {
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            if let Err(e) = self.tunnel(upgraded, addr).await {
                                eprintln!("server io error: {}", e);
                            };
                        }
                        Err(e) => eprintln!("upgrade error: {}", e),
                    }
                });

                Ok(Response::new(Self::empty()))
            } else {
                eprintln!("CONNECT host is not socket addr: {:?}", req.uri());
                let mut resp = Response::new(Self::full("CONNECT must be to a socket address"));
                *resp.status_mut() = http::StatusCode::BAD_REQUEST;

                Ok(resp)
            }
        } else {
            let mut connector = HttpConnector::new();
            if let (Some(v6), Some(v4)) = (self.ipv6_subnet, self.fallback_ipv4) {
                let bind_v6_addr =
                    Self::get_rand_ipv6(v6.first_address().into(), v6.network_length());
                connector.set_local_addresses(v4, bind_v6_addr);
                println!(
                    "{} via {bind_v6_addr}",
                    req.uri().host().unwrap_or_default()
                );
            }

            let client = Client::builder(TokioExecutor::new())
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .http2_only(false)
                .build(connector);

            let resp = client.request(req).await.unwrap();
            Ok(resp.map(|b| b.boxed()))
        }
    }

    fn host_addr(uri: &http::Uri) -> Option<String> {
        uri.authority().and_then(|auth| Some(auth.to_string()))
    }

    fn empty() -> BoxBody<Bytes, hyper::Error> {
        Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed()
    }

    fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
        Full::new(chunk.into())
            .map_err(|never| match never {})
            .boxed()
    }

    // Create a TCP connection to host:port, build a tunnel between the connection and
    // the upgraded connection
    async fn tunnel(self, upgraded: Upgraded, addr_str: String) -> std::io::Result<()> {
        if let Ok(addrs) = addr_str.to_socket_addrs() {
            for addr in addrs {
                if let Some(v6) = self.ipv6_subnet {
                    let socket = TcpSocket::new_v6()?;
                    let bind_addr = Self::get_rand_ipv6_socket_addr(
                        v6.first_address().into(),
                        v6.network_length(),
                    );
                    if socket.bind(bind_addr).is_ok() {
                        println!("{addr_str} via {bind_addr}");
                        if let Ok(mut server) = socket.connect(addr).await {
                            tokio::io::copy_bidirectional(&mut TokioIo::new(upgraded), &mut server)
                                .await?;
                            return Ok(());
                        }
                    }
                } else {
                    // Connect to remote server
                    let mut server = TcpStream::connect(addr).await?;
                    let mut upgraded = TokioIo::new(upgraded);

                    // Proxying data
                    let (from_client, from_server) =
                        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

                    // Print message when done
                    println!(
                        "client wrote {} bytes and received {} bytes",
                        from_client, from_server
                    );
                    return Ok(());
                }
            }
        } else {
            println!("error: {addr_str}");
        }

        Ok(())
    }

    fn get_rand_ipv6_socket_addr(ipv6: u128, prefix_len: u8) -> SocketAddr {
        let mut rng = rand::thread_rng();
        SocketAddr::new(
            Self::get_rand_ipv6(ipv6, prefix_len).into(),
            rng.gen::<u16>(),
        )
    }

    fn get_rand_ipv6(mut ipv6: u128, prefix_len: u8) -> Ipv6Addr {
        let rand: u128 = rand::thread_rng().gen();
        let net_part = (ipv6 >> (128 - prefix_len)) << (128 - prefix_len);
        let host_part = (rand << prefix_len) >> prefix_len;
        ipv6 = net_part | host_part;
        ipv6.into()
    }
}
