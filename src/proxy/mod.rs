mod http;
mod https;
mod socks5;

use tokio::sync::OnceCell;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::BootArgs;

/// Basic auth realm
static BASIC_AUTH_REALM: OnceCell<Option<(String, String)>> = OnceCell::const_new();

#[tokio::main(flavor = "multi_thread")]
pub async fn run(args: BootArgs) -> crate::Result<()> {
    if args.debug {
        std::env::set_var("RUST_LOG", "debug");
    } else {
        std::env::set_var("RUST_LOG", "info");
    }
    // Init tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "RUST_LOG=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Set basic auth realm
    if let (Some(u), Some(p)) = (&args.auth_user, &args.auth_pass) {
        BASIC_AUTH_REALM
            .set(Some((u.to_owned(), p.to_owned())))
            .expect("BASIC_AUTH_REALM should be set only once")
    }

    // Auto set sysctl
    #[cfg(target_os = "linux")]
    args.ipv6_subnet.map(|v6| {
        crate::util::sysctl_ipv6_no_local_bind();
        crate::util::sysctl_route_add_ipv6_subnet(&v6);
    });

    // Choose proxy type
    match args.typed {
        crate::ProxyType::Http => http::run(args).await,
        crate::ProxyType::Https => https::run(args).await,
        crate::ProxyType::Socks5 => socks5::run(args).await,
    }
}
