#[cfg(target_os = "linux")]
/// Try to add a route to the given subnet to the loopback interface.
pub(crate) fn sysctl_route_add_ipv6_subnet(subnet: &cidr::Ipv6Cidr) {
    if !nix::unistd::Uid::effective().is_root() {
        return;
    }

    let res = std::process::Command::new("ip")
        .args(&["route", "add", "local", &format!("{subnet}"), "dev", "lo"])
        .output();
    if let Err(err) = res {
        println!("Failed to add route to the loopback interface: {}", err);
    }
}

#[cfg(target_os = "linux")]
/// Try to remove a route to the given subnet to the loopback interface.
pub(crate) fn sysctl_ipv6_no_local_bind() {
    if !nix::unistd::Uid::effective().is_root() {
        return;
    }

    use sysctl::Sysctl;
    const CTLNAME: &str = "net.ipv6.ip_nonlocal_bind";

    let ctl = <sysctl::Ctl as Sysctl>::new(CTLNAME)
        .expect(&format!("could not get sysctl '{}'", CTLNAME));
    let _ = ctl.name().expect("could not get sysctl name");

    let old_value = ctl.value_string().expect("could not get sysctl value");

    let target_value = match old_value.as_ref() {
        "0" => "1",
        "1" | _ => &old_value,
    };

    ctl.set_value_string(target_value).unwrap_or_else(|e| {
        panic!(
            "could not set sysctl '{}' to '{}': {}",
            CTLNAME, target_value, e
        )
    });
}
