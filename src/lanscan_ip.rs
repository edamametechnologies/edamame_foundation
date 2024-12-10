use regex::Regex;

pub fn is_valid_ip_address(ip_address: &str) -> bool {
    // Check if the IP address is valid (v4 or v6)
    let ip_regex = Regex::new(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}$").unwrap();
    ip_regex.is_match(ip_address)
}
