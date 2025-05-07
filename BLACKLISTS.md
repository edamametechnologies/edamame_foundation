# EDAMAME Blacklist System

## Overview

The EDAMAME blacklist system provides a flexible and powerful way to block malicious network connections. This document explains how blacklists work, how to create them, and provides examples for common use cases.

## Blacklist Structure

### Basic Components

```rust
// Main blacklist container
struct Blacklists {
    date: String,                    // Creation/update date
    signature: String,               // Cryptographic signature
    blacklists: CustomDashMap<String, BlacklistInfo>, // Named blacklist collection
    parsed_ranges: CustomDashMap<String, Vec<IpNet>> // Cache for parsed IP ranges
}

// Individual blacklist definition
struct BlacklistInfo {
    name: String,                // Unique identifier
    description: Option<String>, // Human-readable description
    last_updated: Option<String>, // Date when last updated
    source_url: Option<String>,  // Source of the blacklist data
    ip_ranges: Vec<String>       // List of blocked IP ranges
}
```

## Blacklist Setup

### Basic Blacklist Setup

Blacklists are defined in JSON format and loaded at startup. Each blacklist consists of a unique name and a list of IP ranges to block:

```json
{
  "date": "March 29 2025",
  "signature": "signature_string",
  "blacklists": [
    {
      "name": "basic_blocklist",
      "description": "Basic malicious IPs blocklist",
      "last_updated": "2025-03-29",
      "source_url": "https://example.com/blacklist-source",
      "ip_ranges": [
        "192.168.0.0/16",
        "10.0.0.0/8"
      ]
    }
  ]
}
```

## IP Matching Algorithm

The blacklist system uses a precise matching algorithm to determine if an IP address is blocked:

```
function is_ip_in_blacklist(ip_str, blacklist_name):
    // Parse the IP address
    ip = parse_ip_address(ip_str)
    
    // Get all IP ranges for this blacklist
    ranges = get_all_ip_ranges(blacklist_name)
    
    // Check if the IP is in any of the ranges
    for range in ranges:
        if range.contains(ip):
            return true
    
    return false
```

## IP Address Matching

IP matching supports both IPv4 and IPv6 addresses, as well as CIDR notation:

```
function ip_matches(ip, range):
    return range.contains(ip)
```

**Examples:**
- Exact: `192.168.1.1` only matches that specific IP
- CIDR: `192.168.1.0/24` matches any IP from `192.168.1.0` to `192.168.1.255`
- IPv6 support: `2001:db8::/32` matches any IPv6 address in that prefix

## Global and Custom Blacklists

EDAMAME supports two types of blacklists:

1. **Global Blacklists**: Predefined and updated from trusted sources
2. **Custom Blacklists**: User-defined for specific environments

When checking if an IP is blacklisted, the system checks both types:

```
async function is_ip_blacklisted(ip, custom_blacklists):
    matching_blacklists = []
    
    // First check custom blacklists
    if custom_blacklists exists:
        for blacklist_name in custom_blacklists:
            if is_ip_in_blacklist(ip, blacklist_name):
                matching_blacklists.push(blacklist_name)
    
    // Then check global blacklists
    for blacklist_name in global_blacklists:
        if is_ip_in_blacklist(ip, blacklist_name):
            matching_blacklists.push(blacklist_name)
    
    is_blacklisted = !matching_blacklists.is_empty()
    
    return (is_blacklisted, matching_blacklists)
```

## Best Practices

1. **Use Precise IP Ranges**
   - Prefer specific CIDR blocks over large ranges
   - Document the source of each IP range
   - Regularly update threat intelligence

2. **Document Blacklists**
   - Use clear descriptions for each blacklist
   - Include source URLs and last update dates

3. **Regular Maintenance**
   - Review and update blacklists regularly
   - Remove outdated IP ranges

4. **Performance Considerations**
   - Use the parsed_ranges cache for faster lookups
   - Monitor the size of blacklists
   - Test with representative traffic patterns

## Testing and Validation

To validate blacklist configurations:

1. **Create Test Blacklist**
```json
{
  "date": "2025-03-29",
  "signature": "test_signature",
  "blacklists": [
    {
      "name": "test_blacklist",
      "description": "Test blacklist for validation",
      "ip_ranges": ["192.168.1.0/24", "10.0.0.0/8"]
    }
  ]
}
```

2. **Apply and Test**
```bash
edamame_posture set-custom-blacklists "$(cat test-blacklist.json)"
edamame_posture check-ip 192.168.1.10
```

3. **Monitor Results**
   - Verify expected IPs are blocked
   - Check for any false positives

## Updating Blacklists

Blacklists can be updated from trusted sources:

```
async function update_blacklists(branch):
    // Fetch the latest blacklist data
    status = await fetch_and_update_blacklists(branch)
    
    return status
```

## Troubleshooting

Common issues and solutions:

1. **IP Not Blocked**
   - Verify IP format and CIDR notation
   - Ensure custom blacklists are properly loaded

2. **Performance Issues**
   - Check the size of blacklists
   - Verify the parsing of IP ranges
   - Monitor memory usage of cached parsed ranges

## Reference

### Supported IP Formats
- IPv4 addresses (e.g., `192.168.1.1`)
- IPv6 addresses (e.g., `2001:db8::1`)
- CIDR notation (e.g., `192.168.0.0/16`, `2001:db8::/32`)

### Special Values
- `0.0.0.0/8` - Reserved addresses
- `10.0.0.0/8` - Private network
- `127.0.0.0/8` - Localhost
- `169.254.0.0/16` - Link-local
- `172.16.0.0/12` - Private network
- `192.168.0.0/16` - Private network

### Environment Variables
- `EDAMAME_BLACKLIST_PATH` - Custom blacklist location
- `EDAMAME_BLACKLIST_UPDATE_URL` - URL for blacklist updates

## Further Reading

- [Threat Models](https://github.com/edamametechnologies/threatmodels)
- [EDAMAME Posture](https://github.com/edamametechnologies/edamame_posture_action)
- [CI/CD Integration](https://github.com/edamametechnologies/edamame_posture_action) 