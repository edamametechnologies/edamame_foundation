# EDAMAME Whitelist System

## Overview

The EDAMAME whitelist system provides a flexible and powerful way to control network access through a hierarchical structure with clear matching priorities. This document explains how whitelists work, how to create them, and provides examples for common use cases.

## Whitelist Structure

### Basic Components

```rust
// Main whitelist container
struct Whitelists {
    date: String,                    // Creation/update date
    signature: Option<String>,       // Optional cryptographic signature
    whitelists: Map<String, WhitelistInfo> // Named whitelist collection
}

// Individual whitelist definition
struct WhitelistInfo {
    name: String,                // Unique identifier
    extends: Option<Vec<String>>, // Parent whitelists to inherit from
    endpoints: Vec<WhitelistEndpoint> // List of allowed endpoints
}

// Network endpoint specification
struct WhitelistEndpoint {
    domain: Option<String>,     // Domain name (supports wildcards)
    ip: Option<String>,         // IP address or CIDR range
    port: Option<u16>,          // Port number
    protocol: Option<String>,   // Protocol (TCP, UDP, etc.)
    as_number: Option<u32>,     // Autonomous System number
    as_country: Option<String>, // Country code for the AS
    as_owner: Option<String>,   // AS owner/organization name
    process: Option<String>,    // Process name
    description: Option<String> // Human-readable description
}
```

## Whitelist Building and Inheritance

### Basic Whitelist Setup

Whitelists are defined in JSON format and loaded at startup. Each whitelist consists of a unique name and a list of endpoint specifications:

```json
{
  "date": "October 24th 2023",
  "whitelists": [
    {
      "name": "basic_services",
      "endpoints": [
        {
          "domain": "api.example.com", 
          "port": 443, 
          "protocol": "TCP",
          "description": "Example API server"
        }
      ]
    }
  ]
}
```

### Inheritance System

Whitelists can inherit from other whitelists using the `extends` field, creating a hierarchical structure:

```json
{
  "whitelists": [
    {
      "name": "base_services",
      "endpoints": [
        { "domain": "api.example.com", "port": 443, "protocol": "TCP" }
      ]
    },
    {
      "name": "extended_services",
      "extends": ["base_services"],
      "endpoints": [
        { "domain": "cdn.example.com", "port": 443, "protocol": "TCP" }
      ]
    }
  ]
}
```

When a whitelist extends another:

1. **Endpoint Aggregation**: All endpoints from the parent whitelist(s) are included in the child.
2. **Multiple Inheritance**: A whitelist can extend multiple parent whitelists.
3. **Circular Detection**: The system detects and prevents infinite recursion in circular inheritance patterns.
4. **Inheritance Depth**: There is no limit to the inheritance chain depth.

When retrieving endpoints from a whitelist:
```
function get_all_endpoints(whitelist_name):
    visited = HashSet()
    visited.add(whitelist_name)
    
    info = whitelists.get(whitelist_name)
    endpoints = info.endpoints.clone()
    
    if info.extends exists:
        for parent in info.extends:
            if parent not in visited:
                visited.add(parent)
                endpoints.extend(get_all_endpoints(parent, visited))
    
    return endpoints
```

## Matching Algorithm

The whitelist system follows a precise matching order when determining if a network connection should be allowed:

### 1. Fundamental Match Criteria

These are always checked first and are required for any further matching:

```
if (!port_matches || !protocol_matches || !process_matches):
    return NO_MATCH
```

- **Protocol**: Must match case-insensitively if specified (e.g., "TCP" matches "tcp").
- **Port**: Must match exactly if specified.
- **Process**: Must match case-insensitively if specified.

### 2. Hierarchical Match Order

If fundamental criteria pass, the system evaluates in this strict order:

1. **Domain Matching**: If domain is specified and matches, immediately accept.
2. **IP Matching**: If domain didn't match or wasn't specified, check IP.
3. **AS Information**: Only checked if neither domain nor IP matched, or AS info is specifically required.

```
// Domain priority
if (domain_specified && domain_matches):
    return MATCH

// IP priority
if (ip_specified && ip_matches):
    return MATCH

// Entity match validation
if ((domain_specified || ip_specified) && !(domain_matches || ip_matches)):
    return NO_MATCH

// AS info matching (when needed)
if (should_check_as_info && !as_info_matches):
    return NO_MATCH

// If we've made it this far, all checks have passed
return MATCH
```

## Pattern Matching Details

### Domain Wildcard Matching

The system supports three types of domain wildcards with specific behaviors:

#### 1. Prefix Wildcards (`*.example.com`)

```
function prefix_wildcard_match(domain, pattern):
    // Remove "*."; remaining pattern is the suffix
    suffix = pattern.substring(2)
    
    // Domain must not exactly match suffix (requires subdomain)
    if (domain == suffix):
        return false
        
    // Domain must end with suffix
    if (!domain.endsWith(suffix)):
        return false
        
    // Ensure there's a dot before the suffix (valid subdomain boundary)
    prefixLen = domain.length - suffix.length - 1
    return prefixLen > 0 && domain[prefixLen] == '.'
```

**Examples:**
- `*.example.com` ✓ Matches: `sub.example.com`, `a.b.example.com`
- `*.example.com` ✗ Does NOT match: `example.com`, `otherexample.com`

#### 2. Suffix Wildcards (`example.*`)

```
function suffix_wildcard_match(domain, pattern):
    // Remove ".*"; remaining pattern is the prefix
    prefix = pattern.substring(0, pattern.length - 2)
    
    // Domain must start with prefix
    if (!domain.startsWith(prefix)):
        return false
        
    // Exact prefix match is valid
    if (domain.length == prefix.length):
        return true
        
    // If longer than prefix, next char must be a dot (TLD boundary)
    return domain.length > prefix.length && 
           domain[prefix.length] == '.'
```

**Examples:**
- `example.*` ✓ Matches: `example.com`, `example.org`, `example.co.uk`
- `example.*` ✗ Does NOT match: `www.example.com`, `myexample.com`

#### 3. Middle Wildcards (`api.*.example.com`)

```
function middle_wildcard_match(domain, pattern):
    parts = pattern.split('*')
    prefix = parts[0]
    suffix = parts[1]
    
    return domain.startsWith(prefix) && 
           domain.endsWith(suffix) && 
           domain.length > (prefix.length + suffix.length)
```

**Examples:**
- `api.*.example.com` ✓ Matches: `api.v1.example.com`, `api.staging.example.com`
- `api.*.example.com` ✗ Does NOT match: `api.example.com`, `v1.api.example.com`

### IP Address Matching

IP matching supports both exact matching and CIDR notation:

```
function ip_matches(session_ip, whitelist_ip):
    if (whitelist_ip contains '/'):  // CIDR notation
        return session_ip is within CIDR range
    else:
        return session_ip == whitelist_ip exactly
```

**Examples:**
- Exact: `192.168.1.1` only matches that specific IP
- CIDR: `192.168.1.0/24` matches any IP from `192.168.1.0` to `192.168.1.255`
- IPv6 support: `2001:db8::/32` matches any IPv6 address in that prefix

### AS Information Matching

AS matching includes number, country, and owner verification:

```
// Autonomous System Number
if (whitelist_asn_specified && session_asn != whitelist_asn):
    return NO_MATCH
    
// Country (case-insensitive)
if (whitelist_country_specified && !session_country.equalsIgnoreCase(whitelist_country)):
    return NO_MATCH
    
// Owner (case-insensitive)
if (whitelist_owner_specified && !session_owner.equalsIgnoreCase(whitelist_owner)):
    return NO_MATCH
```

## Matching Process In Detail

The complete matching process for determining if a session matches a whitelist:

1. **Retrieve Endpoints**: Collect all endpoints from the whitelist, including inherited ones.
2. **Empty Check**: If the whitelist contains no endpoints, immediate no-match.
3. **Iterate Endpoints**: For each endpoint in the whitelist:
   a. Check fundamental criteria (protocol, port, process)
   b. Check domain match if specified (highest priority)
   c. Check IP match if specified
   d. Check AS information if required
   e. If all required checks pass, return match
4. **Default**: If no endpoints match, return no-match with reason

```pseudocode
function is_session_in_whitelist(session, whitelist_name):
    visited = HashSet()
    visited.add(whitelist_name)
    
    endpoints = get_all_endpoints(whitelist_name, visited)
    
    if endpoints.isEmpty():
        return (false, "Whitelist contains no endpoints")
    
    for endpoint in endpoints:
        if endpoint_matches(session, endpoint):
            return (true, null)
    
    return (false, "No matching endpoint found")
```

## Best Practices

1. **Start Specific**
   - Begin with the most specific rules possible
   - Use domain names over IP addresses when available
   - Specify ports and protocols explicitly

2. **Use Inheritance**
   - Create base whitelists for common services
   - Extend for environment-specific needs
   - Keep whitelists modular and reusable

3. **Document Endpoints**
   - Use clear descriptions for each endpoint
   - Explain the purpose of each whitelist
   - Document inheritance relationships

4. **Regular Maintenance**
   - Review and update whitelists regularly
   - Remove unused endpoints
   - Audit inheritance chains

5. **Security Considerations**
   - Prefer domain matches over IP matches
   - Use process restrictions for sensitive connections
   - Implement the principle of least privilege

## Testing and Validation

To validate whitelist configurations:

1. **Create Test Whitelist**
```bash
edamame_posture create-custom-whitelists > test.json
```

2. **Apply and Test**
```bash
edamame_posture set-custom-whitelists "$(cat test.json)"
edamame_posture get-sessions
```

3. **Monitor Results**
   - Check logs for blocked connections
   - Verify expected connections work
   - Validate inheritance chains

## Troubleshooting

Common issues and solutions:

1. **Connection Blocked**
   - Check protocol and port match
   - Verify domain/IP pattern syntax
   - Confirm process name if specified

2. **Inheritance Issues**
   - Verify parent whitelist exists
   - Check for circular dependencies
   - Confirm whitelist names match

3. **Pattern Matching**
   - Test wildcard patterns individually
   - Verify CIDR notation
   - Check case sensitivity

## Reference

### Supported Protocols
- TCP
- UDP
- ICMP
- (others as configured)

### Special Values
- `"*"` - Wildcard in domain patterns
- `"0.0.0.0/0"` - All IPv4 addresses
- `::/0` - All IPv6 addresses

### Environment Variables
- `EDAMAME_WHITELIST_PATH` - Custom whitelist location
- `EDAMAME_WHITELIST_LOG_LEVEL` - Logging verbosity

## Further Reading

- [Threat Models](https://github.com/edamametechnologies/threatmodels)
- [EDAMAME Posture](https://github.com/edamametechnologies/edamame_posture_action)
- [CI/CD Integration](https://github.com/edamametechnologies/edamame_posture_action)