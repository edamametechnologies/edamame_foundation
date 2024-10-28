// Built in default whitelists db
pub static WHITELISTS: &str = r#"{
  "date": "October 24th 2024",
  "whitelists": [
    {
      "name": "edamame",
      "extends": null,
      "endpoints": [
        {
          "domain": "ip-api.com",
          "port": 80,
          "description": "IP-API"
        },
        {
          "domain": "api.ipify.org",
          "port": 80,
          "description": "IPify"
        },
        {
          "process": "edamame_posture",
          "domain": "*.execute-api.eu-west-1.amazonaws.com",
          "port": 443,
          "description": "EDAMAME backend"
        },
        {
          "process": "edamame_posture",
          "domain": "*.compute-1.amazonaws.com",
          "port": 443,
          "description": "EDAMAME backend"
        },
        {
          "process": "edamame_posture",
          "domain": "*.compute.amazonaws.com",
          "port": 443,
          "description": "EDAMAME backend"
        }
      ]
    },
    {
      "name": "github",
      "extends": [
        "edamame"
      ],
      "endpoints": [
        {
          "domain": "github.com",
          "port": 443,
          "description": "Connection to GitHub"
        },
        {
          "domain": "*.github.com",
          "port": 443,
          "description": "Connection to GitHub"
        },
        {
          "domain": "raw.githubusercontent.com",
          "port": 443,
          "description": "Connection to GitHub raw content (used by EDAMAME)"
        },
        {
          "domain": "*.actions.githubusercontent.com",
          "port": 443,
          "description": "Connection to GitHub Actions"
        },
        {
          "port": 123,
          "description": "Connection to NTP"
        },
        {
          "as_number": 8075,
          "port": 443,
          "description": "Connection to Microsoft (https) (ASN: 8075, Country: US, Owner: MICROSOFT-CORP-MSN-AS-BLOCK)"
        },
        {
          "domain": "*.fastly.net",
          "port": 443,
          "description": "Connection to Fastly (https) - used by dependencies repos, finer grain requires a proxy"
        },
        {
          "domain": "*.cloudfront.net",
          "port": 443,
          "description": "Connection to CloudFront (https) - used by dependencies repos, finer grain requires a proxy"
        }
      ]
    },
    {
      "name": "github_macos",
      "extends": [
        "github"
      ],
      "endpoints": [
        {
          "domain": "homebrew.github.io",
          "port": 443,
          "description": "Connection to Homebrew (https)"
        },
        {
          "domain": "*.aaplimg.com",
          "port": 443,
          "description": "Connection to Apple services (https)"
        },
        {
          "domain": "*.apple-dns.net",
          "port": 443,
          "description": "Connection to Apple DNS"
        },
        {
          "domain": "*.idms-apple.com.akadns.net",
          "port": 443,
          "description": "Connection to Apple DNS"
        },
        {
          "domain": "*.push-apple.com.akadns.net",
          "port": 5223,
          "description": "Connection to Apple DNS"
        }
      ]
    },
    {
      "name": "github_ubuntu",
      "extends": [
        "github"
      ],
      "endpoints": [
        {
          "domain": "*.ubuntu.com",
          "port": 443,
          "description": "Connection to Ubuntu"
        },
        {
          "domain": "api.snapcraft.io",
          "port": 443,
          "description": "Connection to Snapcraft"
        },
        {
          "ip": "168.63.129.16",
          "port": 80,
          "description": "https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16"
        },
        {
          "ip": "168.63.129.16",
          "port": 32526,
          "description": "https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16"
        },
        {
          "as_number": 8075,
          "port": 23456,
          "description": "Connection to Microsoft (23456) (ASN: 8075, Country: US, Owner: MICROSOFT-CORP-MSN-AS-BLOCK)"
        }
      ]
    }
  ],
  "signature": "d761d15a6d3d2f14873f4f875f548c43a73dfa11f4bb729283f7be6982b0bda8"
}"#;
