// Built in default whitelists db
pub static WHITELISTS: &str = r#"{
  "date": "October 23th 2024",
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
          "domain": "raw.githubusercontent.com",
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
          "domain": "*.actions.githubusercontent.com",
          "port": 443,
          "description": "Connection to GitHub Actions"
        },
        {
          "port": 123,
          "description": "Connection to NTP"
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
          "asn": 714,
          "port": 443,
          "description": "Connection to Apple Servers (https)(ASN: 714, Country: US, Owner: APPLE-ENGINEERING)"
        },
        {
          "asn": 714,
          "port": 5223,
          "description": "Connection to Apple Servers (apple push) (ASN: 714, Country: US, Owner: APPLE-ENGINEERING)"
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
        }
      ]
    }
  ],
  "signature": "0876cecf231a2cabf5f4897596eb2ed86507f7859313d429e7bf914f348ac88d"
}"#;
