pub static WHITELISTS: &str = r#"{
  "date": "October 22nd 2024",
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
          "domain": "d-22jhnwitx0.execute-api.eu-west-1.amazonaws.com",
          "port": 443,
          "description": "EDAMAME backend-assistance-prod"
        },
        {
          "domain": "d-z6dc3lo29h.execute-api.eu-west-1.amazonaws.com",
          "port": 443,
          "description": "EDAMAME backend-score-prod"
        },
        {
          "domain": "ec2-54-217-133-47.compute-1.amazonaws.com",
          "port": 443,
          "description": "Connection to AWS EC2 instance"
        },
        {
          "domain": "ec2-108-128-89-104.compute-1.amazonaws.com",
          "port": 443,
          "description": "Connection to AWS EC2 instance"
        }
      ]
    },
    {
      "name": "github",
      "extends": ["edamame"],
      "endpoints": [
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
          "ip": "104.26.12.205",
          "port": 80,
          "description": "Connection to Cloudflare (ASN: 13335, Country: US, Owner: CLOUDFLARENET)"
        },
        {
          "domain": "*.pool.ntp.org",
          "port": 123,
          "description": "Connection to NTP"
        }
      ]
    },
    {
      "name": "github_macos",
      "extends": ["github"],
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
          "ip": "20.7.220.66",
          "port": 443,
          "description": "Connection to Microsoft ASN (https) (ASN: 8075, Country: US, Owner: MICROSOFT-CORP-MSN-AS-BLOCK)"
        },
        {
          "ip": "104.26.13.205",
          "port": 80,
          "description": "Connection to Cloudflare (http) (ASN: 13335, Country: US, Owner: CLOUDFLARENET)"
        },
        {
          "ip": "104.26.13.205",
          "port": 80,
          "description": "Connection to Cloudflare (http) (ASN: 13335, Country: US, Owner: CLOUDFLARENET)"
        },
        {
          "asn": "714",
          "port": 443,
          "description": "Connection to Apple Servers (https)(ASN: 714, Country: US, Owner: APPLE-ENGINEERING)"
        },
        {
          "asn": "714",
          "port": 5223,
          "description": "Connection to Apple Servers (apple push) (ASN: 714, Country: US, Owner: APPLE-ENGINEERING)"
        }
      ]
    },
    {
      "name": "github_ubuntu",
      "extends": ["github"],
      "endpoints": [
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
          "ip": "20.85.130.105",
          "port": 443,
          "description": "Connection to Microsoft service (https) (ASN: 8075, Country: US, Owner: MICROSOFT-CORP-MSN-AS-BLOCK)"
        },
        {
          "ip": "20.237.33.78",
          "port": 443,
          "description": "Connection to Microsoft service (https) (ASN: 8075, Country: US, Owner: MICROSOFT-CORP-MSN-AS-BLOCK)"
        },
        {
          "asn": "8075",
          "port": 23456,
          "description": "Connection to Microsoft service (aequus) (ASN: 8075, Country: US, Owner: MICROSOFT-CORP-MSN-AS-BLOCK)"
        }
      ]
    }
  ],
  "signature": "99ada0f91fb2df3694cb8feba3cbe31ccafa76ce2dba78b00f01986bda02cf14"
}"#;
