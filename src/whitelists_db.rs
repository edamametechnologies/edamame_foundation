// Built in default whitelists db
pub static WHITELISTS: &str = r#"{
  "date": "November 05th 2024",
  "whitelists": [
    {
      "name": "edamame",
      "extends": null,
      "endpoints": [
        {
          "process": "edamame_posture",
          "domain": "ip-api.com",
          "port": 80,
          "description": "IP-API"
        },
        {
          "process": "edamame_posture",
          "domain": "api.mixpanel.com",
          "port": 443,
          "description": "Connection to Mixpanel analytics"
        },
        {
          "domain": "api.ipify.org",
          "port": 80,
          "description": "Connection to IPify service"
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
        },
        {
          "process": "edamame_posture",
          "domain": "*.azurefd.net",
          "port": 443,
          "description": "Azure Front Door"
        },
        {
          "process": "edamame_posture",
          "domain": "*.blob.core.windows.net",
          "port": 443,
          "description": "Azure Blob Storage"
        },
        {
          "process": "edamame_posture",
          "domain": "*.bc.googleusercontent.com",
          "port": 443,
          "description": "Google Cloud Platform services"
        }
      ]
    },
    {
      "name": "builder",
      "extends": [
        "edamame"
      ],
      "endpoints": [
        {
          "port": 123,
          "description": "Connection to NTP"
        },
        {
          "process": "dart",
          "domain": "pub.dev",
          "port": 443,
          "description": "Connection to Dart/Flutter package repository"
        },
        {
          "domain": "chromium.googlesource.com",
          "port": 443,
          "description": "Connection to Chromium source code repository"
        },
        {
          "process": "gem",
          "domain": "rubygems.org",
          "port": 443,
          "description": "Connection to Ruby package repository"
        },
        {
          "domain": "*.fastly.net",
          "port": 443,
          "description": "Connection to Fastly (https)"
        },
        {
          "domain": "*.cloudfront.net",
          "port": 443,
          "description": "Connection to CloudFront (https)"
        },
        {
          "domain": "*.amazonaws.com",
          "port": 443,
          "description": "Connection to AWS services"
        },
        {
          "as_number": 396982,
          "port": 443,
          "description": "Connection to Google Cloud Platform (https) (ASN: 396982, Country: US, Owner: GOOGLE-CLOUD-PLATFORM)"
        },
        {
          "as_number": 15169,
          "port": 443,
          "description": "Connection to Google services (https) (ASN: 15169, Country: US, Owner: GOOGLE)"
        },
        {
          "as_number": 16509,
          "port": 443,
          "description": "Connection to Amazon services (https) (ASN: 16509, Country: US, Owner: AMAZON-02)"
        },
        {
          "as_number": 54113,
          "port": 443,
          "description": "Connection to Fastly services (https) (ASN: 54113, Country: US, Owner: FASTLY)"
        },
        {
          "domain": "dns.google",
          "port": 853,
          "description": "Connection to Google DNS over TLS"
        },
        {
          "domain": "dns.google",
          "port": 443,
          "description": "Connection to Google DNS over HTTPS"
        },
        {
          "domain": "androidpublisher.googleapis.com",
          "port": 443,
          "description": "Connection to Google Play Developer API"
        }
      ]
    },
    {
      "name": "github",
      "extends": [
        "builder"
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
          "description": "Connection to GitHub raw content"
        },
        {
          "domain": "*.actions.githubusercontent.com",
          "port": 443,
          "description": "Connection to GitHub Actions"
        },
        {
          "domain": "launch.actions.githubusercontent.com",
          "port": 443,
          "description": "Connection to GitHub Actions launch service"
        },
        {
          "ip": "168.63.129.16",
          "port": 80,
          "description": "Azure DNS and health probe"
        },
        {
          "ip": "168.63.129.16",
          "port": 32526,
          "description": "Azure health probe"
        },
        {
          "as_number": 8075,
          "port": 443,
          "description": "Connection to Microsoft (https) (ASN: 8075, Country: US, Owner: MICROSOFT-CORP-MSN-AS-BLOCK)"
        },
        {
          "as_number": 8075,
          "port": 23456,
          "description": "Connection to Microsoft (23456) (ASN: 8075, Country: US, Owner: MICROSOFT-CORP-MSN-AS-BLOCK)"
        },
        {
          "domain": "*.t-msedge.net",
          "port": 443,
          "description": "Connection to Microsoft Edge services"
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
        },
        {
          "domain": "*.apple.com.akadns.net",
          "port": 443,
          "description": "Connection to Apple services via Akamai DNS"
        },
        {
          "domain": "*.itunes-apple.com.akadns.net",
          "port": 443,
          "description": "Connection to Apple DNS"
        },
        {
          "domain": "*.apple.com",
          "port": 443,
          "description": "Connection to Apple services (https)"
        },
        {
          "domain": "certs.apple.com",
          "port": 80,
          "description": "Connection to Apple certificate services (http)"
        },
        {
          "as_number": 714,
          "port": 443,
          "description": "Connection to Apple Engineering services (https) (ASN: 714, Country: US, Owner: APPLE-ENGINEERING)"
        },
        {
          "as_number": 714,
          "port": 5223,
          "description": "Connection to Apple push services (ASN: 714, Country: US, Owner: APPLE-ENGINEERING)"
        },
        {
          "as_number": 6185,
          "port": 443,
          "description": "Connection to Apple Austin services (https) (ASN: 6185, Country: US, Owner: APPLE-AUSTIN)"
        }
      ]
    },
    {
      "name": "github_linux",
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
          "domain": "cloud-mirror-lb.*.cloudapp.azure.com",
          "port": 80,
          "description": "Connection to Microsoft Azure cloud mirror"
        },
        {
          "domain": "azure.archive.ubuntu.com",
          "port": 80,
          "description": "Connection to Ubuntu Azure mirror"
        },
        {
          "domain": "packages.microsoft.com",
          "port": 443,
          "description": "Connection to Microsoft package repository"
        },
        {
          "domain": "esm.ubuntu.com",
          "port": 443,
          "description": "Connection to Ubuntu ESM"
        },
        {
          "as_number": 41231,
          "port": 443,
          "description": "Connection to Canonical services (https) (ASN: 41231, Country: GB, Owner: CANONICAL-AS)"
        },
        {
          "process": "_apt",
          "domain": "esm.ubuntu.com",
          "port": 443,
          "description": "Connection to Ubuntu ESM for package updates"
        },
        {
          "process": "_apt",
          "domain": "*.t-msedge.net",
          "port": 443,
          "description": "Connection to Microsoft Edge services for package updates"
        },
        {
          "process": "systemd-resolve",
          "domain": "*.t-msedge.net",
          "port": 443,
          "description": "Connection to Microsoft Edge services for DNS resolution"
        },
        {
          "process": "systemd-network",
          "domain": "*.t-msedge.net",
          "port": 443,
          "description": "Connection to Microsoft Edge services for network operations"
        }
      ]
    },
    {
      "name": "github_windows",
      "extends": [
        "github"
      ],
      "endpoints": []
    }
  ],
  "signature": "b89a00841cd48f467ee4c231ca02381369c8c609a6a4ab52dac294ef1aa645d7"
}"#;
