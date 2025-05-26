// Built in default whitelists db
pub static WHITELISTS: &str = r#"{
  "date": "May 15th 2025",
  "signature": "fad360694f7933c544424fee637f7115877d2a9be71139b962f4e7c3deb3f3c7",
  "whitelists": [
    {
      "endpoints": [
        {
          "description": "10.0.0.0/8",
          "ip": "10.0.0.0/8"
        },
        {
          "description": "172.16.0.0/12",
          "ip": "172.16.0.0/12"
        },
        {
          "description": "192.168.0.0/16",
          "ip": "192.168.0.0/16"
        },
        {
          "description": "IP-API",
          "domain": "ip-api.com",
          "port": 80
        },
        {
          "description": "Connection to IPify service",
          "domain": "api.ipify.org",
          "port": 80
        },
        {
          "description": "Connection to Mixpanel analytics",
          "domain": "api.mixpanel.com",
          "port": 443,
          "process": "edamame_posture"
        },
        {
          "description": "EDAMAME backend",
          "domain": "*.execute-api.eu-west-1.amazonaws.com",
          "port": 443,
          "process": "edamame_posture"
        },
        {
          "description": "EDAMAME website",
          "domain": "www.edamame.tech",
          "port": 443,
          "process": "edamame_posture"
        },
        {
          "description": "EDAMAME backend",
          "domain": "*.compute-1.amazonaws.com",
          "port": 443,
          "process": "edamame_posture"
        },
        {
          "description": "EDAMAME backend",
          "domain": "*.compute.amazonaws.com",
          "port": 443,
          "process": "edamame_posture"
        },
        {
          "description": "Azure Front Door",
          "domain": "*.azurefd.net",
          "port": 443,
          "process": "edamame_posture"
        },
        {
          "description": "Azure Blob Storage",
          "domain": "*.blob.core.windows.net",
          "port": 443,
          "process": "edamame_posture"
        },
        {
          "description": "Google Cloud Platform services",
          "domain": "*.bc.googleusercontent.com",
          "port": 443,
          "process": "edamame_posture"
        },
        {
          "as_number": 13335,
          "description": "Cloudflare (https)",
          "port": 443,
          "process": "edamame_posture"
        },
        {
          "as_number": 13335,
          "description": "Cloudflare (http)",
          "port": 80,
          "process": "edamame_posture"
        }
      ],
      "extends": null,
      "name": "edamame"
    },
    {
      "endpoints": [
        {
          "description": "Connection to NTP",
          "port": 123
        },
        {
          "description": "Connection to Dart/Flutter package repository",
          "domain": "pub.dev",
          "port": 443,
          "process": "dart"
        },
        {
          "description": "Connection to Googleusercontent (WARNING too permissive but required for Dart/Flutter and others)",
          "domain": "*.googleusercontent.com",
          "port": 443
        },
        {
          "description": "Connection to Chromium source code repository",
          "domain": "chromium.googlesource.com",
          "port": 443
        },
        {
          "description": "Connection to Ruby package repository",
          "domain": "rubygems.org",
          "port": 443
        },
        {
          "description": "Connection to Fastly (https)",
          "domain": "*.fastly.net",
          "port": 443
        },
        {
          "description": "Connection to CloudFront (https)",
          "domain": "*.cloudfront.net",
          "port": 443
        },
        {
          "description": "Connection to AWS services",
          "domain": "*.amazonaws.com",
          "port": 443
        },
        {
          "as_number": 396982,
          "description": "Connection to Google Cloud Platform (https) (ASN: 396982, Country: US, Owner: GOOGLE-CLOUD-PLATFORM)",
          "port": 443
        },
        {
          "as_number": 15169,
          "description": "Connection to Google services (https) (ASN: 15169, Country: US, Owner: GOOGLE)",
          "port": 443
        },
        {
          "as_number": 16509,
          "description": "Connection to Amazon services (https) (ASN: 16509, Country: US, Owner: AMAZON-02)",
          "port": 443
        },
        {
          "as_number": 54113,
          "description": "Connection to Fastly services (https) (ASN: 54113, Country: US, Owner: FASTLY)",
          "port": 443
        },
        {
          "description": "Connection to Google DNS over TLS",
          "domain": "dns.google",
          "port": 853
        },
        {
          "description": "Connection to Google DNS over HTTPS",
          "domain": "dns.google",
          "port": 443
        },
        {
          "description": "Connection to Google Play Developer API",
          "domain": "androidpublisher.googleapis.com",
          "port": 443
        },
        {
          "description": "Connection to Adoptium API",
          "domain": "api.adoptium.net",
          "port": 443
        },
        {
          "description": "Connection to Gradle plugins artifacts",
          "domain": "plugins-artifacts.gradle.org",
          "port": 443
        },
        {
          "description": "Connection to CocoaPods",
          "domain": "cdn.cocoapods.org",
          "port": 443
        },
        {
          "description": "Connection to GlobalSign (https)",
          "domain": "*.globalsign.com",
          "port": 443
        },
        {
          "description": "Connection to GlobalSign (http)",
          "domain": "*.globalsign.com",
          "port": 80
        },
        {
          "description": "Connection to DigiCert",
          "domain": "*.digicert.com",
          "port": 443
        }
      ],
      "extends": [
        "edamame"
      ],
      "name": "builder"
    },
    {
      "endpoints": [
        {
          "description": "Connection to GitHub",
          "domain": "github.com",
          "port": 443
        },
        {
          "description": "Connection to GitHub",
          "domain": "*.github.com",
          "port": 443
        },
        {
          "description": "Connection to GitHub Container Registry",
          "domain": "ghcr.io",
          "port": 443
        },
        {
          "description": "Connection to GitHub raw content",
          "domain": "raw.githubusercontent.com",
          "port": 443
        },
        {
          "description": "Connection to GitHub Actions",
          "domain": "*.actions.githubusercontent.com",
          "port": 443
        },
        {
          "description": "Connection to GitHub Actions launch service",
          "domain": "launch.actions.githubusercontent.com",
          "port": 443
        },
        {
          "description": "Azure DNS and health probe",
          "ip": "168.63.129.16",
          "port": 80
        },
        {
          "description": "Azure health probe",
          "ip": "168.63.129.16",
          "port": 32526
        },
        {
          "as_number": 8075,
          "description": "Connection to Microsoft (https) (ASN: 8075, Country: US, Owner: MICROSOFT-CORP-MSN-AS-BLOCK)",
          "port": 443
        },
        {
          "as_number": 8075,
          "description": "Connection to Microsoft (23456) (ASN: 8075, Country: US, Owner: MICROSOFT-CORP-MSN-AS-BLOCK)",
          "port": 23456
        },
        {
          "description": "Connection to Microsoft Edge services",
          "domain": "*.t-msedge.net",
          "port": 443
        }
      ],
      "extends": [
        "builder"
      ],
      "name": "github"
    },
    {
      "endpoints": [
        {
          "description": "Connection to Homebrew (https)",
          "domain": "homebrew.github.io",
          "port": 443
        },
        {
          "description": "Connection to Apple services (https)",
          "domain": "*.aaplimg.com",
          "port": 443
        },
        {
          "description": "Connection to Apple DNS",
          "domain": "*.apple-dns.net",
          "port": 443
        },
        {
          "description": "Connection to Apple DNS",
          "domain": "*.idms-apple.com.akadns.net",
          "port": 443
        },
        {
          "description": "Connection to Apple DNS",
          "domain": "*.push-apple.com.akadns.net",
          "port": 5223
        },
        {
          "description": "Connection to Apple services via Akamai DNS",
          "domain": "*.apple.com.akadns.net",
          "port": 443
        },
        {
          "description": "Connection to Apple DNS",
          "domain": "*.itunes-apple.com.akadns.net",
          "port": 443
        },
        {
          "description": "Connection to Apple services (https)",
          "domain": "*.apple.com",
          "port": 443
        },
        {
          "description": "Connection to Apple certificate services (http)",
          "domain": "certs.apple.com",
          "port": 80
        },
        {
          "description": "Connection to Apple News",
          "domain": "c.apple.news",
          "port": 443
        },
        {
          "as_number": 714,
          "description": "Connection to Apple Engineering services (https) (ASN: 714, Country: US, Owner: APPLE-ENGINEERING)",
          "port": 443
        },
        {
          "as_number": 714,
          "description": "Connection to Apple push services (ASN: 714, Country: US, Owner: APPLE-ENGINEERING)",
          "port": 5223
        },
        {
          "as_number": 6185,
          "description": "Connection to Apple Austin services (https) (ASN: 6185, Country: US, Owner: APPLE-AUSTIN)",
          "port": 443
        },
        {
          "description": "Connection to GitHub",
          "ip": "192.168.64.0/24",
          "port": 52616
        },
        {
          "description": "Connection to Apple timestamp service",
          "domain": "timestamp.apple.com",
          "port": 80
        }
      ],
      "extends": [
        "github"
      ],
      "name": "github_macos"
    },
    {
      "endpoints": [
        {
          "description": "Connection to Ubuntu",
          "domain": "*.ubuntu.com",
          "port": 443
        },
        {
          "description": "Connection to Alpine Linux",
          "domain": "*.alpinelinux.org",
          "port": 80
        },
        {
          "description": "Connection to Alpine Linux",
          "domain": "*.alpinelinux.org",
          "port": 443
        },
        {
          "description": "Connection to Snapcraft",
          "domain": "api.snapcraft.io",
          "port": 443
        },
        {
          "description": "Connection to Microsoft Azure cloud mirror",
          "domain": "cloud-mirror-lb.*.cloudapp.azure.com",
          "port": 80
        },
        {
          "description": "Connection to Ubuntu Azure mirror",
          "domain": "azure.archive.ubuntu.com",
          "port": 80
        },
        {
          "description": "Connection to Microsoft package repository",
          "domain": "packages.microsoft.com",
          "port": 443
        },
        {
          "description": "Connection to Ubuntu ESM",
          "domain": "esm.ubuntu.com",
          "port": 443
        },
        {
          "as_number": 41231,
          "description": "Connection to Canonical services (https) (ASN: 41231, Country: GB, Owner: CANONICAL-AS)",
          "port": 443
        },
        {
          "description": "Connection to Ubuntu ports",
          "domain": "ports.ubuntu.com",
          "port": 443
        },
        {
          "description": "Connection to Ubuntu mirrors",
          "domain": "archive.archive.ubuntu.com",
          "port": 443
        },
        {
          "as_number": 41231,
          "description": "Connection to Canonical services (http) (ASN: 41231, Country: GB, Owner: CANONICAL-AS)",
          "port": 80,
          "process": "edamame_posture"
        },
        {
          "description": "Connection to Canonical mirrors",
          "domain": "*.canonical.com",
          "port": 80,
          "process": "edamame_posture"
        },
        {
          "description": "Connection to Canonical mirrors",
          "domain": "*.canonical.com",
          "port": 443,
          "process": "edamame_posture"
        },
        {
          "description": "Connection to Ubuntu ESM for package updates",
          "domain": "esm.ubuntu.com",
          "port": 443,
          "process": "_apt"
        },
        {
          "description": "Connection to Microsoft Edge services for package updates",
          "domain": "*.t-msedge.net",
          "port": 443,
          "process": "_apt"
        },
        {
          "description": "Connection to Microsoft Edge services for DNS resolution",
          "domain": "*.t-msedge.net",
          "port": 443,
          "process": "systemd-resolve"
        },
        {
          "description": "Connection to Microsoft Edge services for network operations",
          "domain": "*.t-msedge.net",
          "port": 443,
          "process": "systemd-network"
        }
      ],
      "extends": [
        "github"
      ],
      "name": "github_linux"
    },
    {
      "endpoints": [],
      "extends": [
        "github"
      ],
      "name": "github_windows"
    }
  ]
}"#;
