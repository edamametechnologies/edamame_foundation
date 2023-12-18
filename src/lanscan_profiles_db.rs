// Built in default profile db
pub static DEVICE_PROFILES: &str = r#"{
  "date": "December 17th 2023",
  "signature": "27aa9cba78c3fdccab41b2e86b8553e360b46d36b1b578a1ece10615191ad05e",
  "profiles": [
    {
      "device_type": "Printer",
      "open_ports": [],
      "mdns_services": [
        "_ipp._tcp.local",
        "_printer._tcp.local",
        "_ippusb._tcp.local",
        "_ipps._tcp.local"
      ],
      "vendors": [
        "canon",
        "epson",
        "brother",
        "lexmark",
        "xerox",
        "ricoh",
        "kodak",
        "sharp"
      ],
      "os_list": []
    },
    {
      "device_type": "iPhone",
      "open_ports": [
        62078
      ],
      "mdns_services": [
        "_apple-mobdev2._tcp.local"
      ],
      "vendors": [],
      "os_list": [
        "iOS"
      ]
    },
    {
      "device_type": "Smartphone",
      "open_ports": [],
      "mdns_services": [],
      "vendors": [
        "oneplus",
        "motorola",
        "nokia",
        "htc"
      ],
      "os_list": []
    },
    {
      "device_type": "Apple PC",
      "open_ports": [],
      "mdns_services": [],
      "vendors": [
        "apple"
      ],
      "os_list": [
        "macOS"
      ]
    },
    {
      "device_type": "Windows PC",
      "open_ports": [
        139
      ],
      "mdns_services": [],
      "vendors": [],
      "os_list": [
        "Windows"
      ]
    },
    {
      "device_type": "PC",
      "open_ports": [],
      "mdns_services": [],
      "vendors": [
        "dell",
        "lenovo",
        "acer",
        "asus",
        "msi"
      ],
      "os_list": [
        "Linux",
        "FreeBSD",
        "Windows"
      ]
    },
    {
      "device_type": "Router",
      "open_ports": [
        53
      ],
      "mdns_services": [],
      "vendors": [],
      "os_list": [
        "Linux",
        "FreeBSD"
      ]
    },
    {
      "device_type": "IoT",
      "open_ports": [
        1883,
        8883
      ],
      "mdns_services": [
        "_hue._tcp.local",
        "_hap._tcp.local"
      ],
      "vendors": [
        "wemo",
        "lifx",
        "tuya",
        "dyson",
        "physical graph corporation",
        "philips lighting bv"
      ],
      "os_list": [
        "Linux",
        "FreeBSD"
      ]
    },
    {
      "device_type": "NAS",
      "open_ports": [],
      "mdns_services": [],
      "vendors": [
        "synology",
        "qnap",
        "asustor",
        "drobo",
        "wd",
        "seagate"
      ],
      "os_list": [
        "Linux",
        "FreeBSD"
      ]
    },
    {
      "device_type": "RaspberryPi",
      "open_ports": [],
      "mdns_services": [],
      "vendors": [
        "raspberry pi"
      ],
      "os_list": [
        "Linux"
      ]
    },
    {
      "device_type": "GameConsole",
      "open_ports": [],
      "mdns_services": [],
      "vendors": [
        "sony",
        "microsoft",
        "nintendo"
      ],
      "os_list": []
    },
    {
      "device_type": "NetworkDevice",
      "open_ports": [],
      "mdns_services": [],
      "vendors": [
        "alliedtelesis",
        "alcatel-lucent",
        "arista",
        "aruba",
        "belkin",
        "buffalo",
        "cisco",
        "d-link",
        "dell",
        "extremenetworks",
        "freebox",
        "hpe",
        "juniper",
        "linksys",
        "mikrotik",
        "netgear",
        "tplink",
        "ubiquiti",
        "zyxel"
      ],
      "os_list": []
    },
    {
      "device_type": "SmartSpeaker",
      "open_ports": [],
      "mdns_services": [
        "_sonos._tcp.local"
      ],
      "vendors": [
        "amazon",
        "sonos",
        "bose",
        "jbl",
        "harman kardon"
      ],
      "os_list": [
        "Linux",
        "FreeBSD"
      ]
    },
    {
      "device_type": "SmartTV",
      "open_ports": [],
      "mdns_services": [
        "_androidtvremote2._tcp.local"
      ],
      "vendors": [],
      "os_list": []
    },
    {
      "device_type": "SmartTV",
      "open_ports": [
        7676,
        8001,
        8080
      ],
      "mdns_services": [],
      "vendors": [],
      "os_list": []
    },
    {
      "device_type": "SmartTV",
      "open_ports": [],
      "mdns_services": [
        "_googlecast._tcp.local",
        "_airplay._tcp.local"
      ],
      "vendors": [
        "tcl",
        "hisense",
        "vizio",
        "sharp",
        "toshiba"
      ],
      "os_list": []
    },
    {
      "device_type": "Camera",
      "open_ports": [],
      "mdns_services": [
        "_axis-video._tcp.local"
      ],
      "vendors": [
        "hikvision",
        "dahua",
        "axis",
        "vivotek",
        "flir",
        "nest",
        "arlo"
      ],
      "os_list": []
    }
  ]
}"#;
