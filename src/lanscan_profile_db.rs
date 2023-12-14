// TODO: load this from github
pub static DEVICE_PROFILES: &str = r#"
    [
      {
        "device_type": "Printer",
        "open_ports": [80],
        "vendors": ["hp", "canon", "epson", "brother", "lexmark", "xerox", "ricoh", "kodak", "samsung", "sharp"],
        "os_list": ["Linux", "FreeBSD"]
      },
      {
        "device_type": "iPhone",
        "open_ports": [62078],
        "vendors": [],
        "os_list": ["iOS"]
      },
      {
        "device_type": "Smartphone",
        "open_ports": [5060],
        "vendors": ["samsung", "huawei", "oneplus", "lg", "motorola", "google", "nokia", "sony", "htc"],
        "os_list": ["Android"]
      },
      {
        "device_type": "Apple PC",
        "open_ports": [445],
        "vendors": ["apple"],
        "os_list": ["macOS"]
      },
      {
        "device_type": "PC",
        "open_ports": [445],
        "vendors": ["dell", "hp", "lenovo", "acer", "asus", "msi", "microsoft", "toshiba", "sony", "fujitsu"],
        "os_list": ["Linux", "FreeBSD", "Windows"]
      },
      {
        "device_type": "Router",
        "open_ports": [53],
        "vendors": ["netgear", "cisco", "d-link", "asus", "tplink", "linksys", "ubiquiti", "belkin", "aruba", "juniper", "freebox"],
        "os_list": ["Linux", "FreeBSD"]
      },
      {
        "device_type": "IoT",
        "open_ports": [8883],
        "vendors": ["philips", "belkin", "samsung", "lg", "xiaomi", "google", "tplink", "wemo", "lifx", "tuya"],
        "os_list": ["Linux", "FreeBSD"]
      },
      {
        "device_type": "NAS",
        "open_ports": [548],
        "vendors": ["synology", "qnap", "netgear", "buffalo", "dell", "hp", "asustor", "drobo", "wd", "seagate"],
        "os_list": ["Linux", "FreeBSD"]
      },
      {
        "device_type": "RaspberryPi",
        "open_ports": [],
        "vendors": ["raspberry pi"],
        "os_list": ["Linux"]
      },
      {
        "device_type": "GameConsole",
        "open_ports": [],
        "vendors": ["sony", "microsoft", "nintendo"],
        "os_list": ["FreeBSD", "Linux"]
      },
      {
        "device_type": "NetworkDevice",
        "open_ports": [],
        "vendors": ["cisco", "juniper", "arista", "extremenetworks", "alliedtelesis", "alcatel-lucent", "mikrotik", "ubiquiti", "hpe", "dell", "freebox"],
        "os_list": ["Linux", "FreeBSD"]
      },
      {
        "device_type": "SmartTV",
        "open_ports": [],
        "vendors": ["samsung", "lg", "sony", "panasonic", "tcl", "hisense", "vizio", "sharp", "toshiba"],
        "os_list": ["Linux", "Android"]
      },
      {
        "device_type": "SmartSpeaker",
        "open_ports": [],
        "vendors": ["amazon", "google", "sonos", "bose", "jbl", "harman kardon"],
        "os_list": ["Linux", "FreeBSD"]
      },
      {
        "device_type": "Camera",
        "open_ports": [],
        "vendors": ["hikvision", "dahua", "axis", "vivotek", "flir", "nest", "arlo"],
        "os_list": ["Linux", "FreeBSD"]
      }
    ]
"#;