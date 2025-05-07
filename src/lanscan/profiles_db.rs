// Built in default profile db
pub static DEVICE_PROFILES: &str = r#"{
  "date": "April 11th 2025",
  "profiles": [
    {
      "conditions": [
        {
          "Node": {
            "sub_conditions": [
              {
                "Leaf": {
                  "mdns_services": [
                    "ipp",
                    "printer"
                  ]
                }
              },
              {
                "Leaf": {
                  "vendors": [
                    "canon",
                    "epson",
                    "brother",
                    "lexmark",
                    "xerox",
                    "ricoh",
                    "kodak",
                    "sharp"
                  ]
                }
              },
              {
                "Leaf": {
                  "banners": [
                    "hp http server"
                  ]
                }
              }
            ],
            "type": "OR"
          }
        }
      ],
      "device_type": "Printer"
    },
    {
      "conditions": [
        {
          "Node": {
            "sub_conditions": [
              {
                "Leaf": {
                  "vendors": [
                    "raspberry"
                  ]
                }
              },
              {
                "Leaf": {
                  "banners": [
                    "raspbian"
                  ]
                }
              }
            ],
            "type": "OR"
          }
        }
      ],
      "device_type": "RaspberryPi"
    },
    {
      "conditions": [
        {
          "Node": {
            "sub_conditions": [
              {
                "Leaf": {
                  "vendors": [
                    "sonos",
                    "bose",
                    "jbl",
                    "harman"
                  ]
                }
              },
              {
                "Leaf": {
                  "open_ports": [
                    1400,
                    1410
                  ]
                }
              },
              {
                "Leaf": {
                  "mdns_services": [
                    "_sonos",
                    "bose",
                    "jbl",
                    "harman"
                  ]
                }
              },
              {
                "Leaf": {
                  "hostnames": [
                    "sonos",
                    "bose",
                    "jbl",
                    "harman"
                  ]
                }
              }
            ],
            "type": "OR"
          }
        }
      ],
      "device_type": "SmartSpeaker"
    },
    {
      "conditions": [
        {
          "Node": {
            "sub_conditions": [
              {
                "Leaf": {
                  "open_ports": [
                    53
                  ]
                }
              }
            ],
            "type": "OR"
          }
        }
      ],
      "device_type": "Router"
    },
    {
      "conditions": [
        {
          "Node": {
            "sub_conditions": [
              {
                "Leaf": {
                  "open_ports": [
                    62078
                  ]
                }
              },
              {
                "Node": {
                  "sub_conditions": [
                    {
                      "Leaf": {
                        "open_ports": [
                          49152
                        ]
                      }
                    },
                    {
                      "Leaf": {
                        "vendors": [
                          "apple",
                          ""
                        ]
                      }
                    }
                  ],
                  "type": "AND"
                }
              }
            ],
            "type": "OR"
          }
        }
      ],
      "device_type": "iPhone"
    },
    {
      "conditions": [
        {
          "Node": {
            "sub_conditions": [
              {
                "Leaf": {
                  "vendors": [
                    "apple"
                  ]
                }
              }
            ],
            "type": "OR"
          }
        }
      ],
      "device_type": "Apple PC"
    },
    {
      "conditions": [
        {
          "Node": {
            "sub_conditions": [
              {
                "Leaf": {
                  "vendors": [
                    "oneplus",
                    "motorola",
                    "nokia",
                    "htc"
                  ]
                }
              }
            ],
            "type": "OR"
          }
        }
      ],
      "device_type": "Smartphone"
    },
    {
      "conditions": [
        {
          "Node": {
            "sub_conditions": [
              {
                "Leaf": {
                  "vendors": [
                    "dell",
                    "lenovo",
                    "acer",
                    "msi",
                    "asus"
                  ]
                }
              },
              {
                "Leaf": {
                  "negate": true,
                  "open_ports": [
                    53
                  ]
                }
              }
            ],
            "type": "AND"
          }
        }
      ],
      "device_type": "PC"
    },
    {
      "conditions": [
        {
          "Node": {
            "sub_conditions": [
              {
                "Leaf": {
                  "vendors": [
                    "synology",
                    "asustor",
                    "drobo",
                    "wd",
                    "seagate"
                  ]
                }
              }
            ],
            "type": "OR"
          }
        }
      ],
      "device_type": "NAS"
    },
    {
      "conditions": [
        {
          "Node": {
            "sub_conditions": [
              {
                "Leaf": {
                  "vendors": [
                    "sony",
                    "microsoft",
                    "nintendo"
                  ]
                }
              },
              {
                "Leaf": {
                  "hostnames": [
                    "ps4",
                    "ps5",
                    "xbox"
                  ]
                }
              }
            ],
            "type": "OR"
          }
        }
      ],
      "device_type": "GameConsole"
    },
    {
      "conditions": [
        {
          "Node": {
            "sub_conditions": [
              {
                "Leaf": {
                  "open_ports": [
                    1883
                  ]
                }
              },
              {
                "Leaf": {
                  "open_ports": [
                    8883
                  ]
                }
              },
              {
                "Leaf": {
                  "mdns_services": [
                    "mqtt",
                    "hap",
                    "_hue",
                    "miio"
                  ]
                }
              },
              {
                "Leaf": {
                  "vendors": [
                    "wemo",
                    "lifx",
                    "tuya",
                    "dyson",
                    "physical graph",
                    "philips lighting"
                  ]
                }
              }
            ],
            "type": "OR"
          }
        }
      ],
      "device_type": "IoT"
    },
    {
      "conditions": [
        {
          "Node": {
            "sub_conditions": [
              {
                "Leaf": {
                  "open_ports": [
                    8001,
                    8002,
                    8080
                  ]
                }
              },
              {
                "Leaf": {
                  "open_ports": [
                    3000,
                    3001,
                    18181
                  ]
                }
              },
              {
                "Leaf": {
                  "open_ports": [
                    8008,
                    8009,
                    8443,
                    9000
                  ]
                }
              },
              {
                "Leaf": {
                  "vendors": [
                    "tcl",
                    "hisense",
                    "vizio",
                    "sharp",
                    "toshiba"
                  ]
                }
              },
              {
                "Leaf": {
                  "mdns_services": [
                    "androidtvremote",
                    "googlecast",
                    "airplay"
                  ]
                }
              }
            ],
            "type": "OR"
          }
        }
      ],
      "device_type": "SmartTV"
    },
    {
      "conditions": [
        {
          "Node": {
            "sub_conditions": [
              {
                "Leaf": {
                  "mdns_services": [
                    "axis-video"
                  ]
                }
              },
              {
                "Leaf": {
                  "vendors": [
                    "hikvision",
                    "dahua",
                    "axis",
                    "vivotek",
                    "flir",
                    "nest",
                    "arlo"
                  ]
                }
              }
            ],
            "type": "OR"
          }
        }
      ],
      "device_type": "Camera"
    },
    {
      "conditions": [
        {
          "Node": {
            "sub_conditions": [
              {
                "Leaf": {
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
                    "tp-link",
                    "ubiquiti",
                    "zyxel"
                  ]
                }
              }
            ],
            "type": "OR"
          }
        }
      ],
      "device_type": "NetworkDevice"
    }
  ],
  "signature": "668dface3a45fc82f044dfb25618000ffbcfb773b9d3891e4345c459b1916184"
}"#;
