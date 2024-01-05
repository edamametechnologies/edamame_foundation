// Built in default profile db
pub static DEVICE_PROFILES: &str = r#"{
  "date": "January 5th 2024",
  "signature": "a53cc8078eac325adcde9717ed60fd051364009b296f865d9ec015d473860eea",
  "profiles": [
    {
      "device_type": "Printer",
      "conditions": [
        {
          "Node": {
            "type": "OR",
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
              }
            ]
          }
        }
      ]
    },
    {
      "device_type": "RaspberryPi",
      "conditions": [
        {
          "Leaf": {
            "vendors": [
              "raspberry"
            ]
          }
        }
      ]
    },
    {
      "device_type": "SmartSpeaker",
      "conditions": [
        {
          "Node": {
            "type": "OR",
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
                  "mdns_services": [
                    "sonos",
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
            ]
          }
        }
      ]
    },
    {
      "device_type": "Router",
      "conditions": [
        {
          "Node": {
            "type": "OR",
            "sub_conditions": [
              {
                "Leaf": {
                  "open_ports": [
                    53
                  ]
                }
              }
            ]
          }
        }
      ]
    },
    {
      "device_type": "iPhone",
      "conditions": [
        {
          "Node": {
            "type": "OR",
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
                  "type": "AND",
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
                  ]
                }
              }
            ]
          }
        }
      ]
    },
    {
      "device_type": "Apple PC",
      "conditions": [
        {
          "Node": {
            "type": "OR",
            "sub_conditions": [
              {
                "Leaf": {
                  "vendors": [
                    "apple"
                  ]
                }
              }
            ]
          }
        }
      ]
    },
    {
      "device_type": "Smartphone",
      "conditions": [
        {
          "Node": {
            "type": "OR",
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
            ]
          }
        }
      ]
    },
    {
      "device_type": "PC",
      "conditions": [
        {
          "Node": {
            "type": "AND",
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
                  "open_ports": [
                    53
                  ],
                  "negate": true
                }
              }
            ]
          }
        }
      ]
    },
    {
      "device_type": "NAS",
      "conditions": [
        {
          "Node": {
            "type": "OR",
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
            ]
          }
        }
      ]
    },
    {
      "device_type": "GameConsole",
      "conditions": [
        {
          "Node": {
            "type": "OR",
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
            ]
          }
        }
      ]
    },
    {
      "device_type": "IoT",
      "conditions": [
        {
          "Node": {
            "type": "OR",
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
                    "hue",
                    "yeelink"
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
            ]
          }
        }
      ]
    },
    {
      "device_type": "SmartTV",
      "conditions": [
        {
          "Node": {
            "type": "OR",
            "sub_conditions": [
              {
                "Leaf": {
                  "open_ports": [
                    8001,
                    8002,
                    8080,
                    9080
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
            ]
          }
        }
      ]
    },
    {
      "device_type": "Camera",
      "conditions": [
        {
          "Node": {
            "type": "OR",
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
            ]
          }
        }
      ]
    },
    {
      "device_type": "NetworkDevice",
      "conditions": [
        {
          "Node": {
            "type": "OR",
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
            ]
          }
        }
      ]
    }
  ]
}"#;
