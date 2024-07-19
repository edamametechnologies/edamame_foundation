// Built in default threat model
pub static THREAT_METRICS_ANDROID: &str = r#"{
  "name": "threat model Android",
  "extends": "none",
  "date": "April 17th 2024",
  "signature": "edcd1640587552e638f11cd9f60d4608324029f420ad8b2b65063b6cf4eaa0d3",
  "metrics": [
    {
      "name": "MDM profiles",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "Personal Posture"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "MDM profiles installed",
          "summary": "You have one or more Mobile Device Management (MDM) profiles installed on your computer. This means that your device is or can be remotely administered by a 3rd party. If this is your personal device, this is a grave threat and the profiles should be removed."
        },
        {
          "locale": "FR",
          "title": "Profils MDM installés",
          "summary": "Un ou plusieurs profils de gestion des appareils mobiles (MDM) sont installés sur votre ordinateur. Cela signifie que votre appareil est, ou peut être, administré à distance par un tiers. S'il s'agit de votre appareil personnel, il s'agit d'une grave menace et les profils doivent être supprimés."
        }
      ],
      "implementation": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "mdm_check",
        "education": []
      },
      "remediation": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://en.wikipedia.org/wiki/Mobile_device_management"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://fr.wikipedia.org/wiki/Mobile_device_management"
          }
        ]
      },
      "rollback": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://en.wikipedia.org/wiki/Mobile_device_management"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://fr.wikipedia.org/wiki/Mobile_device_management"
          }
        ]
      }
    },
    {
      "name": "too slow or disabled screensaver lock",
      "metrictype": "bool",
      "dimension": "credentials",
      "severity": 3,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1",
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-8.1.7",
        "SOC 2,CC-Access Control"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Screen lock disabled",
          "summary": "Your device doesn't have a screensaver enabled with a password. It leaves it open for phsyical access by anyone. This is very dangerous!"
        },
        {
          "locale": "FR",
          "title": "Ecran protégé désactivé",
          "summary": "Votre appareil n'a pas d'économiseur d'écran activé avec un mot de passe. Il le laisse ouvert à l'accès physique par n'importe qui. C'est très dangereux !"
        }
      ],
      "implementation": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "screenlock_check",
        "education": []
      },
      "remediation": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=E5OPbL4YJUk"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=k2RVUT7Yai0"
          }
        ]
      },
      "rollback": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=E5OPbL4YJUk"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=k2RVUT7Yai0"
          }
        ]
      }
    },
    {
      "name": "jailbroken",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "Android",
      "tags": [
        "CIS Benchmark Level 1",
        "ISO 27001/2,Mobile Device Policy",
        "PCI-DSS,Requirement-5.1",
        "SOC 2,CC-Mobile Device Management"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Your device is jailbroken",
          "summary": "Your device is jailbroken. Either you did it yourself or a bad actor did it to access your personal data. This is very dangerous! You need to restore your device to factory settings."
        },
        {
          "locale": "FR",
          "title": "Votre appareil est jailbreaké",
          "summary": "Votre appareil est jailbreaké. Soit vous l'avez fait vous-même, soit un acteur malveillant l'a fait pour accéder à vos données personnel. C'est très dangereux ! Vous devez restaurer votre appareil aux paramètres d'usine."
        }
      ],
      "implementation": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "jailbreak_check",
        "education": []
      },
      "remediation": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=UXyeb3n8Gc8"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://www.youtube.com/watch?v=-lRlQdBxmmM"
          }
        ]
      },
      "rollback": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=UXyeb3n8Gc8"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://www.youtube.com/watch?v=-lRlQdBxmmM"
          }
        ]
      }
    },
    {
      "name": "pwned",
      "metrictype": "bool",
      "dimension": "credentials",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "ISO 27001/2,Information Security Incident Management",
        "PCI-DSS,Requirement-12.10",
        "SOC 2,CC-Incident Response",
        "Personal Posture"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Potentially compromised email address",
          "summary": "Your email address might have recently appeared in a data breach. Please set your email in the Identity tab, review the breaches if any and follow instructions."
        },
        {
          "locale": "FR",
          "title": "Adresse e-mail potentiellement compromise",
          "summary": "Votre adresse e-mail est peut-être apparue récemment dans une fuite de données. Renseignez votre email dans le tab Identité, examinez les fuites éventuelles et suivez les instructions."
        }
      ],
      "implementation": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "pwned -i 365",
        "education": []
      },
      "remediation": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "internal",
        "elevation": "",
        "target": "digitalidentity_manager",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://en.wikipedia.org/wiki/Have_I_Been_Pwned"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://www.futura-sciences.com/tech/actualites/internet-voici-savoir-si-vos-donnees-personnelles-internet-ont-ete-piratees-103095/"
          }
        ]
      },
      "rollback": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://en.wikipedia.org/wiki/Have_I_Been_Pwned"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://www.futura-sciences.com/tech/actualites/internet-voici-savoir-si-vos-donnees-personnelles-internet-ont-ete-piratees-103095/"
          }
        ]
      }
    },
    {
      "name": "lanscan",
      "metrictype": "bool",
      "dimension": "network",
      "severity": 1,
      "scope": "generic",
      "tags": [
        "ISO 27001/2,Information Security Incident Management",
        "PCI-DSS,Requirement-12.10",
        "SOC 2,CC-Incident Response",
        "Personal Posture"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Unverified network environment",
          "summary": "The network you are connected to is not a known one. If you are allowed to scan this network, go to the network tab and verify the presence of potentially dangerous devices."
        },
        {
          "locale": "FR",
          "title": "Environement réseau non vérifié",
          "summary": "Le réseau auquel vous êtes connecté n'est pas connu. Si vous êtes autorisé à scanner ce réseau, allez dans l'onglet réseau et vérifiez la présence de périphériques potentiellement dangereux."
        }
      ],
      "implementation": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "lanscan",
        "education": []
      },
      "remediation": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "internal",
        "elevation": "",
        "target": "network_manager",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://en.wikipedia.org/wiki/Port_scanner"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://fr.wikipedia.org/wiki/Balayage_de_ports"
          }
        ]
      },
      "rollback": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://en.wikipedia.org/wiki/Port_scanner"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://fr.wikipedia.org/wiki/Balayage_de_ports"
          }
        ]
      }
    },
    {
      "name": "app not up to date",
      "metrictype": "bool",
      "dimension": "applications",
      "severity": 3,
      "scope": "generic",
      "tags": [],
      "description": [
        {
          "locale": "EN",
          "title": "App is not up to date",
          "summary": "This app is not up to date. Applications are constantly updated to fix potential security issues. It's your best interest to get updates as soon as you can through automatic updates."
        },
        {
          "locale": "FR",
          "title": "Application pas à jour",
          "summary": "Cette application n'est pas à jour. Les applications sont constamment mises à jour pour résoudre les problèmes de sécurité potentiels. Il est dans votre intérêt d'obtenir les mises à jour dès que possible grâce aux mises à jour automatiques."
        }
      ],
      "implementation": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "latestapp_check",
        "education": []
      },
      "remediation": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=v9H4pcZ1QFc"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=fVLLgBFgNMg"
          }
        ]
      },
      "rollback": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=v9H4pcZ1QFc"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=fVLLgBFgNMg"
          }
        ]
      }
    },
    {
      "name": "latest os",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 3,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1",
        "ISO 27001/2,System Update Policy",
        "PCI-DSS,Requirement-6.2",
        "SOC 2,CC-System Updates"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Your OS is not up to date",
          "summary": "Your operating system is not up to date, please proceed to upgrade to get the latest security patches."
        },
        {
          "locale": "FR",
          "title": "Votre OS n'est pas à jour",
          "summary": "Votre système d'exploitation n'est pas à jour, veuillez procéder à sa mise à niveau afin d'obtenir les derniers correctifs de sécurité."
        }
      ],
      "implementation": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "latestos_check",
        "education": []
      },
      "remediation": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=wLWbhRZ7VXI"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=or1OJxptpqQ"
          }
        ]
      },
      "rollback": {
        "system": "Android",
        "minversion": 13,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=wLWbhRZ7VXI"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=or1OJxptpqQ"
          }
        ]
      }
    }
  ]
}"#;
