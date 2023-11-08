// Built in default threat model
pub static THREAT_METRICS_ANDROID: &str = r#"{
  "name": "threat model Android",
  "extends": "none",
  "date": "October 15th 2023",
  "signature": "6026ed0b4940a920bb73ec64f17cf49a5ff579c7db4fc8869c50d8f4ff26611b",
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
            "target": "https://en.wikipedia.org/wiki/Mobile_device_managements"
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
            "target": "https://en.wikipedia.org/wiki/Mobile_device_managements"
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
        "CIS Benchmark Level 1,iOS_Screen_Lock",
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
            "target": "https://www.youtube.com/watch?v=2t0NrqIwI2s"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=55lKpx3SCK0"
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
            "target": "https://www.youtube.com/watch?v=2t0NrqIwI2s"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=55lKpx3SCK0"
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
            "target": "https://www.youtube.com/watch?v=_VNsH_OWmRw"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://www.youtube.com/watch?v=jdIrJ2ex0gE"
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
            "target": "https://www.youtube.com/watch?v=_VNsH_OWmRw"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://www.youtube.com/watch?v=jdIrJ2ex0gE"
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
          "title": "Compromised Google ID",
          "summary": "Your Google ID email has recently appeared in a data breach referenced on haveibeenpwned.com, please review the breach and change your passwords accordingly."
        },
        {
          "locale": "FR",
          "title": "Google ID compromise",
          "summary": "Votre e-mail Google ID est apparue récemment dans une fuite de données référencée sur haveibeenpwned.com, veuillez examiner la fuite et modifier vos mots de passe en conséquence."
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
            "target": "https://www.youtube.com/watch?v=ebUrdg2vFNk"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/shorts/ALRMvPnUTt0"
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
            "target": "https://www.youtube.com/watch?v=FG2DXkPA93g&t=124s"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=FG2DXkPA93g&t=124s"
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
            "target": "https://www.youtube.com/watch?v=1FcE86kwODQ"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=02UHT0OBGlo"
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
            "target": "https://www.youtube.com/watch?v=1FcE86kwODQ"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=02UHT0OBGlo"
          }
        ]
      }
    }
  ]
}"#;
