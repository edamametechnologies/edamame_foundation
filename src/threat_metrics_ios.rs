// Built in default threat model
pub static THREAT_METRICS_IOS: &str = r#"{
  "name": "threat model iOS",
  "extends": "none",
  "date": "December 22th 2024",
  "signature": "e30fc5c74b66d02dcde25e617c87a8e78e0d4bd446607ac9eaa7d204edebe352",
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
          "summary": "You have one or more Mobile Device Management (MDM) profiles installed on your device. This means that your device is or can be remotely administered by a 3rd party. If this is your personal device, this is a grave threat and the profiles should be removed."
        },
        {
          "locale": "FR",
          "title": "Profils MDM installés",
          "summary": "Un ou plusieurs profils de gestion des appareils mobiles (MDM) sont installés sur votre appareil. Cela signifie que votre appareil est, ou peut être, administré à distance par un tiers. S'il s'agit de votre appareil personnel, il s'agit d'une grave menace et les profils doivent être supprimés."
        }
      ],
      "implementation": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "mdm_check",
        "education": []
      },
      "remediation": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://support.apple.com/en-us/guide/deployment/depc0aadd3fe/web"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://support.apple.com/fr-fr/guide/deployment/depc0aadd3fe/web"
          }
        ]
      },
      "rollback": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://support.apple.com/en-us/guide/deployment/depc0aadd3fe/web"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://support.apple.com/fr-fr/guide/deployment/depc0aadd3fe/web"
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
        "CIS Benchmark Level 1,Set Auto-Lock to 2 Minutes or Less",
        "ISO 27001/2,A.11.2.8-Unattended User Equipment",
        "SOC 2,CC6.1-Access Control"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Screen lock disabled",
          "summary": "Your device doesn't have a screensaver enabled with a password. It leaves it open for physical access by anyone. This is very dangerous!"
        },
        {
          "locale": "FR",
          "title": "Ecran protégé désactivé",
          "summary": "Votre appareil n'a pas d'économiseur d'écran activé avec un mot de passe. Il le laisse ouvert à l'accès physique par n'importe qui. C'est très dangereux !"
        }
      ],
      "implementation": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "screenlock_check",
        "education": []
      },
      "remediation": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://support.apple.com/en-us/guide/iphone/iph9a2a69136/ios"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://support.apple.com/fr-fr/guide/iphone/iph9a2a69136/ios"
          }
        ]
      },
      "rollback": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://support.apple.com/en-us/guide/iphone/iph9a2a69136/ios"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://support.apple.com/fr-fr/guide/iphone/iph9a2a69136/ios"
          }
        ]
      }
    },
    {
      "name": "jailbroken",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "iOS",
      "tags": [
        "CIS Benchmark Level 1,Ensure device is not jailbroken"
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
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "jailbreak_check",
        "education": []
      },
      "remediation": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://support.apple.com/en-us/HT201252"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://support.apple.com/fr-fr/HT201252"
          }
        ]
      },
      "rollback": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://support.apple.com/en-us/HT201252"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://support.apple.com/fr-fr/HT201252"
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
        "Personal Posture"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Potentially compromised email address",
          "summary": "Check if your email address might have recently appeared in a data breach."
        },
        {
          "locale": "FR",
          "title": "Adresse e-mail potentiellement compromise",
          "summary": "Vérifiez si votre adresse e-mail est peut-être apparue récemment dans une fuite de données."
        }
      ],
      "implementation": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "pwned -i 365",
        "education": []
      },
      "remediation": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "internal",
        "elevation": "",
        "target": "digitalidentity_manager",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>To verify and mitigate the impact of a breach associated with your email, follow these steps:</p><ul><li>Navigate to the 'Identity' tab.</li><li>Enter your email address in the provided field.</li><li>Review the list of breaches associated with your email.</li><li>Select a breach to view detailed information and perform an AI-driven analysis.</li><li>Based on the analysis, decide whether to dismiss the breach or take further action if it's significant.</li><li>Once all threats are addressed, this alert will be marked as inactive.</li></ul>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Pour vérifier et atténuer l'impact d'une fuite de données associée à votre email, suivez ces étapes :</p><ul><li>Allez dans l'onglet 'Identité'.</li><li>Entrez votre adresse e-mail dans le champ prévu.</li><li>Examinez la liste des fuites associées à votre email.</li><li>Sélectionnez une fuite pour voir les informations détaillées et effectuer une analyse assistée par IA.</li><li>En fonction de l'analyse, décidez de rejeter la fuite ou de prendre des mesures supplémentaires si elle est significative.</li><li>Une fois toutes les menaces traitées, cette alerte sera marquée comme inactive.</li></ul>"
          }
        ]
      },
      "rollback": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://haveibeenpwned.com/"
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
        "Personal Posture"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Unverified or unsafe network environment",
          "summary": "The network you are connected to is not a known one or it contains unsafe devices. If you are allowed to scan this network, go to the network tab and verify the presence of potentially dangerous devices."
        },
        {
          "locale": "FR",
          "title": "Environement réseau non vérifié ou non sécurisé",
          "summary": "Le réseau auquel vous êtes connecté n'est pas connu ou contient des appareils non sécurisés. Si vous êtes autorisé à scanner ce réseau, allez dans l'onglet réseau et vérifiez la présence de périphériques potentiellement dangereux."
        }
      ],
      "implementation": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "lanscan",
        "education": []
      },
      "remediation": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "internal",
        "elevation": "",
        "target": "network_manager",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Scan your network to identify all connected devices and assess potential threats by following these steps:</p><ul><li>Navigate to the 'Network' tab.</li><li>Devices of critical importance are marked with yellow for medium criticality and red for high criticality.</li><li>Select a critical device.</li><li>Assess each port's criticality by reading the associated CVEs and analyzing potential issues with AI.</li><li>If a port is determined to be safe, mark it as verified.</li></ul><p>Once all devices are deemed safe, this threat will be marked as inactive.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Scannez votre réseau pour identifier tous les appareils connectés et évaluer les menaces potentielles en suivant ces étapes:</p><ul><li>Allez dans l'onglet 'Réseau'.</li><li>Les appareils de grande importance sont marqués en jaune pour une criticité moyenne et en rouge pour une criticité élevée.</li><li>Sélectionnez un appareil critique.</li><li>Évaluez la criticité de chaque port en lisant les CVE associés et en analysant les problèmes potentiels avec l'IA.</li><li>Si un port est déterminé comme sûr, marquez-le comme vérifié.</li></ul><p>Une fois que tous les appareils sont considérés comme sûrs, cette menace sera marquée comme inactive.</p>"
          }
        ]
      },
      "rollback": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "internal",
        "elevation": "",
        "target": "network_manager",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Scan your network to identify all connected devices and assess potential threats by following these steps:</p><ul><li>Navigate to the 'Network' tab.</li><li>Devices of critical importance are marked with yellow for medium criticality and red for high criticality.</li><li>Select a critical device.</li><li>Assess each port's criticality by reading the associated CVEs and analyzing potential issues with AI.</li><li>If a port is determined to be safe, mark it as verified.</li></ul><p>Once all devices are deemed safe, this threat will be marked as inactive.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Scannez votre réseau pour identifier tous les appareils connectés et évaluer les menaces potentielles en suivant ces étapes:</p><ul><li>Allez dans l'onglet 'Réseau'.</li><li>Les appareils de grande importance sont marqués en jaune pour une criticité moyenne et en rouge pour une criticité élevée.</li><li>Sélectionnez un appareil critique.</li><li>Évaluez la criticité de chaque port en lisant les CVE associés et en analysant les problèmes potentiels avec l'IA.</li><li>Si un port est déterminé comme sûr, marquez-le comme vérifié.</li></ul><p>Une fois que tous les appareils sont considérés comme sûrs, cette menace sera marquée comme inactive.</p>"
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
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "latestapp_check",
        "education": []
      },
      "remediation": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://support.apple.com/en-us/HT202180"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://support.apple.com/fr-fr/HT202180"
          }
        ]
      },
      "rollback": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://support.apple.com/en-us/HT202180"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://support.apple.com/fr-fr/HT202180"
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
        "CIS Benchmark Level 1,Keep iOS Auto-Update Enabled"
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
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "latestos_check",
        "education": []
      },
      "remediation": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://support.apple.com/en-us/HT204204"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://support.apple.com/fr-fr/HT204204"
          }
        ]
      },
      "rollback": {
        "system": "iOS",
        "minversion": 15,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://support.apple.com/en-us/HT204204"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://support.apple.com/fr-fr/HT204204"
          }
        ]
      }
    }
  ]
}"#;
