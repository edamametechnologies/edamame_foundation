// Built in default threat model
pub static THREAT_METRICS_ANDROID: &str = r#"{
  "date": "April 11th 2025",
  "extends": "none",
  "metrics": [
    {
      "description": [
        {
          "locale": "EN",
          "summary": "You have one or more Mobile Device Management (MDM) profiles installed on your device. This means that your device is or can be remotely administered by a 3rd party. If this is your personal device, this is a grave threat and the profiles should be removed.",
          "title": "MDM profiles installed"
        },
        {
          "locale": "FR",
          "summary": "Un ou plusieurs profils de gestion des appareils mobiles (MDM) sont installés sur votre appareil. Cela signifie que votre appareil est, ou peut être, administré à distance par un tiers. S'il s'agit de votre appareil personnel, il s'agit d'une grave menace et les profils doivent être supprimés.",
          "title": "Profils MDM installés"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": "mdm_check"
      },
      "metrictype": "bool",
      "name": "MDM profiles",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/work/android/answer/6191949?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/work/android/answer/6191949?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/work/android/answer/6191949?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/work/android/answer/6191949?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "Personal Posture"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Your device doesn't have a screensaver enabled with a password. It leaves it open for physical access by anyone. This is very dangerous!",
          "title": "Screen lock disabled"
        },
        {
          "locale": "FR",
          "summary": "Votre appareil n'a pas d'économiseur d'écran activé avec un mot de passe. Il le laisse ouvert à l'accès physique par n'importe qui. C'est très dangereux !",
          "title": "Ecran protégé désactivé"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": "screenlock_check"
      },
      "metrictype": "bool",
      "name": "too slow or disabled screensaver lock",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/android/answer/9079129?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/android/answer/9079129?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/android/answer/9079129?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/android/answer/9079129?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "scope": "generic",
      "severity": 3,
      "tags": [
        "CIS Benchmark Level 1,Maximum screen lock timeout",
        "ISO 27001/2,A.11.2.8-Unattended User Equipment",
        "SOC 2,CC6.1-Access Control"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Your device is jailbroken. Either you did it yourself or a bad actor did it to access your personal data. This is very dangerous! You need to restore your device to factory settings.",
          "title": "Your device is jailbroken"
        },
        {
          "locale": "FR",
          "summary": "Votre appareil est jailbreaké. Soit vous l'avez fait vous-même, soit un acteur malveillant l'a fait pour accéder à vos données personnelles. C'est très dangereux ! Vous devez restaurer votre appareil aux paramètres d'usine.",
          "title": "Votre appareil est jailbreaké"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": "jailbreak_check"
      },
      "metrictype": "bool",
      "name": "jailbroken",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/android/answer/6088915?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/android/answer/6088915?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/android/answer/6088915?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/android/answer/6088915?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "scope": "Android",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 1,Ensure device is not rooted"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Check if your email address might have recently appeared in a data breach.",
          "title": "Potentially compromised email address"
        },
        {
          "locale": "FR",
          "summary": "Vérifiez si votre adresse e-mail est peut-être apparue récemment dans une fuite de données.",
          "title": "Adresse e-mail potentiellement compromise"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": "pwned -i 365"
      },
      "metrictype": "bool",
      "name": "pwned",
      "remediation": {
        "class": "internal",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "<p>To verify and mitigate the impact of a breach associated with your email, follow these steps:</p><ul><li>Navigate to the 'Identity' tab.</li><li>Enter your email address in the provided field.</li><li>Review the list of breaches associated with your email.</li><li>Select a breach to view detailed information and perform an AI-driven analysis.</li><li>Based on the analysis, decide whether to dismiss the breach or take further action if it's significant.</li><li>Once all threats are addressed, this alert will be marked as inactive.</li></ul>"
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "<p>Pour vérifier et atténuer l'impact d'une fuite de données associée à votre email, suivez ces étapes :</p><ul><li>Allez dans l'onglet 'Identité'.</li><li>Entrez votre adresse e-mail dans le champ prévu.</li><li>Examinez la liste des fuites associées à votre email.</li><li>Sélectionnez une fuite pour voir les informations détaillées et effectuer une analyse assistée par IA.</li><li>En fonction de l'analyse, décidez de rejeter la fuite ou de prendre des mesures supplémentaires si elle est significative.</li><li>Une fois toutes les menaces traitées, cette alerte sera marquée comme inactive.</li></ul>"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": "digitalidentity_manager"
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://haveibeenpwned.com/"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://www.futura-sciences.com/tech/actualites/internet-voici-savoir-si-vos-donnees-personnelles-internet-ont-ete-piratees-103095/"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "Personal Posture"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "The network you are connected to is not a known one or it contains unsafe devices. If you are allowed to scan this network, go to the network tab and verify the presence of potentially dangerous devices.",
          "title": "Unverified or unsafe network environment"
        },
        {
          "locale": "FR",
          "summary": "Le réseau auquel vous êtes connecté n'est pas connu ou contient des appareils non sécurisés. Si vous êtes autorisé à scanner ce réseau, allez dans l'onglet réseau et vérifiez la présence de périphériques potentiellement dangereux.",
          "title": "Environement réseau non vérifié ou non sécurisé"
        }
      ],
      "dimension": "network",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": "lanscan"
      },
      "metrictype": "bool",
      "name": "lanscan",
      "remediation": {
        "class": "internal",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "<p>Scan your network to identify all connected devices and assess potential threats by following these steps:</p><ul><li>Navigate to the 'Network' tab.</li><li>Devices of critical importance are marked with yellow for medium criticality and red for high criticality.</li><li>Select a critical device.</li><li>Assess each port's criticality by reading the associated CVEs and analyzing potential issues with AI.</li><li>If a port is determined to be safe, mark it as verified.</li></ul><p>Once all devices are deemed safe, this threat will be marked as inactive.</p>"
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "<p>Scannez votre réseau pour identifier tous les appareils connectés et évaluer les menaces potentielles en suivant ces étapes:</p><ul><li>Allez dans l'onglet 'Réseau'.</li><li>Les appareils de grande importance sont marqués en jaune pour une criticité moyenne et en rouge pour une criticité élevée.</li><li>Sélectionnez un appareil critique.</li><li>Évaluez la criticité de chaque port en lisant les CVE associés et en analysant les problèmes potentiels avec l'IA.</li><li>Si un port est déterminé comme sûr, marquez-le comme vérifié.</li></ul><p>Une fois que tous les appareils sont considérés comme sûrs, cette menace sera marquée comme inactive.</p>"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": "network_manager"
      },
      "rollback": {
        "class": "internal",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "<p>Scan your network to identify all connected devices and assess potential threats by following these steps:</p><ul><li>Navigate to the 'Network' tab.</li><li>Devices of critical importance are marked with yellow for medium criticality and red for high criticality.</li><li>Select a critical device.</li><li>Assess each port's criticality by reading the associated CVEs and analyzing potential issues with AI.</li><li>If a port is determined to be safe, mark it as verified.</li></ul><p>Once all devices are deemed safe, this threat will be marked as inactive.</p>"
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "<p>Scannez votre réseau pour identifier tous les appareils connectés et évaluer les menaces potentielles en suivant ces étapes:</p><ul><li>Allez dans l'onglet 'Réseau'.</li><li>Les appareils de grande importance sont marqués en jaune pour une criticité moyenne et en rouge pour une criticité élevée.</li><li>Sélectionnez un appareil critique.</li><li>Évaluez la criticité de chaque port en lisant les CVE associés et en analysant les problèmes potentiels avec l'IA.</li><li>Si un port est déterminé comme sûr, marquez-le comme vérifié.</li></ul><p>Une fois que tous les appareils sont considérés comme sûrs, cette menace sera marquée comme inactive.</p>"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": "network_manager"
      },
      "scope": "generic",
      "severity": 1,
      "tags": [
        "Personal Posture"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "This app is not up to date. Applications are constantly updated to fix potential security issues. It's your best interest to get updates as soon as you can through automatic updates.",
          "title": "App is not up to date"
        },
        {
          "locale": "FR",
          "summary": "Cette application n'est pas à jour. Les applications sont constamment mises à jour pour résoudre les problèmes de sécurité potentiels. Il est dans votre intérêt d'obtenir les mises à jour dès que possible grâce aux mises à jour automatiques.",
          "title": "Application pas à jour"
        }
      ],
      "dimension": "applications",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": "latestapp_check"
      },
      "metrictype": "bool",
      "name": "app not up to date",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/googleplay/answer/113412?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/googleplay/answer/113412?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/googleplay/answer/113412?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/googleplay/answer/113412?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "scope": "generic",
      "severity": 3,
      "tags": []
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Your operating system is not up to date, please upgrade it to get the latest security patches.",
          "title": "Your OS is not up to date"
        },
        {
          "locale": "FR",
          "summary": "Votre système d'exploitation n'est pas à jour, veuillez procéder à sa mise à niveau afin d'obtenir les derniers correctifs de sécurité.",
          "title": "Votre OS n'est pas à jour"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": "latestos_check"
      },
      "metrictype": "bool",
      "name": "latest os",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/android/answer/7680439?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/android/answer/7680439?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/android/answer/7680439?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/android/answer/7680439?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "scope": "generic",
      "severity": 3,
      "tags": [
        "CIS Benchmark Level 1,System is up to date"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Your device password strength is insufficient. Ensure you are using at least a 6-digit PIN for better security.",
          "title": "Weak password"
        },
        {
          "locale": "FR",
          "summary": "La force de votre mot de passe est insuffisante. Assurez-vous d'utiliser au moins un code PIN à 6 chiffres pour une meilleure sécurité.",
          "title": "Force du mot de passe insuffisante"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": "password_check"
      },
      "metrictype": "bool",
      "name": "password is too weak",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/android/answer/9079129?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/android/answer/9079129?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/android/answer/9079129?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/android/answer/9079129?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Ensure minimum password length"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Your device's biometric authentication is disabled. Enabling biometric authentication can significantly improve your device's security.",
          "title": "Biometric authentication disabled"
        },
        {
          "locale": "FR",
          "summary": "L'authentification biométrique de votre appareil est désactivée. Activer l'authentification biométrique peut améliorer considérablement la sécurité de votre appareil.",
          "title": "Authentification biométrique désactivée"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": "biometric_check"
      },
      "metrictype": "bool",
      "name": "biometric authentication disabled",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/pixelphone/answer/9517039?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/pixelphone/answer/9517039?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/pixelphone/answer/9517039?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/pixelphone/answer/9517039?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "scope": "generic",
      "severity": 4,
      "tags": []
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Google Play Protect is disabled on your device. Enable Play Protect to improve security against harmful apps.",
          "title": "Play Protect disabled"
        },
        {
          "locale": "FR",
          "summary": "Google Play Protect est désactivé sur votre appareil. Activez Play Protect pour améliorer la sécurité contre les applications nuisibles.",
          "title": "Play Protect désactivé"
        }
      ],
      "dimension": "applications",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": "play_protect_check"
      },
      "metrictype": "bool",
      "name": "play protect disabled",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/googleplay/answer/2812853?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/googleplay/answer/2812853?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/googleplay/answer/2812853?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/googleplay/answer/2812853?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Enable Google Play Protect"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Your device's storage is not encrypted. Enable encryption to protect your data from unauthorized access.",
          "title": "Device encryption disabled"
        },
        {
          "locale": "FR",
          "summary": "Le stockage de votre appareil n'est pas chiffré. Activez le chiffrement pour protéger vos données contre tout accès non autorisé.",
          "title": "Chiffrement de l'appareil désactivé"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": "encryption_check"
      },
      "metrictype": "bool",
      "name": "encrypted disk disabled",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/nexus/answer/2844831?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/nexus/answer/2844831?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/nexus/answer/2844831?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/nexus/answer/2844831?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 11,
        "system": "Android",
        "target": ""
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "ISO 27001/2,A.8.3.1-Media Protection",
        "SOC 2,CC6.7-Encryption"
      ]
    }
  ],
  "name": "threat model Android",
  "signature": "9006c92c7c9f283dfc9fc744fb2292d2a0d4510a27b2439ba38885c26ae1eec2"
}"#;
