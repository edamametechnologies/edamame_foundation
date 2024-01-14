// Built in default threat model
pub static THREAT_METRICS_MACOS: &str = r#"{
  "name": "threat model macOS",
  "extends": "none",
  "date": "December 12th 2023",
  "signature": "b44266f387c48766f0fc50f46bd07e179068931e4aeb36a6a7232f581e027cfa",
  "metrics": [
    {
      "name": "edamame helper disabled",
      "metrictype": "bool",
      "dimension": "system services",
      "severity": 5,
      "scope": "generic",
      "tags": [],
      "description": [
        {
          "locale": "EN",
          "title": "EDAMAME helper inactive",
          "summary": "EDAMAME's Helper software is not running or requires an update. It's required for maximum Security Score analysis."
        },
        {
          "locale": "FR",
          "title": "EDAMAME Helper inactif",
          "summary": "Le logiciel d'assistance d'EDAMAME n'est pas en cours d'exécution ou a besoin d'être mis à jour. Il est requis pour une analyse complète du score de sécurité."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "helper_check",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "installer",
        "elevation": "user",
        "target": "https://github.com/edamametechnologies/edamame_helper/releases/download",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "/Library/Application\\ Support/Edamame/Edamame-Helper/uninstall.sh",
        "education": []
      }
    },
    {
      "name": "response to ping enabled",
      "metrictype": "bool",
      "dimension": "network",
      "severity": 3,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,macos_security/sysprefs_firewall_stealth_mode_enable",
        "ISO 27001/2,Communications Security",
        "PCI-DSS,Requirement-1",
        "SOC 2,CC-System Operations"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Response to ping enabled",
          "summary": "Your computer will respond if anything on the network is trying to check its presence. This can be very bad and allow anyone to check your presence and possibly attack your computer."
        },
        {
          "locale": "FR",
          "title": "Réponse au ping activée",
          "summary": "Votre ordinateur répondra si quelque chose essaie de vérifier sa présence. Cela peut être très mauvais et permettre à quiconque de vérifier votre présence sur un réseau et éventuellement d'attaquer votre ordinateur...."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | grep disabled",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off",
        "education": []
      }
    },
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
          "summary": "You have one or more Mobile Device Management (MDM) profiles installed on your computer. This means that your computer is or can be remotely administered by a 3rd party. If this is your personal computer, this is a grave threat and the profiles should be removed."
        },
        {
          "locale": "FR",
          "title": "Profils MDM installés",
          "summary": "Un ou plusieurs profils de gestion des appareils mobiles (MDM) sont installés sur votre ordinateur. Cela signifie que votre ordinateur est, ou peut être, administré à distance par un tiers. S'il s'agit de votre ordinateur personnel, il s'agit d'une grave menace et les profils doivent être supprimés."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "profiles -P | grep profileIdentifier",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "profiles remove -all -forced",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
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
      "name": "MDM remote admin",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "macOS",
      "tags": [
        "Personal Posture"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "JAMF remote administration enabled",
          "summary": "Your computer is or can be remotely administered by a 3rd party using the JAMF MDM framework. If this is your personal computer, this is a grave threat and JAMF should be removed."
        },
        {
          "locale": "FR",
          "title": "Administration à distance JAMF installée",
          "summary": "Votre ordinateur est, ou peut être, administré à distance par un tiers à l'aide du framework JAMF MDM. S'il s'agit de votre ordinateur personnel, il s'agit d'une grave menace et JAMF doit être supprimé."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "pgrep jamf",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "jamf removeFramework",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://www.jamf.com/en"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://www.jamf.com/fr"
          }
        ]
      }
    },
    {
      "name": "WOL enabled",
      "metrictype": "bool",
      "dimension": "network",
      "severity": 1,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,macos_security/sysprefs_wake_network_access_disable",
        "ISO 27001/2,Communications Security",
        "PCI-DSS,Requirement-1",
        "SOC 2,CC-System Operations"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Wake On LAN enabled",
          "summary": "Wake on LAN is a feature that can wake up your computer automatically when something is attempting to connect to it. This is not something you need in most cases and it can allow an attacker to connect to your computer at any time."
        },
        {
          "locale": "FR",
          "title": "Wake On LAN activé",
          "summary": "Wake on LAN est une fonctionnalité qui peut réveiller automatiquement votre ordinateur lorsque quelque chose tente de s'y connecter. Ce n'est pas quelque chose dont vous avez besoin dans la plupart des cas et cela peut permettre à un malfrat de se connecter à votre ordinateur à tout moment."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "systemsetup getwakeonnetworkaccess | grep -v Off",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "systemsetup -setwakeonnetworkaccess off",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "systemsetup -setwakeonnetworkaccess on",
        "education": []
      }
    },
    {
      "name": "manual store application updates",
      "metrictype": "bool",
      "dimension": "applications",
      "severity": 3,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,macos_security/sysprefs_software_update_app_update_enforce",
        "ISO 27001/2,Information Systems Acquisition, Development, and Maintenance",
        "PCI-DSS,Requirement-6",
        "SOC 2,CC-System Development and Maintenance"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Manual Appstore updates",
          "summary": "Applications are constantly updated to fix potential security issues. It's your best interest to get updates as soon as you can through automatic updates."
        },
        {
          "locale": "FR",
          "title": "Mises à jour Appstore manuelles",
          "summary": "Les applications sont constamment mises à jour pour résoudre les problèmes de sécurité potentiels. Il est dans votre intérêt d'obtenir les mises à jour dès que possible grâce aux mises à jour automatiques."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "defaults read /Library/Preferences/com.apple.commerce.plist AutoUpdate 2>&1 | grep -v 1",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "defaults write /Library/Preferences/com.apple.commerce.plist AutoUpdate -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallAppUpdates -bool true",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "defaults write /Library/Preferences/com.apple.commerce.plist AutoUpdate -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallAppUpdates -bool false",
        "education": []
      }
    },
    {
      "name": "local firewall disabled",
      "metrictype": "bool",
      "dimension": "network",
      "severity": 2,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,macos_security/sysprefs_firewall_enable",
        "ISO 27001/2,Communications Security",
        "PCI-DSS,Requirement-1",
        "SOC 2,CC-Network Protection"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Local firewall disabled",
          "summary": "Your local firewall is disabled. This is fine in a trusted environment but dangerous if you happened to connect to public networks. You should turn it on by default."
        },
        {
          "locale": "FR",
          "title": "Pare-feu local désactivé",
          "summary": "Votre pare-feu local est désactivé. C'est bien dans un environnement de confiance mais dangereux si vous vous connectez à des réseaux publics. Vous devriez l'activer par défaut."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "defaults read /Library/Preferences/com.apple.alf globalstate | grep 0",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "defaults write /Library/Preferences/com.apple.alf globalstate -int 2",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "defaults write /Library/Preferences/com.apple.alf globalstate -int 0 && launchctl unload /System/Library/LaunchDaemons/com.apple.alf.agent.plist && launchctl load /System/Library/LaunchDaemons/com.apple.alf.agent.plist&& killall socketfilterfw || true",
        "education": []
      }
    },
    {
      "name": "automatic login enabled",
      "metrictype": "bool",
      "dimension": "credentials",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,macos_security/sysprefs_automatic_login_disable",
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-8",
        "SOC 2,CC-Logical Access"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Automatic login enabled",
          "summary": "Automatic login could appear as very handy but in fact it's a major security threat: it allows anyone to access your data without knowing your password."
        },
        {
          "locale": "FR",
          "title": "Login automatique activé",
          "summary": "La connexion automatique peut sembler très pratique mais en fait c'est une menace majeure pour la sécurité : elle permet à n'importe qui d'accéder à vos données sans connaître votre mot de passe."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "defaults read /Library/Preferences/com.apple.loginwindow | grep autoLoginUser",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=G89On8uvQuQ"
          }
        ]
      }
    },
    {
      "name": "remote login enabled",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,macos_security/sysprefs_ssh_disable",
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-8",
        "SOC 2,CC-System Integrity"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Remote login enabled",
          "summary": "Remote login is enabled. This is not necessary unless your are an IT professional. This is unusual and dangerous for most users."
        },
        {
          "locale": "FR",
          "title": "Accès à distance activé",
          "summary": "L'accès à distance est activée. Ce n'est pas nécessaire sauf si vous êtes un professionnel de l'informatique. Ceci est inhabituel et dangereux pour la plupart des utilisateurs."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "systemsetup -getremotelogin | grep On",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "fulldisk",
        "target": "echo yes | systemsetup -setremotelogin off",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "fulldisk",
        "target": "systemsetup -setremotelogin on",
        "education": []
      }
    },
    {
      "name": "remote desktop enabled",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,macos_security/sysprefs_remote_management_disable",
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-8",
        "SOC 2,CC-System Integrity"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Remote desktop enabled",
          "summary": "Remote desktop is enabled. This is not necessary unless your are an IT professional. This is unusual and dangerous for most users."
        },
        {
          "locale": "FR",
          "title": "Bureau à distance activé",
          "summary": "La connexion au bureau à distance est activée. Ce n'est pas nécessaire sauf si vous êtes un professionnel de l'informatique. Ceci est inhabituel et dangereux pour la plupart des utilisateurs."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "pgrep ARDAgent",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "fulldisk",
        "target": "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "fulldisk",
        "target": "sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate",
        "education": []
      }
    },
    {
      "name": "file sharing enabled",
      "metrictype": "bool",
      "dimension": "system services",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,macos_security/sysprefs_smbd_disable",
        "ISO 27001/2,Information Security Policies",
        "PCI-DSS,Requirement-9",
        "SOC 2,CC-System Services"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "File sharing enabled",
          "summary": "File sharing is enabled. While this could be intentional we strongly recommend to turn it off. It's not that easy to configure and can expose your data to unwanted people."
        },
        {
          "locale": "FR",
          "title": "Partage de fichiers activé",
          "summary": "Le partage de fichiers est activé. Bien que cela puisse être intentionnel, nous vous recommandons fortement de le désactiver. Ce n'est pas si facile à configurer et cela peut exposer vos données à des personnes indésirables."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "launchctl list | grep smbd",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "launchctl load -w /System/Library/LaunchDaemons/com.apple.smbd.plist && defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist EnabledServices -array disk",
        "education": []
      }
    },
    {
      "name": "remote events enabled",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 4,
      "scope": "macOS",
      "tags": [
        "CIS Benchmark Level 1,macos_security/sysprefs_rae_disable",
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-6.5",
        "SOC 2,CC-System Integrity"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Remote events enabled",
          "summary": "Remote events are enabled. While this could be intentional we strongly recommend to turn it off. It's unnecessary for most users and has been a target for exploit in the recent past."
        },
        {
          "locale": "FR",
          "title": "Événements à distance activés",
          "summary": "Les événements à distance sont activés. Bien que cela puisse être intentionnel, nous vous recommandons fortement de les désactiver. C'est inutile pour la plupart des utilisateurs et cela a été une cible d'attaques dans un passé récent."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "launchctl print-disabled system | grep com.apple.AEServer | grep -E 'enabled|false'",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "fulldisk",
        "target": "systemsetup -setremoteappleevents off",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "fulldisk",
        "target": "systemsetup -setremoteappleevents on",
        "education": []
      }
    },
    {
      "name": "encrypted disk organizational recovery",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "Personal Posture"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Corporate disk recovery key",
          "summary": "It seems your computer hard disk has been encrypted by your employer. It means that they could potentially decrypt it if you give the computer back to them. You should suppress that possibility."
        },
        {
          "locale": "FR",
          "title": "Clé d'entreprise de récupération de disque",
          "summary": "Il semble que le disque dur de votre ordinateur ait été crypté par votre employeur. Cela signifie qu'ils pourraient potentiellement le déchiffrer si vous leur rendez l'ordinateur. Vous devriez supprimer cette possibilité."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "fdesetup hasinstitutionalrecoverykey | grep true",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://derflounder.wordpress.com/2019/07/03/managing-macos-mojaves-filevault-2-with-fdesetup/"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://derflounder-wordpress-com.translate.goog/2019/07/03/managing-macos-mojaves-filevault-2-with-fdesetup/?_x_tr_sl=auto&_x_tr_tl=fr&_x_tr_hl=en&_x_tr_pto=wapp"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://derflounder.wordpress.com/2019/07/03/managing-macos-mojaves-filevault-2-with-fdesetup/"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://derflounder-wordpress-com.translate.goog/2019/07/03/managing-macos-mojaves-filevault-2-with-fdesetup/?_x_tr_sl=auto&_x_tr_tl=fr&_x_tr_hl=en&_x_tr_pto=wapp"
          }
        ]
      }
    },
    {
      "name": "encrypted disk disabled",
      "metrictype": "bool",
      "dimension": "system services",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,macos_security/sysprefs_filevault_enforce",
        "ISO 27001/2,Information Security Incident Management",
        "PCI-DSS,Requirement-3.4",
        "SOC 2,CC-Data Protection"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Disk encryption disabled",
          "summary": "Your main storage is not encrypted. While there is a little performance impact by enabling it, we really urge you to set it up. Without that anyone physically accessing your computer can access your data."
        },
        {
          "locale": "FR",
          "title": "Encryption du disque désactivée",
          "summary": "Votre stockage principal n'est pas crypté. Bien qu'il y ait un petit impact sur les performances en l'activant, nous vous invitons vraiment à le configurer. Sans cela, toute personne accédant physiquement à votre ordinateur peut accéder à vos données."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "fdesetup isactive | grep false",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=ETgLlx3Npqg"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=Ovr9nyIagTY"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://www.youtube.com/watch?v=ETgLlx3Npqg"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://www.youtube.com/watch?v=Ovr9nyIagTY"
          }
        ]
      }
    },
    {
      "name": "unsigned applications allowed",
      "metrictype": "bool",
      "dimension": "applications",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,macos_security/os_gatekeeper_enable",
        "ISO 27001/2,Information Systems Acquisition, Development, and Maintenance",
        "PCI-DSS,Requirement-6.6",
        "SOC 2,CC-Application Security"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Unsigned applications allowed",
          "summary": "Your computer has been setup to allow unsigned applications to run. This is unusual and dangerous. You should turn this off."
        },
        {
          "locale": "FR",
          "title": "Applications non signées autorisées",
          "summary": "Votre ordinateur a été configuré pour autoriser l'exécution d'applications non signées. C'est inhabituel et dangereux. Vous devriez désactiver cette option."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "spctl --status | grep disabled",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "spctl --global-enable",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "spctl --global-disable",
        "education": []
      }
    },
    {
      "name": "manual system updates",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,macos_security/sysprefs_install_macos_updates_enforce",
        "CIS Benchmark Level 1,macos_security/sysprefs_software_update_download_enforce",
        "ISO 27001/2,Information Systems Acquisition, Development, and Maintenance",
        "PCI-DSS,Requirement-6.1",
        "SOC 2,CC-System Maintenance"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Manual system updates",
          "summary": "System updates are manual. Your really should turn on automatic system updates to get the latest security fixes for your computer."
        },
        {
          "locale": "FR",
          "title": "Mises à jour système manuelles",
          "summary": "Les mises à jour du système sont manuelles. Vous devriez vraiment activer les mises à jour automatiques du système pour obtenir les derniers correctifs de sécurité pour votre ordinateur."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>&1 | grep -v 1",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true; softwareupdate --schedule on",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool false; softwareupdate --schedule off",
        "education": []
      }
    },
    {
      "name": "too slow or disabled screensaver lock",
      "metrictype": "bool",
      "dimension": "credentials",
      "severity": 3,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,macos_security/sysprefs_screensaver_ask_for_password_delay_enforce",
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-8.1.8",
        "SOC 2,CC-Access Control"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Screen lock disabled",
          "summary": "Your computer doesn't have a screensaver enabled with a password. It leaves it open for phsyical access by anyone. This is very dangerous!"
        },
        {
          "locale": "FR",
          "title": "Ecran protégé désactivé",
          "summary": "Votre ordinateur n'a pas d'économiseur d'écran activé avec un mot de passe. Il le laisse ouvert à l'accès physique par n'importe qui. C'est très dangereux !"
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "sysadminctl -screenLock status 2>&1 | grep off",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=C6of13nZTpM"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=C6of13nZTpM"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=C6of13nZTpM"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=C6of13nZTpM"
          }
        ]
      }
    },
    {
      "name": "no EPP",
      "metrictype": "bool",
      "dimension": "applications",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "ISO 27001/2,Malware Protection",
        "PCI-DSS,Requirement-5",
        "SOC 2,CC-Malware Protection"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "No antivirus enabled",
          "summary": "You don't have any antivirus installed (MalwareBytes, Sentinel One...). We recommend you to enable one."
        },
        {
          "locale": "FR",
          "title": "Pas d'antivirus activé",
          "summary": "Vous n'avez pas d'antivirus installé (MalwareBytes, Sentinel One...). Nous vous recommandons d'en activer un."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "if ! { pgrep RTProtectionDaemon >/dev/null || sentinelctl version 2>/dev/null | grep -q \"Agent version\"; }; then echo noepp; fi",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://www.malwarebytes.com/"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://www.malwarebytes.com/"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=1vIf7ujOYdY"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=1vIf7ujOYdY"
          }
        ]
      }
    },
    {
      "name": "SIP disabled",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "macOS",
      "tags": [
        "CIS Benchmark Level 1,macos_security/os_sip_enable",
        "ISO 27001/2,System Acquisition, Development and Maintenance",
        "PCI-DSS,Requirement-6.1",
        "SOC 2,CC-System Integrity"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "System Integrity Protection disabled",
          "summary": "System Integrity Protection is a great ability of macOS that prevents any software to change system files and components. To some extent it's a \"good enough\" antivirus for your Mac. Having it disabled is... unusual and dangerous. It should be enabled by default on your Mac. This content will explain a way to enable it again. Bear with me .. it's somewhat hard to achieve!"
        },
        {
          "locale": "FR",
          "title": "Protection d'intégrité système désactivée",
          "summary": "La Protection de l'Intégrité du Système est une capacité clé de macOS qui empêche tous logiciels de modifier les fichiers et les composants du système. Dans une certaine mesure, c'est un antivirus \"assez bon\" pour votre Mac. Le désactiver est... inhabituel et dangereux. Il devrait être activé par défaut sur votre Mac. Ce contenu vous expliquera comment l'activer à nouveau. Soyez courageux... c'est un peu difficile à réaliser !"
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "csrutil status | grep disabled",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=Fx_1OPFzu88"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://www.remosoftware.com/info/fr/comment-activer-ou-desactiver-la-protection-de-lintegrite-du-systeme-mac/"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=StAn0ZHiXTc"
          }
        ]
      }
    },
    {
      "name": "guest account enabled",
      "metrictype": "bool",
      "dimension": "system services",
      "severity": 2,
      "scope": "macOS",
      "tags": [
        "CIS Benchmark Level 1,macos_security/sysprefs_guest_account_disable",
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-8.1.6",
        "SOC 2,CC-Access Control"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Guest account enabled",
          "summary": "Guest account is enabled. This is usually fine but it's not that easy to limit access to your data. You should disable it."
        },
        {
          "locale": "FR",
          "title": "Compte invité activé",
          "summary": "Le compte invité est activé. C'est généralement bien, mais il n'est pas si facile de limiter l'accès à vos données. Vous devriez le désactiver."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "sysadminctl -guestAccount status 2>&1 | grep enabled",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "sysadminctl -guestAccount off",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "sysadminctl -guestAccount on",
        "education": []
      }
    },
    {
      "name": "root user enabled",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 3,
      "scope": "macOS",
      "tags": [
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-2.3",
        "SOC 2,CC-Access Control"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Root user enabled",
          "summary": "A special system user has been configured on your computer. This is unusual and should be disabled immediately."
        },
        {
          "locale": "FR",
          "title": "Utilisateur root activé",
          "summary": "Un utilisateur système spécial a été configuré sur votre ordinateur. Ceci est inhabituel et doit être désactivé immédiatement."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "dscl . -read /Users/root Password | grep \"\\*\\*\"",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=Sx8o8C1oqyc"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=Bw05ksrrD4g"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=Sx8o8C1oqyc"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=Bw05ksrrD4g"
          }
        ]
      }
    },
    {
      "name": "unprotected system wide changes",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 3,
      "scope": "macOS",
      "tags": [
        "CIS Benchmark Level 1,macos_security/sysprefs_system_wide_preferences_configure",
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-2.2",
        "SOC 2,CC-Access Control"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Unprotected system changes",
          "summary": "Your computer system settings can be modified by any users. You should restrict it."
        },
        {
          "locale": "FR",
          "title": "Changement de paramètres système non protégés",
          "summary": "Les paramètres de votre système informatique peuvent être modifiés par tous les utilisateurs. Vous devriez le restreindre."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "security authorizationdb read system.preferences 2> /dev/null | grep -A1 shared | grep true",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "security authorizationdb read system.preferences > /tmp/system.preferences.plist; /usr/libexec/PlistBuddy -c \"Set :shared false\" /tmp/system.preferences.plist; security authorizationdb write system.preferences < /tmp/system.preferences.plist",
        "education": []
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "security authorizationdb read system.preferences > /tmp/system.preferences.plist; /usr/libexec/PlistBuddy -c \"Set :shared true\" /tmp/system.preferences.plist; security authorizationdb write system.preferences < /tmp/system.preferences.plist",
        "education": []
      }
    },
    {
      "name": "pwned",
      "metrictype": "bool",
      "dimension": "credentials",
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
          "title": "Compromised email address",
          "summary": "Your email address might have recently appeared in a data breach. Please set your email in the Identity tab, review the breaches if any and follow instructions."
        },
        {
          "locale": "FR",
          "title": "Adresse e-mail compromise",
          "summary": "Votre adresse e-mail est peut-être apparue récemment dans une fuite de données. Renseignez votre email dans le tab Identité, examinez les fuites éventuelles et suivez les instructions."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "pwned -i 365",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
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
        "system": "macOS",
        "minversion": 12,
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
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "lanscan",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
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
        "system": "macOS",
        "minversion": 12,
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
      "name": "latest os",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 2,
      "scope": "generic",
      "tags": [
        "ISO 27001/2,System Acquisition, Development and Maintenance",
        "PCI-DSS,Requirement-6.2",
        "SOC 2,CC-System Maintenance"
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
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist | grep macOS",
        "education": []
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
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
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
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
    }
  ]
}"#;
