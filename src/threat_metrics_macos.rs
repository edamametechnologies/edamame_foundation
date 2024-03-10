// Built in default threat model
pub static THREAT_METRICS_MACOS: &str = r#"{
  "name": "threat model macOS",
  "extends": "none",
  "date": "March 03th 2024",
  "signature": "a8f82e30153a34debe02d9a3f5b9db5f0f715a6c83090123af4d1c9b7b1da16d",
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
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>If you need to uninstall the EDAMAME Helper software for any reason, you can use the provided shell script command. Note that uninstalling may affect the Security Score analysis of your system.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Si vous devez désinstaller le logiciel d'assistance EDAMAME pour une raison quelconque, vous pouvez utiliser la commande de script shell fournie. Notez que la désinstallation peut affecter l'analyse du score de sécurité de votre système.</p>"
          }
        ]
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
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Enabling stealth mode through the CLI command <code>/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on</code> will make your system invisible to ping requests, enhancing your network security by reducing the attack surface visible to potential attackers.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>L'activation du mode furtif via la commande CLI <code>/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on</code> rendra votre système invisible aux requêtes ping, améliorant ainsi la sécurité de votre réseau en réduisant la surface d'attaque visible par les attaquants potentiels.</p>"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling stealth mode by executing <code>/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off</code> via CLI will make your system respond to ping requests again. Be cautious as this increases your network visibility and may expose your system to potential threats.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>La désactivation du mode furtif en exécutant <code>/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off</code> via CLI permettra à nouveau à votre système de répondre aux requêtes ping. Soyez prudent, car cela augmente la visibilité de votre réseau et peut exposer votre système à des menaces potentielles.</p>"
          }
        ]
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
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>To remove MDM profiles from your macOS device, you can use the CLI command <code>profiles remove -all -forced</code>. This action will ensure that your device is no longer managed remotely, which is crucial for maintaining personal security and privacy.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Pour supprimer les profils MDM de votre appareil macOS, vous pouvez utiliser la commande CLI <code>profiles remove -all -forced</code>. Cette action garantira que votre appareil n'est plus géré à distance, ce qui est crucial pour maintenir la sécurité et la confidentialité personnelles.</p>"
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
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling Wake On LAN (WOL) prevents your computer from being remotely activated, which can be a security risk. Use the command <code>systemsetup -setwakeonnetworkaccess off</code> to turn off WOL and enhance your device's security.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver le Wake On LAN (WOL) empêche votre ordinateur d'être activé à distance, ce qui peut représenter un risque de sécurité. Utilisez la commande <code>systemsetup -setwakeonnetworkaccess off</code> pour désactiver le WOL et améliorer la sécurité de votre appareil.</p>"
          }
        ]
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
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Enabling the local firewall on macOS can be done via CLI with <code>defaults write /Library/Preferences/com.apple.alf globalstate -int 2</code>. This enhances security by monitoring and controlling incoming connections.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>L'activation du pare-feu local sur macOS peut être effectuée via CLI avec <code>defaults write /Library/Preferences/com.apple.alf globalstate -int 2</code>. Cela améliore la sécurité en surveillant et contrôlant les connexions entrantes.</p>"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "defaults write /Library/Preferences/com.apple.alf globalstate -int 0 && launchctl unload /System/Library/LaunchDaemons/com.apple.alf.agent.plist && launchctl load /System/Library/LaunchDaemons/com.apple.alf.agent.plist&& killall socketfilterfw || true",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>If necessary, the firewall can be disabled for troubleshooting or specific network tasks with <code>defaults write /Library/Preferences/com.apple.alf globalstate -int 0</code>, but it's recommended to keep it enabled for security.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Si nécessaire, le pare-feu peut être désactivé pour le dépannage ou des tâches réseau spécifiques avec <code>defaults write /Library/Preferences/com.apple.alf globalstate -int 0</code>, mais il est recommandé de le garder activé pour la sécurité.</p>"
          }
        ]
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
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling automatic login enhances your security by requiring authentication at startup. Execute the CLI command <code>defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser</code> to turn it off. This ensures that unauthorized users cannot access your system without entering the correct credentials.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver la connexion automatique améliore votre sécurité en exigeant une authentification au démarrage. Exécutez la commande CLI <code>defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser</code> pour la désactiver. Cela garantit que les utilisateurs non autorisés ne peuvent pas accéder à votre système sans saisir les identifiants corrects.</p>"
          }
        ]
      },
      "remediation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling automatic login enhances your security by requiring authentication at startup. Execute the CLI command <code>defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser</code> to turn it off. This ensures that unauthorized users cannot access your system without entering the correct credentials.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver la connexion automatique améliore votre sécurité en exigeant une authentification au démarrage. Exécutez la commande CLI <code>defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser</code> pour la désactiver. Cela garantit que les utilisateurs non autorisés ne peuvent pas accéder à votre système sans saisir les identifiants corrects.</p>"
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
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling remote login via the CLI command <code>echo yes | systemsetup -setremotelogin off</code> secures your macOS system by preventing unauthorized remote access. This command requires full disk access permissions to execute and ensures that your system is only accessible by authorized users locally.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver l'accès à distance via la commande CLI <code>echo yes | systemsetup -setremotelogin off</code> sécurise votre système macOS en empêchant l'accès à distance non autorisé. Cette commande nécessite des permissions d'accès complet au disque pour s'exécuter et garantit que votre système est uniquement accessible localement par les utilisateurs autorisés.</p>"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "fulldisk",
        "target": "systemsetup -setremotelogin on",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Enabling remote login on macOS can be done via the CLI command <code>systemsetup -setremotelogin on</code>. This command allows remote users to access the system via SSH, which can be useful for remote administration but increases the risk of unauthorized access. Use this feature cautiously and ensure your firewall and user access permissions are properly configured.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>L'activation de l'accès à distance sur macOS peut être effectuée via la commande CLI <code>systemsetup -setremotelogin on</code>. Cette commande permet aux utilisateurs distants d'accéder au système via SSH, ce qui peut être utile pour l'administration à distance mais augmente le risque d'accès non autorisé. Utilisez cette fonction avec prudence et assurez-vous que votre pare-feu et les permissions d'accès utilisateur sont correctement configurés.</p>"
          }
        ]
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
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling remote desktop access can significantly enhance the security of your macOS system. Use the CLI command <code>/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop</code> to turn off remote management services. This prevents unauthorized remote desktop access, ensuring only approved users can control the system remotely.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver l'accès au bureau à distance peut considérablement renforcer la sécurité de votre système macOS. Utilisez la commande CLI <code>/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop</code> pour désactiver les services de gestion à distance. Cela empêche l'accès à distance non autorisé au bureau, garantissant que seuls les utilisateurs approuvés peuvent contrôler le système à distance.</p>"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "fulldisk",
        "target": "sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Re-enabling remote desktop services on macOS can be done through the CLI command <code>sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate</code>. While this enables remote management capabilities, it's crucial to ensure that only trusted users have access and that your network is secure to mitigate potential security risks.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Réactiver les services de bureau à distance sur macOS peut se faire via la commande CLI <code>sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate</code>. Bien que cela active les capacités de gestion à distance, il est crucial de s'assurer que seuls les utilisateurs de confiance ont accès et que votre réseau est sécurisé pour atténuer les risques de sécurité potentiels.</p>"
          }
        ]
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
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling file sharing on your macOS system can significantly enhance your data security. Use the CLI command <code>launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist</code> to turn off SMB file sharing. This action ensures that your files are not inadvertently shared across the network, reducing the risk of unauthorized access.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver le partage de fichiers sur votre système macOS peut considérablement renforcer la sécurité de vos données. Utilisez la commande CLI <code>launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist</code> pour désactiver le partage de fichiers SMB. Cette action garantit que vos fichiers ne sont pas partagés par inadvertance sur le réseau, réduisant ainsi le risque d'accès non autorisé.</p>"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "launchctl load -w /System/Library/LaunchDaemons/com.apple.smbd.plist && defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist EnabledServices -array disk",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Re-enabling file sharing on macOS allows for easy file access and sharing within a network. To enable SMB file sharing, use the CLI command <code>launchctl load -w /System/Library/LaunchDaemons/com.apple.smbd.plist && defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist EnabledServices -array disk</code>. Ensure proper security measures are in place to protect shared data.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Réactiver le partage de fichiers sur macOS permet un accès et un partage de fichiers faciles au sein d'un réseau. Pour activer le partage de fichiers SMB, utilisez la commande CLI <code>launchctl load -w /System/Library/LaunchDaemons/com.apple.smbd.plist && defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist EnabledServices -array disk</code>. Assurez-vous que des mesures de sécurité appropriées sont en place pour protéger les données partagées.</p>"
          }
        ]
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
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling file sharing on your macOS system can significantly enhance your data security. Use the CLI command <code>launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist</code> to turn off SMB file sharing. This action ensures that your files are not inadvertently shared across the network, reducing the risk of unauthorized access.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver le partage de fichiers sur votre système macOS peut considérablement renforcer la sécurité de vos données. Utilisez la commande CLI <code>launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist</code> pour désactiver le partage de fichiers SMB. Cette action garantit que vos fichiers ne sont pas partagés par inadvertance sur le réseau, réduisant ainsi le risque d'accès non autorisé.</p>"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "fulldisk",
        "target": "systemsetup -setremoteappleevents on",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Re-enabling file sharing on macOS allows for easy file access and sharing within a network. To enable SMB file sharing, use the CLI command <code>launchctl load -w /System/Library/LaunchDaemons/com.apple.smbd.plist && defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist EnabledServices -array disk</code>. Ensure proper security measures are in place to protect shared data.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Réactiver le partage de fichiers sur macOS permet un accès et un partage de fichiers faciles au sein d'un réseau. Pour activer le partage de fichiers SMB, utilisez la commande CLI <code>launchctl load -w /System/Library/LaunchDaemons/com.apple.smbd.plist && defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist EnabledServices -array disk</code>. Assurez-vous que des mesures de sécurité appropriées sont en place pour protéger les données partagées.</p>"
          }
        ]
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
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Enabling Gatekeeper to block unsigned applications enhances your security by ensuring only trusted software can run on your macOS system. Use the CLI command <code>spctl --global-enable</code> to enforce application signatures. This action prevents potentially harmful applications from running, safeguarding your system against malware.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Activer Gatekeeper pour bloquer les applications non signées améliore votre sécurité en garantissant que seuls les logiciels de confiance peuvent s'exécuter sur votre système macOS. Utilisez la commande CLI <code>spctl --global-enable</code> pour imposer les signatures d'application. Cette action empêche l'exécution d'applications potentiellement dangereuses, protégeant ainsi votre système contre les logiciels malveillants.</p>"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "spctl --global-disable",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling Gatekeeper allows unsigned applications to run on your macOS system, which can be necessary for certain software not available through the App Store. If you need to do this, use the CLI command <code>spctl --global-disable</code>. Be cautious and ensure you trust any unsigned applications you choose to run, as this increases the risk of installing potentially harmful software.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver Gatekeeper permet à des applications non signées de s'exécuter sur votre système macOS, ce qui peut être nécessaire pour certains logiciels non disponibles via l'App Store. Si vous devez le faire, utilisez la commande CLI <code>spctl --global-disable</code>. Soyez prudent et assurez-vous de faire confiance à toutes les applications non signées que vous choisissez d'exécuter, car cela augmente le risque d'installer des logiciels potentiellement dangereux.</p>"
          }
        ]
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
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Automating system updates is crucial for maintaining the security and efficiency of your macOS system. Enable automatic updates with the CLI command <code>defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true; softwareupdate --schedule on</code>. This ensures your system always has the latest security patches and improvements.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Automatiser les mises à jour système est crucial pour maintenir la sécurité et l'efficacité de votre système macOS. Activez les mises à jour automatiques avec la commande CLI <code>defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true; softwareupdate --schedule on</code>. Cela garantit que votre système dispose toujours des derniers correctifs de sécurité et améliorations.</p>"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool false; softwareupdate --schedule off",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>If you need to disable automatic system updates, perhaps for testing or other specific scenarios, use the CLI command <code>defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool false; softwareupdate --schedule off</code>. Remember, this action might leave your system vulnerable to security threats.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Si vous devez désactiver les mises à jour automatiques du système, peut-être pour des tests ou d'autres scénarios spécifiques, utilisez la commande CLI <code>defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool false; softwareupdate --schedule off</code>. N'oubliez pas, cette action pourrait laisser votre système vulnérable aux menaces de sécurité.</p>"
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
          "summary": "You don't have any antivirus installed (MalwareBytes, Sentinel One, BitDefender...). We recommend you to enable one."
        },
        {
          "locale": "FR",
          "title": "Pas d'antivirus activé",
          "summary": "Vous n'avez pas d'antivirus installé (MalwareBytes, Sentinel One, BitDefender...). Nous vous recommandons d'en activer un."
        }
      ],
      "implementation": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "if ! { pgrep BDLDaemon >/dev/null || pgrep RTProtectionDaemon >/dev/null || sentinelctl version 2>/dev/null | grep -q \"Agent version\"; }; then echo noepp; fi",
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
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling the guest account on your macOS system is an important step in securing your computer against unauthorized access. To disable the guest account, open Terminal and execute the following command: <code>sudo sysadminctl -guestAccount off</code>. This command requires administrator privileges, so you may need to enter your administrator password to proceed.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver le compte invité sur votre système macOS est une étape importante pour sécuriser votre ordinateur contre les accès non autorisés. Pour désactiver le compte invité, ouvrez le Terminal et exécutez la commande suivante : <code>sudo sysadminctl -guestAccount off</code>. Cette commande nécessite des privilèges d'administrateur, donc vous devrez peut-être entrer votre mot de passe administrateur pour continuer.</p>"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "sysadminctl -guestAccount on",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>If you need to enable the guest account on your macOS for any specific reason, such as providing temporary access to your computer, you can do so safely by opening Terminal and executing the command: <code>sudo sysadminctl -guestAccount on</code>. Remember to disable the guest account again once it's no longer needed to maintain the security of your system.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Si vous devez activer le compte invité sur votre macOS pour une raison spécifique, comme fournir un accès temporaire à votre ordinateur, vous pouvez le faire en toute sécurité en ouvrant le Terminal et en exécutant la commande : <code>sudo sysadminctl -guestAccount on</code>. N'oubliez pas de désactiver à nouveau le compte invité une fois qu'il n'est plus nécessaire pour maintenir la sécurité de votre système.</p>"
          }
        ]
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
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Restricting system-wide changes is essential for maintaining the integrity and security of your macOS device. The process involves modifying the system's authorization database to ensure that only authorized users can make significant changes. Detailed guidance on how to securely configure system preferences can be found on <a href='https://support.apple.com'>Apple's support website</a>. For a deeper understanding, consulting resources such as <a href='https://developer.apple.com/documentation/security'>Apple's security documentation</a> may provide additional insights into securing macOS systems.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Restreindre les modifications à l'échelle du système est essentiel pour maintenir l'intégrité et la sécurité de votre appareil macOS. Le processus implique la modification de la base de données d'autorisation du système pour garantir que seuls les utilisateurs autorisés peuvent effectuer des changements significatifs. Des conseils détaillés sur la façon de configurer de manière sécurisée les préférences système peuvent être trouvés sur <a href='https://support.apple.com/fr-fr'>le site de support d'Apple</a>. Pour une compréhension plus approfondie, la consultation de ressources telles que <a href='https://developer.apple.com/documentation/security'>la documentation de sécurité d'Apple</a> peut fournir des informations supplémentaires sur la sécurisation des systèmes macOS.</p>"
          }
        ]
      },
      "rollback": {
        "system": "macOS",
        "minversion": 12,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "security authorizationdb read system.preferences > /tmp/system.preferences.plist; /usr/libexec/PlistBuddy -c \"Set :shared true\" /tmp/system.preferences.plist; security authorizationdb write system.preferences < /tmp/system.preferences.plist",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Rolling back the restrictions on system-wide changes can reintroduce the flexibility of allowing any user to modify system settings, which might be necessary for specific administrative tasks or troubleshooting. However, it's important to carefully consider the security implications of such a change. Guidance on managing system preferences for different user roles can be found on <a href='https://support.apple.com'>Apple's support website</a>. Additionally, <a href='https://developer.apple.com/documentation/security'>Apple's security documentation</a> offers insights on balancing security and usability in macOS systems.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Annuler les restrictions sur les modifications à l'échelle du système peut réintroduire la flexibilité permettant à tout utilisateur de modifier les paramètres du système, ce qui peut être nécessaire pour des tâches administratives spécifiques ou le dépannage. Cependant, il est important de considérer attentivement les implications en matière de sécurité d'un tel changement. Des conseils sur la gestion des préférences système pour différents rôles d'utilisateur peuvent être trouvés sur <a href='https://support.apple.com/fr-fr'>le site de support d'Apple</a>. De plus, <a href='https://developer.apple.com/documentation/security'>la documentation de sécurité d'Apple</a> offre des perspectives sur l'équilibre entre la sécurité et l'usabilité dans les systèmes macOS.</p>"
          }
        ]
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
