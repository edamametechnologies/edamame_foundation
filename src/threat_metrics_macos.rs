// Built in default threat model
pub static THREAT_METRICS_MACOS: &str = r#"{
  "date": "November 24th 2025",
  "extends": "none",
  "metrics": [
    {
      "description": [
        {
          "locale": "EN",
          "summary": "EDAMAME's Helper software is not running or requires an update. It's required for complete Security Score analysis and remediation.",
          "title": "EDAMAME helper inactive"
        },
        {
          "locale": "FR",
          "summary": "Le logiciel d'assistance d'EDAMAME n'est pas en cours d'exécution ou a besoin d'être mis à jour. Il est requis pour une analyse complète du score de sécurité.",
          "title": "EDAMAME Helper inactif"
        }
      ],
      "dimension": "system services",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "helper_check"
      },
      "metrictype": "bool",
      "name": "edamame helper disabled",
      "remediation": {
        "class": "installer",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://github.com/edamametechnologies/edamame_helper"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://github.com/edamametechnologies/edamame_helper"
          }
        ],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "https://github.com/edamametechnologies/edamame_helper/releases/download"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "If you need to uninstall the EDAMAME Helper software for any reason, you can use the provided shell script command. Note that uninstalling may affect the Security Score analysis of your system."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Si vous devez désinstaller le logiciel d'assistance EDAMAME pour une raison quelconque, vous pouvez utiliser la commande de script shell fournie. Notez que la désinstallation peut affecter l'analyse du score de sécurité de votre système."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' '/Library/Application\\ Support/Edamame/Edamame-Helper/uninstall.sh' | /bin/bash"
      },
      "scope": "generic",
      "severity": 5,
      "tags": []
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Your computer will respond if anything on the network is trying to check its presence. This can be very bad and allow anyone to check your presence and possibly attack your computer.",
          "title": "Response to ping enabled"
        },
        {
          "locale": "FR",
          "summary": "Votre ordinateur répondra si quelque chose essaie de vérifier sa présence. Cela peut être très mauvais et permettre à quiconque de vérifier votre présence sur un réseau et éventuellement d'attaquer votre ordinateur....",
          "title": "Réponse au ping activée"
        }
      ],
      "dimension": "network",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' '/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | grep -E \"disabled|is off\"' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "response to ping enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Enabling stealth mode will make your system invisible to ping requests, enhancing your network security by reducing the attack surface visible to potential attackers."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "L'activation du mode furtif rendra votre système invisible aux requêtes ping, améliorant ainsi la sécurité de votre réseau en réduisant la surface d'attaque visible par les attaquants potentiels."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' '/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on' | /bin/bash"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling stealth will make your system respond to ping requests again. Be cautious as this increases your network visibility and may expose your system to potential threats."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "La désactivation du mode furtif permettra à nouveau à votre système de répondre aux requêtes ping. Soyez prudent, car cela augmente la visibilité de votre réseau et peut exposer votre système à des menaces potentielles."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' '/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off' | /bin/bash"
      },
      "scope": "generic",
      "severity": 3,
      "tags": [
        "CIS Benchmark Level 1,Enable Stealth Mode"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "You have one or more Mobile Device Management (MDM) profiles installed on your device. This means that your device is or can be remotely administered by a 3rd party. If this is your personal computer, this is a grave threat and the profiles should be removed.",
          "title": "MDM profiles installed"
        },
        {
          "locale": "FR",
          "summary": "Un ou plusieurs profils de gestion des appareils mobiles (MDM) sont installés sur votre appareil. Cela signifie que votre appareil est, ou peut être, administré à distance par un tiers. S'il s'agit de votre ordinateur personnel, il s'agit d'une grave menace et les profils doivent être supprimés.",
          "title": "Profils MDM installés"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'profiles -P | grep profileIdentifier | grep -v digital_health_restrictions | grep -v dateandtime' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "MDM profiles",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Removing MDM profiles from your macOS device will ensure that your device is no longer managed remotely, which is crucial for maintaining personal security and privacy."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Supprimer les profils MDM de votre appareil macOS garantira que votre appareil n'est plus géré à distance, ce qui est crucial pour maintenir la sécurité et la confidentialité personnelles."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'profiles remove -all -forced' | /bin/bash"
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.apple.com/en-us/guide/deployment/depc0aadd3fe/web"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.apple.com/fr-fr/guide/deployment/depc0aadd3fe/web"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
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
          "summary": "Your computer is or can be remotely administered by a 3rd party using the JAMF MDM framework. If this is your personal computer, this is a grave threat and JAMF should be removed.",
          "title": "JAMF remote administration enabled"
        },
        {
          "locale": "FR",
          "summary": "Votre ordinateur est, ou peut être, administré à distance par un tiers à l'aide du framework JAMF MDM. S'il s'agit de votre ordinateur personnel, il s'agit d'une grave menace et JAMF doit être supprimé.",
          "title": "Administration à distance JAMF installée"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'pgrep jamf' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "MDM remote admin",
      "remediation": {
        "class": "cli",
        "education": [],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'jamf removeFramework' | /bin/bash"
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://www.jamf.com/en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://www.jamf.com/fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": ""
      },
      "scope": "macOS",
      "severity": 5,
      "tags": [
        "Personal Posture"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Wake on LAN is a feature that can wake up your computer automatically when something is attempting to connect to it. This is not something you need in most cases and it can allow an attacker to connect to your computer at any time.",
          "title": "Wake On LAN enabled"
        },
        {
          "locale": "FR",
          "summary": "Wake on LAN est une fonctionnalité qui peut réveiller automatiquement votre ordinateur lorsque quelque chose tente de s'y connecter. Ce n'est pas quelque chose dont vous avez besoin dans la plupart des cas et cela peut permettre à un malfrat de se connecter à votre ordinateur à tout moment.",
          "title": "Wake On LAN activé"
        }
      ],
      "dimension": "network",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'systemsetup getwakeonnetworkaccess | grep -v Off' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "WOL enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling Wake On LAN (WOL) prevents your computer from being remotely activated, which can be a security risk."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver le Wake On LAN (WOL) empêche votre ordinateur d'être activé à distance, ce qui peut représenter un risque de sécurité."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'systemsetup -setwakeonnetworkaccess off' | /bin/bash"
      },
      "rollback": {
        "class": "cli",
        "education": [],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'systemsetup -setwakeonnetworkaccess on' | /bin/bash"
      },
      "scope": "generic",
      "severity": 1,
      "tags": [
        "CIS Benchmark Level 1,Disable Wake on Network Access"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Applications are constantly updated to fix potential security issues. It's your best interest to get updates as soon as you can through automatic updates.",
          "title": "Manual Appstore updates"
        },
        {
          "locale": "FR",
          "summary": "Les applications sont constamment mises à jour pour résoudre les problèmes de sécurité potentiels. Il est dans votre intérêt d'obtenir les mises à jour dès que possible grâce aux mises à jour automatiques.",
          "title": "Mises à jour Appstore manuelles"
        }
      ],
      "dimension": "applications",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "globalpreferences",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'defaults read /Library/Preferences/com.apple.commerce.plist AutoUpdate 2>&1 | grep -v 1' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "manual store application updates",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "This command enables automatic updates for App Store applications and macOS."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Cette commande active les mises à jour automatiques pour les applications de l'App Store et macOS."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'defaults write /Library/Preferences/com.apple.commerce.plist AutoUpdate -bool true;' 'defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallAppUpdates -bool true;' 'defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true' | /bin/bash"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "This command disables automatic updates for App Store applications and macOS."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Cette commande désactive les mises à jour automatiques pour les applications de l'App Store et macOS."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'defaults write /Library/Preferences/com.apple.commerce.plist AutoUpdate -bool false;' 'defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallAppUpdates -bool false;' 'defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool false' | /bin/bash"
      },
      "scope": "generic",
      "severity": 3,
      "tags": [
        "CIS Benchmark Level 1,Enable App Store Automatic Update"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Your local firewall is disabled. This is fine in a trusted environment but dangerous if you happened to connect to public networks. You should turn it on by default.",
          "title": "Local firewall disabled"
        },
        {
          "locale": "FR",
          "summary": "Votre pare-feu local est désactivé. C'est bien dans un environnement de confiance mais dangereux si vous vous connectez à des réseaux publics. Vous devriez l'activer par défaut.",
          "title": "Pare-feu local désactivé"
        }
      ],
      "dimension": "network",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep disabled' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "local firewall disabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Enabling the local firewall on macOS enhances security by monitoring and controlling incoming connections."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "L'activation du pare-feu local sur macOS améliore la sécurité en surveillant et contrôlant les connexions entrantes."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' '/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on' | /bin/bash"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "If necessary, the firewall can be disabled for troubleshooting or specific network tasks, but it's recommended to keep it enabled for security."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Si nécessaire, le pare-feu peut être désactivé pour le dépannage ou pour des tâches réseau spécifiques, mais il est recommandé de le garder activé pour la sécurité."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' '/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off' | /bin/bash"
      },
      "scope": "generic",
      "severity": 2,
      "tags": [
        "CIS Benchmark Level 1,Enable Firewall"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Automatic login could appear as very handy but in fact it's a major security threat: it allows anyone to access your data without knowing your password.",
          "title": "Automatic login enabled"
        },
        {
          "locale": "FR",
          "summary": "La connexion automatique peut sembler très pratique mais en fait c'est une menace majeure pour la sécurité : elle permet à n'importe qui d'accéder à vos données sans connaître votre mot de passe.",
          "title": "Login automatique activé"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling automatic login enhances your security by requiring authentication at startup. This ensures that unauthorized users cannot access your system without entering the correct credentials."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver la connexion automatique améliore votre sécurité en exigeant une authentification au démarrage. Cela garantit que les utilisateurs non autorisés ne peuvent pas accéder à votre système sans saisir les identifiants corrects."
          }
        ],
        "elevation": "globalpreferences",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'defaults read /Library/Preferences/com.apple.loginwindow | grep autoLoginUser' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "automatic login enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling automatic login enhances your security by requiring authentication at startup. This ensures that unauthorized users cannot access your system without entering the correct credentials."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver la connexion automatique améliore votre sécurité en exigeant une authentification au démarrage. Cela garantit que les utilisateurs non autorisés ne peuvent pas accéder à votre système sans saisir les identifiants corrects."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser' | /bin/bash"
      },
      "rollback": {
        "class": "link",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "To enable automatic login again, press the button to access the relevant system settings. Click on 'Automatic login'. Choose the desired user from the dropdown menu. If prompted, enter the password for the selected user."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Pour réactiver la connexion automatique, appuyez sur le bouton pour accèder au paramètres systèmes correspondants. Cliquez sur 'Connexion automatique'. Choisissez l'utilisateur désiré dans le menu déroulant. Si vous y êtes invité, saisissez le mot de passe de l'utilisateur sélectionné."
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "x-apple.systempreferences:com.apple.preferences.users"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Disable automatic login"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Remote login is enabled. This is not necessary unless your are an IT professional. This is unusual and dangerous for most users.",
          "title": "Remote login enabled"
        },
        {
          "locale": "FR",
          "summary": "L'accès à distance est activée. Ce n'est pas nécessaire sauf si vous êtes un professionnel de l'informatique. Ceci est inhabituel et dangereux pour la plupart des utilisateurs.",
          "title": "Accès à distance activé"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'systemsetup -getremotelogin | grep On' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "remote login enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling remote login secures your macOS system by preventing unauthorized remote access."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver l'accès à distance sécurise votre système macOS en empêchant l'accès à distance non autorisé."
          }
        ],
        "elevation": "fulldisk",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'echo yes | systemsetup -setremotelogin off' | /bin/bash"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Enabling remote login allows remote users to access the system via SSH, which can be useful for remote administration but increases the risk of unauthorized access. Use this feature cautiously and ensure your firewall and user access permissions are properly configured."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "L'activation de l'accès à distance sur macOS permet aux utilisateurs distants d'accéder au système via SSH, ce qui peut être utile pour l'administration à distance mais augmente le risque d'accès non autorisé. Utilisez cette fonction avec prudence et assurez-vous que votre pare-feu et les permissions d'accès utilisateur sont correctement configurés."
          }
        ],
        "elevation": "fulldisk",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'systemsetup -setremotelogin on' | /bin/bash"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Disable Remote Login"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Remote desktop is enabled. This is not necessary unless your are an IT professional. This is unusual and dangerous for most users.",
          "title": "Remote desktop enabled"
        },
        {
          "locale": "FR",
          "summary": "La connexion au bureau à distance est activée. Ce n'est pas nécessaire sauf si vous êtes un professionnel de l'informatique. Ceci est inhabituel et dangereux pour la plupart des utilisateurs.",
          "title": "Bureau à distance activé"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'pgrep ARDAgent' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "remote desktop enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling remote desktop access can significantly enhance the security of your macOS system. This prevents unauthorized remote desktop access, ensuring only approved users can control the system remotely."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver l'accès au bureau à distance peut considérablement renforcer la sécurité de votre système macOS. Cela empêche l'accès à distance non autorisé au bureau, garantissant que seuls les utilisateurs approuvés peuvent contrôler le système à distance."
          }
        ],
        "elevation": "fulldisk",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' '/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop' | /bin/bash"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Re-enabling remote desktop services on macOS can be done through the CLI. While this enables remote management capabilities, it's crucial to ensure that only trusted users have access and that your network is secure to mitigate potential security risks."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Réactiver les services de bureau à distance sur macOS peut se faire via une ligne de commande. Bien que cela active les capacités de gestion à distance, il est crucial de s'assurer que seuls les utilisateurs de confiance ont accès et que votre réseau est sécurisé pour atténuer les risques de sécurité potentiels."
          }
        ],
        "elevation": "fulldisk",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' '/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate' | /bin/bash"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Disable Remote Desktop Sharing"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "File sharing is enabled. While this could be intentional we strongly recommend to turn it off. It's not that easy to configure and can expose your data to unwanted people.",
          "title": "File sharing enabled"
        },
        {
          "locale": "FR",
          "summary": "Le partage de fichiers est activé. Bien que cela puisse être intentionnel, nous vous recommandons fortement de le désactiver. Ce n'est pas si facile à configurer et cela peut exposer vos données à des personnes indésirables.",
          "title": "Partage de fichiers activé"
        }
      ],
      "dimension": "system services",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'launchctl list | grep smbd' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "file sharing enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling file sharing on your macOS system can significantly enhance your data security. This action ensures that your files are not inadvertently shared across the network, reducing the risk of unauthorized access."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver le partage de fichiers sur votre système macOS peut considérablement renforcer la sécurité de vos données. Cette action garantit que vos fichiers ne sont pas partagés par inadvertance sur le réseau, réduisant ainsi le risque d'accès non autorisé."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist' | /bin/bash"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Re-enabling file sharing on macOS allows for easy file access and sharing within a network. Ensure proper security measures are in place to protect shared data."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Réactiver le partage de fichiers sur macOS permet un accès et un partage de fichiers faciles au sein d'un réseau. Assurez-vous que des mesures de sécurité appropriées sont en place pour protéger les données partagées."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'launchctl load -w /System/Library/LaunchDaemons/com.apple.smbd.plist &&' 'defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist EnabledServices -array disk' | /bin/bash"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Disable File Sharing"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Remote events are enabled. While this could be intentional we strongly recommend to turn it off. It's unnecessary for most users and has been a target for exploit in the recent past.",
          "title": "Remote events enabled"
        },
        {
          "locale": "FR",
          "summary": "Les événements à distance sont activés. Bien que cela puisse être intentionnel, nous vous recommandons fortement de les désactiver. C'est inutile pour la plupart des utilisateurs et cela a été une cible d'attaques dans un passé récent.",
          "title": "Événements à distance activés"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'launchctl print-disabled system | grep com.apple.AEServer | grep -E '\"'\"'enabled|false'\"'\"'' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "remote events enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "To enhance your macOS security, disable remote Apple events, which are often unnecessary and can be exploited. This will prevent unauthorized remote control of your system."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Pour améliorer la sécurité de votre macOS, désactivez les événements Apple à distance, souvent inutiles et exploitables. Cela empêchera le contrôle à distance non autorisé de votre système."
          }
        ],
        "elevation": "fulldisk",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'systemsetup -setremoteappleevents off' | /bin/bash"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "If you need to re-enable remote Apple events for specific purposes, ensure you have the necessary security measures in place to protect your system from unauthorized access."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Si vous avez besoin de réactiver les événements Apple à distance pour des raisons spécifiques, assurez-vous d'avoir les mesures de sécurité nécessaires en place pour protéger votre système contre tout accès non autorisé."
          }
        ],
        "elevation": "fulldisk",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'systemsetup -setremoteappleevents on' | /bin/bash"
      },
      "scope": "macOS",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Disable Remote Apple Events"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "It seems your computer hard disk has been encrypted by your employer. It means that they could potentially decrypt it if you give the computer back to them. You should suppress that possibility.",
          "title": "Corporate disk recovery key"
        },
        {
          "locale": "FR",
          "summary": "Il semble que le disque dur de votre ordinateur ait été crypté par votre employeur. Cela signifie qu'ils pourraient potentiellement le déchiffrer si vous leur rendez l'ordinateur. Vous devriez supprimer cette possibilité.",
          "title": "Clé d'entreprise de récupération de disque"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'fdesetup hasinstitutionalrecoverykey | grep true' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "encrypted disk organizational recovery",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://derflounder.wordpress.com/2019/07/03/managing-macos-mojaves-filevault-2-with-fdesetup/"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://derflounder-wordpress-com.translate.goog/2019/07/03/managing-macos-mojaves-filevault-2-with-fdesetup/?_x_tr_sl=auto&_x_tr_tl=fr&_x_tr_hl=en&_x_tr_pto=wapp"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://derflounder.wordpress.com/2019/07/03/managing-macos-mojaves-filevault-2-with-fdesetup/"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://derflounder-wordpress-com.translate.goog/2019/07/03/managing-macos-mojaves-filevault-2-with-fdesetup/?_x_tr_sl=auto&_x_tr_tl=fr&_x_tr_hl=en&_x_tr_pto=wapp"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
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
          "summary": "Your main storage is not encrypted. While there is a little performance impact by enabling it, we really urge you to set it up. Without that anyone physically accessing your computer can access your data.",
          "title": "Disk encryption disabled"
        },
        {
          "locale": "FR",
          "summary": "Votre stockage principal n'est pas crypté. Bien qu'il y ait un petit impact sur les performances en l'activant, nous vous invitons vraiment à le configurer. Sans cela, toute personne accédant physiquement à votre ordinateur peut accéder à vos données.",
          "title": "Encryption du disque désactivée"
        }
      ],
      "dimension": "system services",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'system_profiler SPHardwareDataType | grep -q '\"'\"'Virtual'\"'\"' ||' 'fdesetup isactive | grep false' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "encrypted disk disabled",
      "remediation": {
        "class": "link",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "To enable FileVault, press the button to access the relevant system settings. Click 'Turn On FileVault'. Follow the prompts to set up a recovery key and restart your Mac. You will see an option to use your iCloud account to unlock your disk or create a recovery key. Select your preference and proceed."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Pour activer FileVault, appuyez sur le bouton pour accèder au paramètres systèmes correspondants. Cliquez sur 'Activer FileVault'. Suivez les instructions pour configurer une clé de récupération et redémarrez votre Mac. Vous verrez une option pour utiliser votre compte iCloud pour déverrouiller votre disque ou créer une clé de récupération. Sélectionnez votre préférence et continuez."
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "x-apple.systempreferences:com.apple.preference.security?FileVault"
      },
      "rollback": {
        "class": "link",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "To disable FileVault, press the button to access the relevant system settings. Click 'Turn Off FileVault'. Follow the prompts to decrypt your disk."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Pour désactiver FileVault, appuyez sur le bouton pour accèder au paramètres systèmes correspondants. Cliquez sur 'Désactiver FileVault'. Suivez les instructions pour déchiffrer votre disque."
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "x-apple.systempreferences:com.apple.preference.security?FileVault"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Enable FileVault",
        "ISO 27001/2,A.8.3.1-Media Protection",
        "SOC 2,CC6.7-Data Protection"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Your computer has been setup to allow unsigned applications to run. This is unusual and dangerous. You should turn this off.",
          "title": "Unsigned applications allowed"
        },
        {
          "locale": "FR",
          "summary": "Votre ordinateur a été configuré pour autoriser l'exécution d'applications non signées. C'est inhabituel et dangereux. Vous devriez désactiver cette option.",
          "title": "Applications non signées autorisées"
        }
      ],
      "dimension": "applications",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'spctl --status | grep disabled' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "unsigned applications allowed",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Enabling Gatekeeper to block unsigned applications enhances your security by ensuring only trusted software can run on your macOS system. This action prevents potentially harmful applications from running, safeguarding your system against malware."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Activer Gatekeeper pour bloquer les applications non signées améliore votre sécurité en garantissant que seuls les logiciels de confiance peuvent s'exécuter sur votre système macOS. Cette action empêche l'exécution d'applications potentiellement dangereuses, protégeant ainsi votre système contre les logiciels malveillants."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'spctl --global-enable' | /bin/bash"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "To disable Gatekeeper, open System Settings > Privacy & Security > Security section, and change \"Allow applications downloaded from\" to \"Anywhere\" (or \"App Store and identified developers\"). Note: Disabling Gatekeeper allows unsigned applications to run on your macOS system, which can be necessary for certain software not available through the App Store. Be cautious and ensure you trust any unsigned applications you choose to run, as this increases the risk of installing potentially harmful software."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Pour désactiver Gatekeeper, ouvrez Réglages Système > Confidentialité et sécurité > section Sécurité, et changez \"Autoriser les applications téléchargées depuis\" en \"N'importe où\" (ou \"App Store et développeurs identifiés\"). Note : Désactiver Gatekeeper permet à des applications non signées de s'exécuter sur votre système macOS, ce qui peut être nécessaire pour certains logiciels non disponibles via l'App Store. Soyez prudent et assurez-vous de faire confiance à toutes les applications non signées que vous choisissez d'exécuter, car cela augmente le risque d'installer des logiciels potentiellement dangereux."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'spctl --global-disable' | /bin/bash"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Enable Gatekeeper"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "System updates are manual. Your really should turn on automatic system updates to get the latest security fixes for your computer.",
          "title": "Manual system updates"
        },
        {
          "locale": "FR",
          "summary": "Les mises à jour du système sont manuelles. Vous devriez vraiment activer les mises à jour automatiques du système pour obtenir les derniers correctifs de sécurité pour votre ordinateur.",
          "title": "Mises à jour système manuelles"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "globalpreferences",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null | grep -q 1 ||' 'echo macosupdate_disabled' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "manual system updates",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Automating system updates is crucial for maintaining the security and efficiency of your macOS system. This ensures your system always has the latest security patches and improvements."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Automatiser les mises à jour système est crucial pour maintenir la sécurité et l'efficacité de votre système macOS. Cela garantit que votre système dispose toujours des derniers correctifs de sécurité et améliorations."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true;' 'defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true;' 'defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true;' 'defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true;' 'defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true;' 'softwareupdate --schedule on' | /bin/bash"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "If you need to disable automatic system updates, perhaps for testing or other specific scenarios, don't forget that this action could make your system more exposed to security threats."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Si vous devez désactiver les mises à jour automatiques du système, peut-être pour des tests ou d'autres scénarios spécifiques, n'oubliez pas que cette action pourrait laisser votre système vulnérable aux menaces de sécurité."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool false;' 'defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool false;' 'defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool false;' 'defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool false;' 'defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool false;' 'softwareupdate --schedule off' | /bin/bash"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Enable Software Update Automatic Download"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Your computer doesn't have a screensaver enabled with a password. It leaves it open for physical access by anyone. This is very dangerous!",
          "title": "Screen lock disabled"
        },
        {
          "locale": "FR",
          "summary": "Votre ordinateur n'a pas d'économiseur d'écran activé avec un mot de passe. Il le laisse ouvert à l'accès physique par n'importe qui. C'est très dangereux !",
          "title": "Ecran protégé désactivé"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'sysadminctl -screenLock status 2>&1 | grep off' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "too slow or disabled screensaver lock",
      "remediation": {
        "class": "link",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "To enable screensaver lock, press the button to access the relevant system settings. In the 'Lock Screen' settings, check the box for 'Require password after screen saver begins or display is turned off' and set the desired time interval."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Pour activer le verrouillage de l'écran de veille, appuyez sur le bouton pour accèder au paramètres systèmes correspondants. Dans les paramètres de l'écran de verrouillage, cochez la case 'Exiger le mot de passe après la mise en veille ou l'extinction de l'affichage' et définissez l'intervalle de temps souhaité."
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "x-apple.systempreferences:com.apple.Lock-Screen-Settings.extension"
      },
      "rollback": {
        "class": "link",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "To disable screensaver lock, press the button to access the relevant system settings. In the 'Lock Screen' settings, uncheck the box for 'Require password after screen saver begins or display is turned off'."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Pour désactiver le verrouillage de l'écran de veille, appuyez sur le bouton pour accèder au paramètres systèmes correspondants. Dans les paramètres de l'écran de verrouillage, décochez la case 'Exiger le mot de passe après la mise en veille ou l'extinction de l'affichage'."
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "x-apple.systempreferences:com.apple.Lock-Screen-Settings.extension"
      },
      "scope": "generic",
      "severity": 3,
      "tags": [
        "CIS Benchmark Level 1,Set inactivity interval",
        "ISO 27001/2,A.11.2.8-Unattended User Equipment",
        "SOC 2,CC6.1-Access Control"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "You don't have any antivirus installed (MalwareBytes, Sentinel One, BitDefender...). We recommend you to enable one.",
          "title": "No antivirus enabled"
        },
        {
          "locale": "FR",
          "summary": "Vous n'avez pas d'antivirus installé (MalwareBytes, Sentinel One, BitDefender...). Nous vous recommandons d'en activer un.",
          "title": "Pas d'antivirus activé"
        }
      ],
      "dimension": "applications",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'set -euo pipefail' '' 'is_proc()  { pgrep -x \"$1\" >/dev/null 2>&1; }' 'is_fproc() { pgrep -f \"$1\" >/dev/null 2>&1; }' '' 'has_crowdstrike() {' '  # CrowdStrike Falcon (system extension + app/CLI)' '  [[ -e \"/Library/LaunchDaemons/com.crowdstrike.falcon.Agent.plist\" ]] && return 0' '  command -v systemextensionsctl >/dev/null 2>&1 && \\' '    systemextensionsctl list 2>/dev/null | grep -Fq \"com.crowdstrike.falcon.Agent\" && return 0' '  [[ -x \"/Applications/Falcon.app/Contents/Resources/falconctl\" ]] && return 0' '  return 1' '}' '' 'has_carbonblack() {' '  # VMware Carbon Black Cloud / EDR (daemon plist names)' '  [[ -e \"/Library/LaunchDaemons/com.vmware.carbonblack.cloud.daemon.plist\" ]] && return 0' '  [[ -e \"/Library/LaunchDaemons/com.carbonblack.daemon.plist\" ]] && return 0' '  command -v systemextensionsctl >/dev/null 2>&1 && \\' '    systemextensionsctl list 2>/dev/null | grep -iq \"carbonblack\" && return 0' '  return 1' '}' '' 'has_ms_defender() {' '  # Microsoft Defender for Endpoint' '  if command -v mdatp >/dev/null 2>&1; then' '    # Prefer a health probe if available' '    ( mdatp health --field real_time_protection_enabled 2>/dev/null | grep -qi \"true\" ) && return 0' '    ( mdatp health --field healthy 2>/dev/null | grep -qi \"true\" ) && return 0' '  fi' '  is_fproc \"wdavdaemon\" && return 0' '  return 1' '}' '' 'has_sophos() {' '  # Sophos Intercept X / Endpoint' '  is_proc \"SophosScanD\" && return 0' '  is_fproc \"com.sophos\" && return 0' '  return 1' '}' '' 'has_symantec() {' '  # Symantec Endpoint Protection' '  is_proc \"SymDaemon\" && return 0' '  return 1' '}' '' 'has_trendmicro() {' '  # Trend Micro Apex One (macOS)' '  is_proc \"iCoreService\" && return 0' '  command -v systemextensionsctl >/dev/null 2>&1 && \\' '    systemextensionsctl list 2>/dev/null | grep -Fq \"com.trendmicro.icore.es\" && return 0' '  return 1' '}' '' 'has_cortex_xdr() {' '  # Palo Alto Networks Cortex XDR (aka Traps)' '  [[ -x \"/Library/Application Support/PaloAltoNetworks/Traps/bin/cytool\" ]] && return 0' '  is_fproc \"/Library/Application Support/PaloAltoNetworks/Traps/bin/pmd\" && return 0' '  [[ -e \"/Library/LaunchDaemons/com.paloaltonetworks.cortex.pmd.plist\" ]] && return 0' '  return 1' '}' '' 'has_jamf_protect() {' '  is_proc \"JamfProtectAgent\" && return 0' '  # protectctl exists but may not be on PATH everywhere' '  if [[ -x \"/usr/local/bin/protectctl\" ]]; then /usr/local/bin/protectctl version >/dev/null 2>&1 && return 0; fi' '  if command -v protectctl >/dev/null 2>&1; then protectctl version >/dev/null 2>&1 && return 0; fi' '  return 1' '}' '' 'has_cylance() {' '  # Cylance / BlackBerry Protect' '  [[ -e \"/Library/LaunchDaemons/com.cylance.agent_service.plist\" ]] && return 0' '  is_fproc \"CylanceSvc\" && return 0' '  return 1' '}' '' 'has_eset() {' '  # ESET Endpoint Security for macOS' '  is_proc \"esets_daemon\" && return 0' '  return 1' '}' '' 'has_bitdefender() { is_proc \"BDLDaemon\" && return 0; return 1; }   # Bitdefender' 'has_malwarebytes() { is_proc \"RTProtectionDaemon\" && return 0; return 1; } # Malwarebytes' 'has_sentinelone() { command -v sentinelctl >/dev/null 2>&1 && sentinelctl version 2>/dev/null | grep -q \"SentinelOne\" && return 0; return 1; }' '' 'has_xprotect() {' '  # Apple XProtect Remediator (built-in)' '  if command -v xprotect >/dev/null 2>&1; then' '    xprotect status 2>/dev/null | grep -Fq \"launch scans: enabled\" || return 1' '    xprotect status 2>/dev/null | grep -Fq \"background scans: enabled\" || return 1' '    return 0' '  fi' '' '  # Fallback for older macOS versions where only the XProtect process exists' '  is_fproc \"xprotect\" && return 0' '  is_proc \"XProtect\" && return 0' '  return 1' '}' '' 'has_any_edr() {' '  has_bitdefender      && return 0' '  has_malwarebytes     && return 0' '  has_sentinelone      && return 0' '  has_crowdstrike      && return 0' '  has_carbonblack      && return 0' '  has_ms_defender      && return 0' '  has_sophos           && return 0' '  has_symantec         && return 0' '  has_trendmicro       && return 0' '  has_cortex_xdr       && return 0' '  has_jamf_protect     && return 0' '  has_cylance          && return 0' '  has_eset             && return 0' '  has_xprotect         && return 0  # treat “good XProtect status” as EPP present' '  return 1' '}' '' 'if ! has_any_edr; then' '  echo \"epp_disabled\"' 'fi' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "no EPP",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://www.malwarebytes.com/"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://www.malwarebytes.com/"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://www.apple.com/fr/macos/security/"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://www.apple.com/fr/macos/security/"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": ""
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "ISO 27001/2,A.12.2.1-Malware Controls",
        "SOC 2,CC6.8-Malware Protection"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "You don't have any password manager installed. It's recommended to install one.",
          "title": "No password manager installed"
        },
        {
          "locale": "FR",
          "summary": "Vous n'avez pas de gestionnaire de mots de passe installé. Nous vous recommandons d'en installer un.",
          "title": "Pas de gestionnaire de mots de passe installé"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'set -euo pipefail' '' 'ensure_home() {' '  if [[ -n \"${HOME:-}\" && -d \"${HOME}\" ]]; then' '    return' '  fi' '' '  local user' '  user=\"$(id -un)\"' '' '  # macOS: prefer dscl lookup' '  if HOME=\"$(/usr/bin/dscl . -read \"/Users/${user}\" NFSHomeDirectory 2>/dev/null | awk '\"'\"'{print $2}'\"'\"')\"; then' '    if [[ -n \"${HOME}\" && -d \"${HOME}\" ]]; then' '      return' '    fi' '  fi' '' '  # Fallback to tilde expansion' '  if HOME=\"$(eval echo \"~${user}\")\" && [[ -n \"${HOME}\" && -d \"${HOME}\" ]]; then' '    return' '  fi' '' '  # Absolute last resort' '  HOME=\"/var/root\"' '}' '' 'ensure_home' '' 'found_pm=0' '' '# --- Native (desktop or App Store “container” apps incl. Safari extensions) ---' 'app_paths=(' '  \"/Applications/1Password.app\"' '  \"/Applications/1Password 7.app\"      # legacy' '  \"/Applications/1Password7.app\"       # legacy naming' '  \"/Applications/1Password for Safari.app\"' '  \"/Applications/Bitwarden.app\"' '  \"/Applications/LastPass.app\"' '  \"/Applications/LastPass for Safari.app\"' '  \"/Applications/Dashlane.app\"' '  \"/Applications/Keeper Password Manager.app\"' '  \"/Applications/Keeper for Safari.app\"' '  \"/Applications/Enpass.app\"' '  \"/Applications/KeePassXC.app\"' '  \"/Applications/NordPass.app\"' '  \"/Applications/RoboForm.app\"' '  \"/Applications/Zoho Vault.app\"' '  \"/Applications/Proton Pass.app\"' '  \"$HOME/Applications/Chrome Apps.localized/Google Password Manager.app\"' ')' '' 'for p in \"${app_paths[@]}\"; do' '  if [[ -d \"$p\" ]]; then' '    found_pm=1; break' '  fi' 'done' '' '# --- Chromium-family extensions (Chrome, Edge, Brave, Vivaldi) ---' '# Known extension IDs' 'chrome_ids=(' '  \"aeblfdkhhhdcdjpifhhbdiojplfjncoa\"   # 1Password – Password Manager (stable)' '  \"khgocmkkpikpnmmkgmdnfckapcdkgfaf\"   # 1Password Beta' '  \"nngceckbapebfimnlniiiahkandclblb\"   # Bitwarden' '  \"hdokiejnpimakedhajhdlcegeplioahd\"   # LastPass' '  \"fdjamakpfbbddfjaooikfcpapjohcfmg\"   # Dashlane' '  \"bfogiafebfohielmmehodmfbbebbbpei\"   # Keeper' '  \"igkpcodhieompeloncfnbekccinhapdb\"   # Zoho Vault' '  \"eiaeiblijfjekdanodkjadfinkhbfgcd\"   # NordPass' '  \"pnlccmojcmeohlpggmfnbbiapkmbliob\"   # RoboForm' '  \"oboonakemofpalcgghocfoadofidjkkk\"   # KeePassXC-Browser' '  \"kmcfomidfpdkfieipokbalgegidffkal\"   # Enpass' '  \"ghmbeldphafepmbegfdlkpapadhbakde\"   # Proton Pass' ')' '' 'chromium_bases=(' '  \"$HOME/Library/Application Support/Google/Chrome\"' '  \"$HOME/Library/Application Support/Microsoft Edge\"' '  \"$HOME/Library/Application Support/BraveSoftware/Brave-Browser\"' '  \"$HOME/Library/Application Support/Vivaldi\"' ')' '' 'if [[ $found_pm -eq 0 ]]; then' '  for base in \"${chromium_bases[@]}\"; do' '    [[ -d \"$base\" ]] || continue' '    for profile in \"$base\"/*; do' '      [[ -d \"$profile/Extensions\" ]] || continue' '      for id in \"${chrome_ids[@]}\"; do' '        if [[ -d \"$profile/Extensions/$id\" ]]; then' '          found_pm=1; break' '        fi' '      done' '      [[ $found_pm -eq 1 ]] && break' '    done' '    [[ $found_pm -eq 1 ]] && break' '  done' 'fi' '' '# --- Firefox extensions (look for known names in extensions.json) ---' 'if [[ $found_pm -eq 0 ]]; then' '  ff_root=\"$HOME/Library/Application Support/Firefox/Profiles\"' '  if [[ -d \"$ff_root\" ]]; then' '    for prof in \"$ff_root\"/*; do' '      ej=\"$prof/extensions.json\"' '      if [[ -f \"$ej\" ]] && \\' '         grep -Eiq '\"'\"'\"name\".*\"(1Password|Bitwarden|LastPass|Dashlane|Keeper|Enpass|NordPass|Zoho Vault|Proton Pass|KeePassXC)\"'\"'\"' \"$ej\"; then' '        found_pm=1; break' '      fi' '    done' '  fi' 'fi' '' '# --- Result ---' 'if [[ $found_pm -eq 0 ]]; then' '  echo \"No password manager installed\"' 'fi' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "no password manager",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://en.wikipedia.org/wiki/Password_manager"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://fr.wikipedia.org/wiki/Gestionnaire_de_mots_de_passe"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://en.wikipedia.org/wiki/Password_manager"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://fr.wikipedia.org/wiki/Gestionnaire_de_mots_de_passe"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
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
          "summary": "System Integrity Protection is a great ability of macOS that prevents any software to change system files and components. To some extent it's a 'good enough' antivirus for your Mac. Having it disabled is... unusual and dangerous. It should be enabled by default on your Mac. This content will explain a way to enable it again. Bear with me .. it's somewhat hard to achieve!",
          "title": "System Integrity Protection disabled"
        },
        {
          "locale": "FR",
          "summary": "La Protection de l'Intégrité du Système est une capacité clé de macOS qui empêche tous logiciels de modifier les fichiers et les composants du système. Dans une certaine mesure, c'est un antivirus 'assez bon' pour votre Mac. Le désactiver est... inhabituel et dangereux. Il devrait être activé par défaut sur votre Mac. Ce contenu vous expliquera comment l'activer à nouveau. Soyez courageux... c'est un peu difficile à réaliser !",
          "title": "Protection d'intégrité système désactivée"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'csrutil status | grep disabled' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "SIP disabled",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.apple.com/en-us/HT204899"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.apple.com/fr-fr/HT204899"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.apple.com/en-us/HT204899"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.apple.com/fr-fr/HT204899"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": ""
      },
      "scope": "macOS",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 1,Ensure System Integrity Protection is enabled"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Guest account is enabled. This is usually fine but it's not that easy to limit access to your data. You should disable it.",
          "title": "Guest account enabled"
        },
        {
          "locale": "FR",
          "summary": "Le compte invité est activé. C'est généralement bien, mais il n'est pas si facile de limiter l'accès à vos données. Vous devriez le désactiver.",
          "title": "Compte invité activé"
        }
      ],
      "dimension": "system services",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'sysadminctl -guestAccount status 2>&1 | grep enabled' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "guest account enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling the guest account on your macOS system is an important step in securing your computer against unauthorized access."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver le compte invité sur votre système macOS est une étape importante pour sécuriser votre ordinateur contre les accès non autorisés."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'sysadminctl -guestAccount off' | /bin/bash"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "If you need to enable the guest account on your macOS for any specific reason, such as providing temporary access to your computer, you can do so safely. Remember to disable the guest account again once it's no longer needed to maintain the security of your system."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Si vous devez activer le compte invité sur votre macOS pour une raison spécifique, comme fournir un accès temporaire à votre ordinateur, vous pouvez le faire en toute sécurité. N'oubliez pas de désactiver à nouveau le compte invité une fois qu'il n'est plus nécessaire pour maintenir la sécurité de votre système."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'sysadminctl -guestAccount on' | /bin/bash"
      },
      "scope": "macOS",
      "severity": 2,
      "tags": [
        "CIS Benchmark Level 1,Disable Guest account"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "A special system user has been configured on your computer. This is unusual and should be disabled immediately.",
          "title": "Root user enabled"
        },
        {
          "locale": "FR",
          "summary": "Un utilisateur système spécial a été configuré sur votre ordinateur. Ceci est inhabituel et doit être désactivé immédiatement.",
          "title": "Utilisateur root activé"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'dscl . -read /Users/root Password | grep '\"'\"'\\*\\*'\"'\"'' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "root user enabled",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.apple.com/HT204012"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.apple.com/fr-fr/HT204012"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.apple.com/HT204012"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.apple.com/fr-fr/HT204012"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": ""
      },
      "scope": "macOS",
      "severity": 3,
      "tags": [
        "CIS Benchmark Level 1,Disable root account"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Your computer system settings can be modified by any users. You should restrict it.",
          "title": "Unprotected system changes"
        },
        {
          "locale": "FR",
          "summary": "Les paramètres de votre système informatique peuvent être modifiés par tous les utilisateurs. Vous devriez le restreindre.",
          "title": "Changement de paramètres système non protégés"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'security authorizationdb read system.preferences 2> /dev/null | grep -A1 shared | grep true' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "unprotected system wide changes",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Restricting system-wide changes is essential for maintaining the integrity and security of your macOS device. The process involves modifying the system's authorization database to ensure that only authorized users can make significant changes. Detailed guidance on how to securely configure system preferences can be found on <a href='https://support.apple.com'>Apple's support website</a>. For a deeper understanding, consulting resources such as <a href='https://developer.apple.com/documentation/security'>Apple's security documentation</a> may provide additional insights into securing macOS systems."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Restreindre les modifications à l'échelle du système est essentiel pour maintenir l'intégrité et la sécurité de votre appareil macOS. Le processus implique la modification de la base de données d'autorisation du système pour garantir que seuls les utilisateurs autorisés peuvent effectuer des changements significatifs. Des conseils détaillés sur la façon de configurer de manière sécurisée les préférences système peuvent être trouvés sur <a href='https://support.apple.com/fr-fr'>le site de support d'Apple</a>. Pour une compréhension plus approfondie, la consultation de ressources telles que <a href='https://developer.apple.com/documentation/security'>la documentation de sécurité d'Apple</a> peut fournir des informations supplémentaires sur la sécurisation des systèmes macOS."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'security authorizationdb read system.preferences > /tmp/system.preferences.plist;' '/usr/libexec/PlistBuddy -c \"Set :shared false\" /tmp/system.preferences.plist;' 'security authorizationdb write system.preferences < /tmp/system.preferences.plist' | /bin/bash"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Rolling back the restrictions on system-wide changes can reintroduce the flexibility of allowing any user to modify system settings, which might be necessary for specific administrative tasks or troubleshooting. However, it's important to carefully consider the security implications of such a change. Guidance on managing system preferences for different user roles can be found on <a href='https://support.apple.com'>Apple's support website</a>. Additionally, <a href='https://developer.apple.com/documentation/security'>Apple's security documentation</a> offers insights on balancing security and usability in macOS systems."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Annuler les restrictions sur les modifications à l'échelle du système peut réintroduire la flexibilité permettant à tout utilisateur de modifier les paramètres du système, ce qui peut être nécessaire pour des tâches administratives spécifiques ou le dépannage. Cependant, il est important de considérer attentivement les implications en matière de sécurité d'un tel changement. Des conseils sur la gestion des préférences système pour différents rôles d'utilisateur peuvent être trouvés sur <a href='https://support.apple.com/fr-fr'>le site de support d'Apple</a>. De plus, <a href='https://developer.apple.com/documentation/security'>la documentation de sécurité d'Apple</a> offre des perspectives sur l'équilibre entre la sécurité et l'usabilité dans les systèmes macOS."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'security authorizationdb read system.preferences > /tmp/system.preferences.plist;' '/usr/libexec/PlistBuddy -c \"Set :shared true\" /tmp/system.preferences.plist;' 'security authorizationdb write system.preferences < /tmp/system.preferences.plist' | /bin/bash"
      },
      "scope": "macOS",
      "severity": 3,
      "tags": [
        "CIS Benchmark Level 1,Enable system wide preferences"
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
        "minversion": 12,
        "system": "macOS",
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
        "minversion": 12,
        "system": "macOS",
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
        "minversion": 12,
        "system": "macOS",
        "target": ""
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
        "minversion": 12,
        "system": "macOS",
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
        "minversion": 12,
        "system": "macOS",
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
        "minversion": 12,
        "system": "macOS",
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
          "summary": "The egress network traffic is not verified or contains anomalous traffic.",
          "title": "Unverified or anomalous traffic"
        },
        {
          "locale": "FR",
          "summary": "Le trafic réseau sortant n'est pas vérifié ou contient du trafic anormal.",
          "title": "Trafic sortant non vérifié ou non sécurisé"
        }
      ],
      "dimension": "network",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "egresscan"
      },
      "metrictype": "bool",
      "name": "egresscan",
      "remediation": {
        "class": "internal",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "<p>Inspect the egress network traffic to identify potential threats by following these steps:</p><ul><li>Navigate to the 'Sessions' tab.</li><li>Press the 'Capture' button.</li><li>If an anomalous session is identified, take appropriate action.</li></ul>"
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "<p>Inspectez le trafic réseau sortant pour identifier les menaces potentielles en suivant ces étapes:</p><ul><li>Allez dans l'onglet 'Sessions'.</li><li>Appuyez sur le bouton 'Capture'.</li><li>Si une session anormale est identifiée, prenez les mesures appropriées.</li></ul>"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "session_manager"
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
        "minversion": 12,
        "system": "macOS",
        "target": "session_manager"
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
          "summary": "Your operating system is not up to date, please proceed to upgrade to get the latest security patches.",
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
        "class": "cli",
        "education": [],
        "elevation": "globalpreferences",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist | grep macOS' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "latest os",
      "remediation": {
        "class": "link",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "To update your macOS, press the button to access the relevant system settings. Click 'Update Now' or 'Upgrade Now' if an update is available and follow the prompts to install the latest version."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Pour mettre à jour votre macOS, appuyez sur le bouton pour accèder au paramètres systèmes correspondants. Cliquez sur 'Mettre à jour maintenant' ou 'Mettre à niveau maintenant' si une mise à jour est disponible et suivez les instructions pour installer la dernière version."
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "x-apple.systempreferences:com.apple.preferences.softwareupdate"
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://www.macworld.com/article/673171/how-to-install-older-versions-of-macos-or-os-x.html"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://www.techadvisor.com/article/1490855/comment-installer-ancienne-version-macos.html"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": ""
      },
      "scope": "generic",
      "severity": 2,
      "tags": [
        "CIS Benchmark Level 1,Enable Software Update"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Your Google Chrome browser is not up to date. Running the latest version ensures you have the latest security features and performance improvements.",
          "title": "Chrome browser not up to date"
        },
        {
          "locale": "FR",
          "summary": "Votre navigateur Google Chrome n'est pas à jour. Exécuter la dernière version garantit que vous disposez des dernières fonctionnalités de sécurité et des améliorations de performance.",
          "title": "Navigateur Chrome non à jour"
        }
      ],
      "dimension": "applications",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'defaults read /Applications/Google\\ Chrome.app/Contents/Info.plist CFBundleShortVersionString &>/dev/null &&' '{ local_version=$(defaults read /Applications/Google\\ Chrome.app/Contents/Info.plist CFBundleShortVersionString);' 'latest_version=$(curl -s \"https://formulae.brew.sh/api/cask/google-chrome.json\" | sed -n '\"'\"'s/.*\\\"version\\\": \\\"\\([^\\\"]*\\)\\\".*/\\1/p'\"'\"');' 'if [ \"$(printf '\"'\"'%s\\n%s\\n'\"'\"' \"$local_version\" \"$latest_version\" | sort -V | tail -n1)\" = \"$latest_version\" ] &&' '[ \"$local_version\" != \"$latest_version\" ];' 'then echo \"Chrome is not up to date (Installed: $local_version, Latest: $latest_version)\";' 'fi;' '}' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "Chrome not uptodate",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/chrome/answer/95414"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/chrome/answer/95414?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/chrome/a/answer/6350036"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/chrome/a/answer/6350036?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
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
          "summary": "One or more business rules are not respected. Please check the command output for more details. To enable business rules, set the EDAMAME_BUSINESS_RULES_CMD environment variable. See: https://github.com/edamametechnologies/edamame_posture_cli?tab=readme-ov-file#business-rules",
          "title": "Business rule not respected"
        },
        {
          "locale": "FR",
          "summary": "Une ou plusieurs règles métier ne sont pas respectées. Veuillez consulter la sortie de la commande pour plus de détails. Pour activer les règles métier, définissez la variable d'environnement EDAMAME_BUSINESS_RULES_CMD. Voir : https://github.com/edamametechnologies/edamame_posture_cli?tab=readme-ov-file#business-rules",
          "title": "Règle métier non respectée"
        }
      ],
      "dimension": "applications",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "business_rules"
      },
      "metrictype": "bool",
      "name": "Business rule not respected",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Refer to the business rules documentation for more details."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Consultez la documentation des règles métier pour plus de détails."
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Refer to the business rules documentation for more details."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Consultez la documentation des règles métier pour plus de détails."
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": ""
      },
      "scope": "generic",
      "severity": 1,
      "tags": []
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Command-line interface (CLI) access is not restricted for standard users. Non-administrator users can access interactive shell environments, which may allow unauthorized system modifications or circumvention of security policies.",
          "title": "CLI not restricted for standard users"
        },
        {
          "locale": "FR",
          "summary": "L'accès à l'interface de ligne de commande (CLI) n'est pas restreint pour les utilisateurs standard. Les utilisateurs non-administrateurs peuvent accéder aux environnements shell interactifs, ce qui peut permettre des modifications système non autorisées ou le contournement des politiques de sécurité.",
          "title": "CLI non restreint pour les utilisateurs standard"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'grep -q \"BEGIN RESTRICT_ZSH_NONADMINS\" /etc/zshrc ||' 'echo CLI not restricted' | /bin/bash"
      },
      "metrictype": "bool",
      "name": "CLI not restricted for standard users",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Restricting command-line access for standard users prevents unauthorized system modifications and helps enforce security policies. This measure is particularly important in managed environments where users should not have direct shell access."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Restreindre l'accès à la ligne de commande pour les utilisateurs standard empêche les modifications système non autorisées et aide à appliquer les politiques de sécurité. Cette mesure est particulièrement importante dans les environnements gérés où les utilisateurs ne devraient pas avoir d'accès shell direct."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'grep -q \"BEGIN RESTRICT_ZSH_NONADMINS\" /etc/zshrc ||' 'cat <<'\"'\"'EOF'\"'\"' >> /etc/zshrc' '# BEGIN RESTRICT_ZSH_NONADMINS' '## Prevent non-admin users from using interactive zsh shells' 'if [[ -t 1 ]];' 'then' '  if ! id -Gn | grep -qw admin;' 'then' '    echo \"\"' '    echo \"Command-line access is restricted by your administrator.\"' '    osascript -e \"display alert \\\"Access Restricted\\\" message \\\"Command-line tools are blocked for standard users.\\\" buttons {\\\"OK\\\"}\" 2>/dev/null ||' 'true' '    exit 1' '  fi' 'fi' '# END RESTRICT_ZSH_NONADMINS' 'EOF' | /bin/bash"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Removing CLI restrictions will allow standard users to access interactive shell environments again. This may be necessary for users who require command-line access for legitimate purposes, but it reduces system security in managed environments."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Supprimer les restrictions CLI permettra aux utilisateurs standard d'accéder à nouveau aux environnements shell interactifs. Cela peut être nécessaire pour les utilisateurs qui ont besoin d'un accès en ligne de commande à des fins légitimes, mais cela réduit la sécurité du système dans les environnements gérés."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 12,
        "system": "macOS",
        "target": "printf '%s\\n' 'python3 - <<'\"'\"'PY'\"'\"'' 'skip = False' 'lines = []' 'with open(\"/etc/zshrc\") as src:' '    for line in src:' '        if \"BEGIN RESTRICT_ZSH_NONADMINS\" in line:' '            skip = True' '            continue' '        if \"END RESTRICT_ZSH_NONADMINS\" in line:' '            skip = False' '            continue' '        if not skip:' '            lines.append(line)' 'with open(\"/etc/zshrc\", \"w\") as dst:' '    dst.writelines(lines)' 'print(\"[OK] zsh block removed\")' 'PY' | /bin/bash"
      },
      "scope": "macOS",
      "severity": 3,
      "tags": [
        "Personal Posture"
      ]
    }
  ],
  "name": "threat model macOS",
  "signature": "26a075778bc7cfc60c4bc2b69ca55bbdc4f7caad3d2bc1cf29e12a03f2b87147"
}"#;
