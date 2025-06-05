// Built in default threat model
pub static THREAT_METRICS_LINUX: &str = r#"{
  "date": "June 01th 2025",
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
        "minversion": 3,
        "system": "Linux",
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
        "minversion": 3,
        "system": "Linux",
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
        "minversion": 3,
        "system": "Linux",
        "target": "apt remove edamame-helper"
      },
      "scope": "generic",
      "severity": 5,
      "tags": []
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "You don't have any antivirus enabled (Sentinel One...). We recommend you to enable one.",
          "title": "No antivirus enabled"
        },
        {
          "locale": "FR",
          "summary": "Vous n'avez pas d'antivirus activé (Sentinel One...). Nous vous recommandons d'en activer un.",
          "title": "Pas d'antivirus activé"
        }
      ],
      "dimension": "applications",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "sentinel_found=0; forti_found=0; if command -v sentinelctl >/dev/null 2>&1 && LANG=C sentinelctl version 2>/dev/null | grep -q \"Agent version\"; then sentinel_found=1; fi; if pgrep -f FortiEDRAvScanner >/dev/null 2>&1; then forti_found=1; fi; if [ $sentinel_found -eq 0 ] && [ $forti_found -eq 0 ]; then echo \"epp_disabled\"; fi"
      },
      "metrictype": "bool",
      "name": "no EPP",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://help.ubuntu.com/community/Antivirus"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "FR",
            "target": "https://fr.wikipedia.org/wiki/Antivirus"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
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
        "minversion": 3,
        "system": "Linux",
        "target": "(command -v pass || command -v keepassxc || command -v bw || command -v lpass || command -v gopass || command -v 1password) >/dev/null 2>&1 || echo \"No password manager installed\""
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
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "FR",
            "target": "https://fr.wikipedia.org/wiki/Gestionnaire_de_mots_de_passe"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
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
          "summary": "Your main disk and swap are not encrypted. Enabling disk encryption helps protect your data from unauthorized access.",
          "title": "Disk encryption disabled"
        },
        {
          "locale": "FR",
          "summary": "Votre disque principal et votre swap ne sont pas cryptés. Activer le cryptage du disque aide à protéger vos données contre tout accès non autorisé.",
          "title": "Cryptage du disque désactivé"
        }
      ],
      "dimension": "system services",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "apt update -qq > /dev/null 2>&1 || true && apt install virt-what -y > /dev/null 2>&1 && [ -z \"$(virt-what)\" ] && { root_dev=$(findmnt -n -o SOURCE /); swap_dev=$(swapon --show=NAME --noheadings 2>/dev/null | head -n1); root_parent=$(lsblk -n -o NAME,TYPE,MOUNTPOINT -p | grep \" $(readlink -f \"$root_dev\")$\" | cut -d\" \" -f1); lsblk -n -o NAME,TYPE -p | grep -q \"^$root_parent.*crypt$\" || echo \"root_encryption_disabled\"; if [ -n \"$swap_dev\" ]; then swap_parent=$(lsblk -n -o NAME,TYPE,MOUNTPOINT -p | grep \" $(readlink -f \"$swap_dev\")$\" | cut -d\" \" -f1); lsblk -n -o NAME,TYPE -p | grep -q \"^$swap_parent.*crypt$\" || echo \"swap_encryption_disabled\"; fi; }"
      },
      "metrictype": "bool",
      "name": "encrypted disk disabled",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://help.ubuntu.com/community/FullDiskEncryptionHowto"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://help.ubuntu.com/community/FullDiskEncryptionHowto"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 2,Configure Disk Encryption",
        "ISO 27001/2,A.8.3.1-Media Protection",
        "SOC 2,CC6.7-Data Protection"
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
        "minversion": 3,
        "system": "Linux",
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
        "minversion": 3,
        "system": "Linux",
        "target": "digitalidentity_manager"
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://haveibeenpwned.com/"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
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
        "minversion": 3,
        "system": "Linux",
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
        "minversion": 3,
        "system": "Linux",
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
        "minversion": 3,
        "system": "Linux",
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
          "summary": "The /etc/passwd file in Unix and Linux systems contains user account information. The recommended permissions for this file are 644. This means:\nThe owner (usually root) has read and write permissions (6).\nThe group and other users have read-only permissions (4).\nThis setup ensures that only the superuser can modify the file, preserving system security. Meanwhile, other users and processes can still read the information they need from the file. This balance of functionality and security is why 644 permissions are considered good practice for the /etc/passwd file.",
          "title": "File permissions /etc/passwd"
        },
        {
          "locale": "FR",
          "summary": "Le fichier `/etc/passwd` dans les systèmes Unix et Linux contient des informations sur les comptes utilisateurs. Les permissions recommandées pour ce fichier sont `644`. Cela signifie que :\n- Le propriétaire (généralement `root`) a les permissions de lecture et d'écriture (6).\n- Le groupe et les autres utilisateurs ont les permissions de lecture seule (4).\nCette configuration garantit que seul le superutilisateur peut modifier le fichier, préservant ainsi la sécurité du système. Pendant ce temps, les autres utilisateurs et processus peuvent toujours lire les informations dont ils ont besoin à partir du fichier. Cet équilibre entre fonctionnalité et sécurité est la raison pour laquelle les permissions `644` sont considérées comme une bonne pratique pour le fichier `/etc/passwd`.",
          "title": "Permissions du fichier /etc/passwd"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "stat /etc/passwd | grep -q '(0644/-rw-r--r--)' || echo bad_permissions"
      },
      "metrictype": "bool",
      "name": "passwd permissions",
      "remediation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "chmod 644 /etc/passwd"
      },
      "rollback": {
        "class": "",
        "education": [],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 1,Verify Password File Permissions"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "The /etc/shadow file in Unix and Linux systems stores encrypted password data for each user and has stricter permissions than /etc/passwd. This is because /etc/shadow contains sensitive data.\nThe recommended permissions for the /etc/shadow file are 640:\n6 (read and write) for the owner, who should be the root or superuser. This allows the system to modify the file when passwords are changed.\n0 for the group and others. This means no permissions are given to the group or others, meaning they cannot read, write, or execute the file.",
          "title": "File permissions /etc/shadow"
        },
        {
          "locale": "FR",
          "summary": "Le fichier `/etc/shadow` dans les systèmes Unix et Linux stocke les données de mot de passe cryptées pour chaque utilisateur et a des permissions plus strictes que `/etc/passwd`. Cela est dû au fait que `/etc/shadow` contient des données sensibles.\nLes permissions recommandées pour le fichier `/etc/shadow` sont `640` :\n- `6` (lecture et écriture) pour le propriétaire, qui devrait être l'utilisateur root ou superutilisateur. Cela permet au système de modifier le fichier lorsque les mots de passe sont changés.\n- `0` pour le groupe et les autres. Cela signifie qu'aucune permission n'est donnée au groupe ou aux autres, ce qui signifie qu'ils ne peuvent pas lire, écrire ou exécuter le fichier.",
          "title": "Permissions du fichier /etc/shadow"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "stat /etc/shadow | grep -q '(0640/-rw-r-----)' || echo bad_permissions"
      },
      "metrictype": "bool",
      "name": "shadow permissions",
      "remediation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "chmod 640 /etc/shadow"
      },
      "rollback": {
        "class": "",
        "education": [],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 1,Verify Shadow File Permissions"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "The `/etc/fstab` file in Unix and Linux systems provides a table of filesystems that should be mounted automatically at system startup. This file contains important information like what filesystems to mount, where to mount them, and what options to use.\nGiven its significance, the recommended permissions for the `/etc/fstab` file are `644`:\n- `6` (read and write) for the owner, which should be the root or superuser. This allows the system to modify the file when filesystems are added or removed.\n- `4` (read-only) for the group and others. This allows users and processes to read the file and understand the system's filesystems, but prevents them from making potentially harmful changes.\nThis setup ensures only the root user can modify the file, protecting the system's filesystem configuration. Meanwhile, it allows other users and processes to read the file, providing necessary access to filesystem information.",
          "title": "File permissions /etc/fstab"
        },
        {
          "locale": "FR",
          "summary": "Le fichier `/etc/fstab` dans les systèmes Unix et Linux fournit une table des systèmes de fichiers qui doivent être montés automatiquement au démarrage du système. Ce fichier contient des informations importantes telles que les systèmes de fichiers à monter, où les monter et quelles options utiliser.\nCompte tenu de son importance, les permissions recommandées pour le fichier `/etc/fstab` sont `644` :\n- `6` (lecture et écriture) pour le propriétaire, qui devrait être l'utilisateur root ou superutilisateur. Cela permet au système de modifier le fichier lorsque des systèmes de fichiers sont ajoutés ou supprimés.\n- `4` (lecture seule) pour le groupe et les autres. Cela permet aux utilisateurs et aux processus de lire le fichier et de comprendre les systèmes de fichiers du système, mais les empêche d'apporter des modifications potentiellement nuisibles.\nCette configuration garantit que seul l'utilisateur root peut modifier le fichier, protégeant ainsi la configuration du système de fichiers.",
          "title": "Permissions du fichier /etc/fstab"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "stat /etc/fstab | grep -q '(0644/-rw-r--r--)' || echo bad_permissions"
      },
      "metrictype": "bool",
      "name": "fstab permissions",
      "remediation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "chmod 644 /etc/fstab"
      },
      "rollback": {
        "class": "",
        "education": [],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "scope": "generic",
      "severity": 5,
      "tags": []
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "The `/etc/group` file in Unix and Linux systems stores group information or data. It contains a list of all the groups on the system, along with each group's associated users.\nGiven its importance, the recommended permissions for the `/etc/group` file are `644`:\n- `6` (read and write) for the owner, which should be the root or superuser. This allows the system to add or remove groups or modify group membership.\n- `4` (read-only) for the group and others. This allows users and processes to read the file and understand the system's group memberships, but prevents them from making unauthorized changes.\nThis setup ensures only the root user can modify the file, protecting the system's group configuration. Meanwhile, it allows other users and processes to read the file, providing necessary access to group information.",
          "title": "File permissions /etc/group"
        },
        {
          "locale": "FR",
          "summary": "Le fichier `/etc/group` dans les systèmes Unix et Linux stocke les informations ou les données des groupes. Il contient une liste de tous les groupes sur le système, ainsi que les utilisateurs associés à chaque groupe.\nCompte tenu de son importance, les permissions recommandées pour le fichier `/etc/group` sont `644` :\n- `6` (lecture et écriture) pour le propriétaire, qui devrait être l'utilisateur root ou superutilisateur. Cela permet au système d'ajouter ou de supprimer des groupes ou de modifier l'appartenance à un groupe.\n- `4` (lecture seule) pour le groupe et les autres. Cela permet aux utilisateurs et aux processus de lire le fichier et de comprendre l'appartenance aux groupes du système, mais les empêche de faire des modifications non autorisées.\nCette configuration garantit que seul l'utilisateur root peut modifier le fichier, protégeant ainsi la configuration des groupes du système. En même temps, elle permet aux autres utilisateurs et processus de lire le fichier, fournissant l'accès nécessaire aux informations sur les groupes.",
          "title": "Permissions du fichier /etc/group"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "stat /etc/group | grep -q '(0644/-rw-r--r--)' || echo bad_permissions"
      },
      "metrictype": "bool",
      "name": "group permissions",
      "remediation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "chmod 644 /etc/group"
      },
      "rollback": {
        "class": "",
        "education": [],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 1,Verify Group File Permissions"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "The `/etc/group` file should be owned by the root group to maintain the integrity and confidentiality of group information stored within. Incorrect group ownership could lead to unauthorized access or modification of this sensitive file, compromising system security.",
          "title": "Group Ownership of /etc/group"
        },
        {
          "locale": "FR",
          "summary": "Le fichier `/etc/group` doit être possédé par le groupe root pour maintenir l'intégrité et la confidentialité des informations du groupe stockées à l'intérieur. Une appartenance au groupe incorrecte pourrait conduire à un accès ou une modification non autorisés de ce fichier sensible, compromettant la sécurité du système.",
          "title": "Appartenance au groupe de /etc/group"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "ls -l /etc/group | grep -q \"root root\" || echo bad_group"
      },
      "metrictype": "bool",
      "name": "group group",
      "remediation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "chown root:root /etc/group"
      },
      "rollback": {
        "class": "",
        "education": [],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 1,Verify Group File Ownership"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "The `/etc/shadow` file should be owned by the root group or a specific security or system group. This file contains sensitive user information such as encrypted passwords. Incorrect group ownership could lead to unauthorized access or potential manipulation of this critical file, compromising system security and user confidentiality.",
          "title": "Group Ownership of /etc/shadow"
        },
        {
          "locale": "FR",
          "summary": "Le fichier `/etc/shadow` doit être possédé par le groupe root ou un groupe spécifique de sécurité ou système. Ce fichier contient des informations sensibles sur l'utilisateur, telles que des mots de passe cryptés. Une appartenance au groupe incorrecte pourrait conduire à un accès non autorisé ou une manipulation potentielle de ce fichier critique, compromettant la sécurité du système et la confidentialité de l'utilisateur.",
          "title": "Appartenance au groupe de /etc/shadow"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "ls -l /etc/shadow | grep -q \"root shadow\" || echo bad_group"
      },
      "metrictype": "bool",
      "name": "shadow group",
      "remediation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "chown root:shadow /etc/shadow"
      },
      "rollback": {
        "class": "",
        "education": [],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 1,Verify Shadow File Group Ownership"
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
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "LANG=C apt update -qq > /dev/null 2>&1 || true && apt list --upgradeable 2>/dev/null | grep -q \"upgradable\" && echo os_outdated"
      },
      "metrictype": "bool",
      "name": "latest os",
      "remediation": {
        "class": "cli",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "apt update -qq > /dev/null 2>&1 || true && apt upgrade -y"
      },
      "rollback": {
        "class": "",
        "education": [],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "scope": "generic",
      "severity": 2,
      "tags": [
        "CIS Benchmark Level 1,Ensure package manager repositories are configured"
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
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "if command -v ufw >/dev/null 2>&1; then output=$(LANG=C ufw status 2>&1); ufw_exit_code=$?; if [ $ufw_exit_code -eq 0 ]; then echo \"$output\" | grep -qi \"Status: active\" || echo firewall_disabled; fi; fi"
      },
      "metrictype": "bool",
      "name": "local firewall disabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://help.ubuntu.com/community/UFW"
          }
        ],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "apt update -qq > /dev/null 2>&1 || true && apt install ufw -y > /dev/null 2>&1 && ufw enable"
      },
      "rollback": {
        "class": "",
        "education": [],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "ufw disable"
      },
      "scope": "generic",
      "severity": 3,
      "tags": [
        "CIS Benchmark Level 1,Ensure UFW is installed"
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
        "minversion": 3,
        "system": "Linux",
        "target": "LANG=C systemctl is-active ssh | grep -q \"inactive\" || echo remote_login_enabled"
      },
      "metrictype": "bool",
      "name": "remote login enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling remote login secures your Linux system by preventing unauthorized remote access. This command requires superuser permissions to execute and ensures that your system is only accessible by authorized users locally."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver l'accès à distance sécurise votre système Linux en empêchant l'accès à distance non autorisé. Cette commande nécessite des permissions de super utilisateur pour s'exécuter et garantit que votre système est uniquement accessible localement par les utilisateurs autorisés."
          }
        ],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "systemctl stop ssh && systemctl disable ssh"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Enabling remote login on Linux allows remote users to access the system via SSH, which can be useful for remote administration but increases the risk of unauthorized access. Use this feature cautiously and ensure your firewall and user access permissions are properly configured."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "L'activation de l'accès à distance sur Linux permet aux utilisateurs distants d'accéder au système via SSH, ce qui peut être utile pour l'administration à distance mais augmente le risque d'accès non autorisé. Utilisez cette fonction avec prudence et assurez-vous que votre pare-feu et les permissions d'accès utilisateur sont correctement configurés."
          }
        ],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "systemctl enable ssh && systemctl start ssh"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Ensure SSH Server is configured with appropriate ciphers"
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
        "elevation": "user",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "LANG=C systemctl is-active xrdp 2>/dev/null | grep -q \"inactive\" || echo rdp_enabled"
      },
      "metrictype": "bool",
      "name": "remote desktop enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling remote desktop access can significantly enhance the security of your Linux system. This prevents unauthorized remote desktop access, ensuring only approved users can control the system remotely."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver l'accès au bureau à distance peut considérablement renforcer la sécurité de votre système Linux. Cela empêche l'accès à distance non autorisé au bureau, garantissant que seuls les utilisateurs approuvés peuvent contrôler le système à distance."
          }
        ],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "systemctl stop xrdp && systemctl disable xrdp"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Re-enabling remote desktop services on Linux enables remote management capabilities. It's crucial to ensure that only trusted users have access and that your network is secure to mitigate potential security risks."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Réactiver les services de bureau à distance sur Linux active les capacités de gestion à distance. Il est crucial de s'assurer que seuls les utilisateurs de confiance ont accès et que votre réseau est sécurisé pour atténuer les risques de sécurité potentiels."
          }
        ],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "apt update -qq > /dev/null 2>&1 || true && apt install xrdp -y > /dev/null 2>&1 && systemctl start xrdp && systemctl enable xrdp"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Ensure remote administration tools are not installed"
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
        "elevation": "user",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "LANG=C systemctl is-active nfs-kernel-server 2>/dev/null | grep -q \"inactive\" || echo nfs_enabled; LANG=C systemctl is-active smbd 2>/dev/null | grep -q \"inactive\" || echo smb_enabled"
      },
      "metrictype": "bool",
      "name": "file sharing enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling file sharing on your Linux system can significantly enhance your data security. This action ensures that your files are not inadvertently accessible to unauthorized users over the network."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver le partage de fichiers sur votre système Linux peut considérablement améliorer la sécurité de vos données. Cette action garantit que vos fichiers ne sont pas accessibles par inadvertance à des utilisateurs non autorisés sur le réseau."
          }
        ],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "systemctl stop smbd && systemctl disable smbd; systemctl stop nfs-kernel-server && systemctl disable nfs-kernel-server"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "If you re-enable file sharing services can allow for file sharing capabilities, make sure that appropriate security measures and user permissions are in place to protect sensitive data."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Si vous éactivez les services de partage de fichiers, assurez-vous que des mesures de sécurité appropriées et des permissions utilisateur sont en place pour protéger les données sensibles."
          }
        ],
        "elevation": "admin",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "apt update -qq > /dev/null 2>&1 || true && apt install samba -y > /dev/null 2>&1 && systemctl start smbd && systemctl enable smbd && apt install nfs-kernel-server -y > /dev/null 2>&1 && systemctl start nfs-kernel-server && systemctl enable nfs-kernel-server"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Ensure NFS and RPC are not enabled"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "When the screen saver is active, we recommend that a password is required to exit it. Otherwise anyone could access your computer while you are away.",
          "title": "Screen saver requires password disabled"
        },
        {
          "locale": "FR",
          "summary": "Lorsque l'économiseur d'écran est actif, nous recommandons qu'un mot de passe soit requis pour en sortir. Sinon, n'importe qui pourrait accéder à votre ordinateur pendant votre absence.",
          "title": "Économiseur d'écran nécessite un mot de passe désactivé"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "LANG=C gsettings get org.gnome.desktop.screensaver lock-enabled | grep -q \"true\" || echo screensaver_lock_disabled"
      },
      "metrictype": "bool",
      "name": "too slow or disabled screensaver lock",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Enabling screen locking on your Linux system ensures that a password is required to exit the screensaver, protecting your system from unauthorized access when unattended."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "L'activation du verrouillage de l'écran sur votre système Linux garantit qu'un mot de passe est requis pour quitter l'économiseur d'écran, protégeant votre système contre les accès non autorisés en votre absence."
          }
        ],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "gsettings set org.gnome.desktop.screensaver lock-enabled true"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling screen locking reduces the security of your system by allowing anyone to access it when the screensaver is active."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver le verrouillage de l'écran réduit la sécurité de votre système en permettant à quiconque d'y accéder lorsque l'économiseur d'écran est actif."
          }
        ],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "gsettings set org.gnome.desktop.screensaver lock-enabled false"
      },
      "scope": "generic",
      "severity": 3,
      "tags": [
        "CIS Benchmark Level 1,Lock inactive user accounts",
        "ISO 27001/2,A.11.2.8-Unattended User Equipment",
        "SOC 2,CC6.1-Logical Access"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Secure Boot is a security standard developed to ensure that a device boots using only software that is trusted by the Original Equipment Manufacturer (OEM). Enabling Secure Boot helps protect against bootloader attacks.",
          "title": "Secure boot disabled"
        },
        {
          "locale": "FR",
          "summary": "Le Secure Boot est une norme de sécurité développée pour garantir qu'un appareil démarre uniquement avec des logiciels de confiance par le fabricant d'équipements d'origine (OEM). Activer Secure Boot aide à protéger contre les attaques de démarrage.",
          "title": "Secure Boot désactivé"
        }
      ],
      "dimension": "system services",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "LANG=C mokutil --sb-state | grep -q \"SecureBoot enabled\" || echo secure_boot_disabled"
      },
      "metrictype": "bool",
      "name": "secure boot disabled",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://wiki.debian.org/SecureBoot"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://wiki.debian.org/SecureBoot"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 2,Ensure Secure Boot is enabled"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Enforcing a strong password policy is essential to protect against unauthorized access. Ensure that the system has a robust password policy implemented.",
          "title": "Weak password policy"
        },
        {
          "locale": "FR",
          "summary": "L'application d'une politique de mot de passe robuste est essentielle pour se protéger contre les accès non autorisés. Assurez-vous que le système dispose d'une politique de mot de passe solide.",
          "title": "Politique de mot de passe faible"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": "[ ! -f /etc/security/pwquality.conf ] && echo \"weak password_policy: pwquality is not in use\" || ! grep -qvE '^\\s*#|^\\s*$' /etc/security/pwquality.conf && echo \"weak password policy: conf file uses defaults\""
      },
      "metrictype": "bool",
      "name": "password is too weak",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://manpages.ubuntu.com/manpages/oracular/en/man3/pwquality.3.html"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://manpages.ubuntu.com/manpages/oracular/en/man3/pwquality.3.html"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Configure Password Policy Requirements"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "One or more business rules are not respected. Please check the command output for more details.",
          "title": "Business rule not respected"
        },
        {
          "locale": "FR",
          "summary": "Une ou plusieurs règles métier ne sont pas respectées. Veuillez vérifier la sortie de la commande pour plus de détails.",
          "title": "Règle métier non respectée"
        }
      ],
      "dimension": "applications",
      "implementation": {
        "class": "internal",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 3,
        "system": "Linux",
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
        "minversion": 3,
        "system": "Linux",
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
        "minversion": 3,
        "system": "Linux",
        "target": ""
      },
      "scope": "generic",
      "severity": 1,
      "tags": []
    }
  ],
  "name": "threat model Linux",
  "signature": "060f74f017d0b6caef1ae4f72b9c2773e6f82a9171c0abdb1898ccb5ac4e6fa9"
}"#;
