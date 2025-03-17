// Built in default threat model
pub static THREAT_METRICS_LINUX: &str = r#"{
  "name": "threat model Linux",
  "extends": "none",
  "date": "March 16th 2025",
  "signature": "7288001f1d8355d7be1f79f459530794d35400c22ddedb6972fd13907fd849fa",
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
          "summary": "EDAMAME's Helper software is not running or requires an update. It's required for complete Security Score analysis and remediation."
        },
        {
          "locale": "FR",
          "title": "EDAMAME Helper inactif",
          "summary": "Le logiciel d'assistance d'EDAMAME n'est pas en cours d'exécution ou a besoin d'être mis à jour. Il est requis pour une analyse complète du score de sécurité."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "helper_check",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "installer",
        "elevation": "user",
        "target": "https://github.com/edamametechnologies/edamame_helper/releases/download",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://github.com/edamametechnologies/edamame_helper"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://github.com/edamametechnologies/edamame_helper"
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "apt remove edamame-helper",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "If you need to uninstall the EDAMAME Helper software for any reason, you can use the provided shell script command. Note that uninstalling may affect the Security Score analysis of your system."
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "Si vous devez désinstaller le logiciel d'assistance EDAMAME pour une raison quelconque, vous pouvez utiliser la commande de script shell fournie. Notez que la désinstallation peut affecter l'analyse du score de sécurité de votre système."
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
        "ISO 27001/2,A.12.2.1-Malware Controls",
        "SOC 2,CC6.8-Malware Protection"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "No antivirus enabled",
          "summary": "You don't have any antivirus enabled (Sentinel One...). We recommend you to enable one."
        },
        {
          "locale": "FR",
          "title": "Pas d'antivirus activé",
          "summary": "Vous n'avez pas d'antivirus activé (Sentinel One...). Nous vous recommandons d'en activer un."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "LANG=C sentinelctl version 2>/dev/null | grep -q 'Agent version' || pgrep -f FortiEDRAvScanner >/dev/null 2>&1 || echo epp_disabled",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://help.ubuntu.com/community/Antivirus"
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "FR",
            "class": "link",
            "target": "https://fr.wikipedia.org/wiki/Antivirus"
          }
        ]
      }
    },
    {
      "name": "no password manager",
      "metrictype": "bool",
      "dimension": "credentials",
      "severity": 4,
      "scope": "generic",
      "tags": [],
      "description": [
        {
          "locale": "EN",
          "title": "No password manager installed",
          "summary": "You don't have any password manager installed. It's recommended to install one."
        },
        {
          "locale": "FR",
          "title": "Pas de gestionnaire de mots de passe installé",
          "summary": "Vous n'avez pas de gestionnaire de mots de passe installé. Nous vous recommandons d'en installer un."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "(command -v pass || command -v keepassxc || command -v bw || command -v lpass || command -v gopass || command -v 1password) >/dev/null 2>&1 || echo \"No password manager installed\"",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://en.wikipedia.org/wiki/Password_manager"
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "FR",
            "class": "link",
            "target": "https://fr.wikipedia.org/wiki/Gestionnaire_de_mots_de_passe"
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
        "CIS Benchmark Level 2,Configure Disk Encryption",
        "ISO 27001/2,A.8.3.1-Media Protection",
        "SOC 2,CC6.7-Data Protection"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Disk encryption disabled",
          "summary": "Your main disk and swap are not encrypted. Enabling disk encryption helps protect your data from unauthorized access."
        },
        {
          "locale": "FR",
          "title": "Cryptage du disque désactivé",
          "summary": "Votre disque principal et votre swap ne sont pas cryptés. Activer le cryptage du disque aide à protéger vos données contre tout accès non autorisé."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "apt update -qq > /dev/null 2>&1 || true && apt install virt-what -y > /dev/null 2>&1 && [ -z \"$(virt-what)\" ] && { root_dev=$(findmnt -n -o SOURCE /); swap_dev=$(swapon --show=NAME --noheadings 2>/dev/null | head -n1); root_parent=$(lsblk -n -o NAME,TYPE,MOUNTPOINT -p | grep \" $(readlink -f \"$root_dev\")$\" | cut -d\" \" -f1); lsblk -n -o NAME,TYPE -p | grep -q \"^$root_parent.*crypt$\" || echo \"root_encryption_disabled\"; if [ -n \"$swap_dev\" ]; then swap_parent=$(lsblk -n -o NAME,TYPE,MOUNTPOINT -p | grep \" $(readlink -f \"$swap_dev\")$\" | cut -d\" \" -f1); lsblk -n -o NAME,TYPE -p | grep -q \"^$swap_parent.*crypt$\" || echo \"swap_encryption_disabled\"; fi; }",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://help.ubuntu.com/community/FullDiskEncryptionHowto"
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://help.ubuntu.com/community/FullDiskEncryptionHowto"
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
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "pwned -i 365",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
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
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://haveibeenpwned.com/"
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
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "lanscan",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
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
        "system": "Linux",
        "minversion": 3,
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
      "name": "passwd permissions",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Verify Password File Permissions"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "File permissions /etc/passwd",
          "summary": "The /etc/passwd file in Unix and Linux systems contains user account information. The recommended permissions for this file are 644. This means:\nThe owner (usually root) has read and write permissions (6).\nThe group and other users have read-only permissions (4).\nThis setup ensures that only the superuser can modify the file, preserving system security. Meanwhile, other users and processes can still read the information they need from the file. This balance of functionality and security is why 644 permissions are considered good practice for the /etc/passwd file."
        },
        {
          "locale": "FR",
          "title": "Permissions du fichier /etc/passwd",
          "summary": "Le fichier `/etc/passwd` dans les systèmes Unix et Linux contient des informations sur les comptes utilisateurs. Les permissions recommandées pour ce fichier sont `644`. Cela signifie que :\n- Le propriétaire (généralement `root`) a les permissions de lecture et d'écriture (6).\n- Le groupe et les autres utilisateurs ont les permissions de lecture seule (4).\nCette configuration garantit que seul le superutilisateur peut modifier le fichier, préservant ainsi la sécurité du système. Pendant ce temps, les autres utilisateurs et processus peuvent toujours lire les informations dont ils ont besoin à partir du fichier. Cet équilibre entre fonctionnalité et sécurité est la raison pour laquelle les permissions `644` sont considérées comme une bonne pratique pour le fichier `/etc/passwd`."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "stat /etc/passwd | grep -q '(0644/-rw-r--r--)' || echo bad_permissions",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "chmod 644 /etc/passwd",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": []
      }
    },
    {
      "name": "shadow permissions",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Verify Shadow File Permissions"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "File permissions /etc/shadow",
          "summary": "The /etc/shadow file in Unix and Linux systems stores encrypted password data for each user and has stricter permissions than /etc/passwd. This is because /etc/shadow contains sensitive data.\nThe recommended permissions for the /etc/shadow file are 640:\n6 (read and write) for the owner, who should be the root or superuser. This allows the system to modify the file when passwords are changed.\n0 for the group and others. This means no permissions are given to the group or others, meaning they cannot read, write, or execute the file."
        },
        {
          "locale": "FR",
          "title": "Permissions du fichier /etc/shadow",
          "summary": "Le fichier `/etc/shadow` dans les systèmes Unix et Linux stocke les données de mot de passe cryptées pour chaque utilisateur et a des permissions plus strictes que `/etc/passwd`. Cela est dû au fait que `/etc/shadow` contient des données sensibles.\nLes permissions recommandées pour le fichier `/etc/shadow` sont `640` :\n- `6` (lecture et écriture) pour le propriétaire, qui devrait être l'utilisateur root ou superutilisateur. Cela permet au système de modifier le fichier lorsque les mots de passe sont changés.\n- `0` pour le groupe et les autres. Cela signifie qu'aucune permission n'est donnée au groupe ou aux autres, ce qui signifie qu'ils ne peuvent pas lire, écrire ou exécuter le fichier."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "stat /etc/shadow | grep -q '(0640/-rw-r-----)' || echo bad_permissions",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "chmod 640 /etc/shadow",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": []
      }
    },
    {
      "name": "fstab permissions",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "generic",
      "tags": [],
      "description": [
        {
          "locale": "EN",
          "title": "File permissions /etc/fstab",
          "summary": "The `/etc/fstab` file in Unix and Linux systems provides a table of filesystems that should be mounted automatically at system startup. This file contains important information like what filesystems to mount, where to mount them, and what options to use.\nGiven its significance, the recommended permissions for the `/etc/fstab` file are `644`:\n- `6` (read and write) for the owner, which should be the root or superuser. This allows the system to modify the file when filesystems are added or removed.\n- `4` (read-only) for the group and others. This allows users and processes to read the file and understand the system's filesystems, but prevents them from making potentially harmful changes.\nThis setup ensures only the root user can modify the file, protecting the system's filesystem configuration. Meanwhile, it allows other users and processes to read the file, providing necessary access to filesystem information."
        },
        {
          "locale": "FR",
          "title": "Permissions du fichier /etc/fstab",
          "summary": "Le fichier `/etc/fstab` dans les systèmes Unix et Linux fournit une table des systèmes de fichiers qui doivent être montés automatiquement au démarrage du système. Ce fichier contient des informations importantes telles que les systèmes de fichiers à monter, où les monter et quelles options utiliser.\nCompte tenu de son importance, les permissions recommandées pour le fichier `/etc/fstab` sont `644` :\n- `6` (lecture et écriture) pour le propriétaire, qui devrait être l'utilisateur root ou superutilisateur. Cela permet au système de modifier le fichier lorsque des systèmes de fichiers sont ajoutés ou supprimés.\n- `4` (lecture seule) pour le groupe et les autres. Cela permet aux utilisateurs et aux processus de lire le fichier et de comprendre les systèmes de fichiers du système, mais les empêche d'apporter des modifications potentiellement nuisibles.\nCette configuration garantit que seul l'utilisateur root peut modifier le fichier, protégeant ainsi la configuration du système de fichiers du système. En même temps, elle permet aux autres utilisateurs et processus de lire le fichier, fournissant l'accès nécessaire aux informations sur le système de fichiers."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "stat /etc/fstab | grep -q '(0644/-rw-r--r--)' || echo bad_permissions",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "chmod 644 /etc/fstab",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": []
      }
    },
    {
      "name": "group permissions",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Verify Group File Permissions"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "File permissions /etc/group",
          "summary": "The `/etc/group` file in Unix and Linux systems stores group information or data. It contains a list of all the groups on the system, along with each group's associated users.\nGiven its importance, the recommended permissions for the `/etc/group` file are `644`:\n- `6` (read and write) for the owner, which should be the root or superuser. This allows the system to add or remove groups or modify group membership.\n- `4` (read-only) for the group and others. This allows users and processes to read the file and understand the system's group memberships, but prevents them from making unauthorized changes.\nThis setup ensures only the root user can modify the file, protecting the system's group configuration. Meanwhile, it allows other users and processes to read the file, providing necessary access to group information."
        },
        {
          "locale": "FR",
          "title": "Permissions du fichier /etc/group",
          "summary": "Le fichier `/etc/group` dans les systèmes Unix et Linux stocke les informations ou les données des groupes. Il contient une liste de tous les groupes sur le système, ainsi que les utilisateurs associés à chaque groupe.\nCompte tenu de son importance, les permissions recommandées pour le fichier `/etc/group` sont `644` :\n- `6` (lecture et écriture) pour le propriétaire, qui devrait être l'utilisateur root ou superutilisateur. Cela permet au système d'ajouter ou de supprimer des groupes ou de modifier l'appartenance à un groupe.\n- `4` (lecture seule) pour le groupe et les autres. Cela permet aux utilisateurs et aux processus de lire le fichier et de comprendre l'appartenance aux groupes du système, mais les empêche de faire des modifications non autorisées.\nCette configuration garantit que seul l'utilisateur root peut modifier le fichier, protégeant ainsi la configuration des groupes du système. En même temps, elle permet aux autres utilisateurs et processus de lire le fichier, fournissant l'accès nécessaire aux informations sur les groupes."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "stat /etc/group | grep -q '(0644/-rw-r--r--)' || echo bad_permissions",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "chmod 644 /etc/group",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": []
      }
    },
    {
      "name": "group group",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Verify Group File Ownership"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Group Ownership of /etc/group",
          "summary": "The `/etc/group` file should be owned by the root group to maintain the integrity and confidentiality of group information stored within. Incorrect group ownership could lead to unauthorized access or modification of this sensitive file, compromising system security."
        },
        {
          "locale": "FR",
          "title": "Appartenance au groupe de /etc/group",
          "summary": "Le fichier `/etc/group` doit être possédé par le groupe root pour maintenir l'intégrité et la confidentialité des informations du groupe stockées à l'intérieur. Une appartenance au groupe incorrecte pourrait conduire à un accès ou une modification non autorisés de ce fichier sensible, compromettant la sécurité du système."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "ls -l /etc/group | grep -q 'root root' || echo bad_group",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "chown root:root /etc/group",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": []
      }
    },
    {
      "name": "shadow group",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Verify Shadow File Group Ownership"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Group Ownership of /etc/shadow",
          "summary": "The `/etc/shadow` file should be owned by the root group or a specific security or system group. This file contains sensitive user information such as encrypted passwords. Incorrect group ownership could lead to unauthorized access or potential manipulation of this critical file, compromising system security and user confidentiality."
        },
        {
          "locale": "FR",
          "title": "Appartenance au groupe de /etc/shadow",
          "summary": "Le fichier `/etc/shadow` doit être possédé par le groupe root ou un groupe spécifique de sécurité ou système. Ce fichier contient des informations sensibles sur l'utilisateur, telles que des mots de passe cryptés. Une appartenance au groupe incorrecte pourrait conduire à un accès non autorisé ou une manipulation potentielle de ce fichier critique, compromettant la sécurité du système et la confidentialité de l'utilisateur."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "ls -l /etc/shadow | grep -q 'root shadow' || echo bad_group",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "chown root:shadow /etc/shadow",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": []
      }
    },
    {
      "name": "latest os",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 2,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Ensure package manager repositories are configured"
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
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "LANG=C apt update -qq > /dev/null 2>&1 || true && apt list --upgradeable 2>/dev/null | grep -q 'upgradable' && echo os_outdated",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "apt update -qq > /dev/null 2>&1 || true && apt upgrade -y",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": []
      }
    },
    {
      "name": "local firewall disabled",
      "metrictype": "bool",
      "dimension": "network",
      "severity": 3,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Ensure UFW is installed"
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
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "LANG=C ufw status | grep -qi 'Status: active' || echo firewall_disabled",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "apt update -qq > /dev/null 2>&1 || true && apt install ufw -y > /dev/null 2>&1 && ufw enable",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://help.ubuntu.com/community/UFW"
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "admin",
        "target": "ufw disable",
        "education": []
      }
    },
    {
      "name": "remote login enabled",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Ensure SSH Server is configured with appropriate ciphers"
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
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "LANG=C systemctl is-active ssh | grep -q 'inactive' || echo remote_login_enabled",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "systemctl stop ssh && systemctl disable ssh",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "Disabling remote login secures your Linux system by preventing unauthorized remote access. This command requires superuser permissions to execute and ensures that your system is only accessible by authorized users locally."
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "Désactiver l'accès à distance sécurise votre système Linux en empêchant l'accès à distance non autorisé. Cette commande nécessite des permissions de super utilisateur pour s'exécuter et garantit que votre système est uniquement accessible localement par les utilisateurs autorisés."
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "systemctl enable ssh && systemctl start ssh",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "Enabling remote login on Linux allows remote users to access the system via SSH, which can be useful for remote administration but increases the risk of unauthorized access. Use this feature cautiously and ensure your firewall and user access permissions are properly configured."
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "L'activation de l'accès à distance sur Linux permet aux utilisateurs distants d'accéder au système via SSH, ce qui peut être utile pour l'administration à distance mais augmente le risque d'accès non autorisé. Utilisez cette fonction avec prudence et assurez-vous que votre pare-feu et les permissions d'accès utilisateur sont correctement configurés."
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
        "CIS Benchmark Level 1,Ensure remote administration tools are not installed"
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
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "LANG=C systemctl is-active xrdp 2>/dev/null | grep -q 'inactive' || echo rdp_enabled",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "systemctl stop xrdp && systemctl disable xrdp",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "Disabling remote desktop access can significantly enhance the security of your Linux system. This prevents unauthorized remote desktop access, ensuring only approved users can control the system remotely."
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "Désactiver l'accès au bureau à distance peut considérablement renforcer la sécurité de votre système Linux. Cela empêche l'accès à distance non autorisé au bureau, garantissant que seuls les utilisateurs approuvés peuvent contrôler le système à distance."
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "apt update -qq > /dev/null 2>&1 || true && apt install xrdp -y > /dev/null 2>&1 && systemctl start xrdp && systemctl enable xrdp",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "Re-enabling remote desktop services on Linux enables remote management capabilities. It's crucial to ensure that only trusted users have access and that your network is secure to mitigate potential security risks."
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "Réactiver les services de bureau à distance sur Linux active les capacités de gestion à distance. Il est crucial de s'assurer que seuls les utilisateurs de confiance ont accès et que votre réseau est sécurisé pour atténuer les risques de sécurité potentiels."
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
        "CIS Benchmark Level 1,Ensure NFS and RPC are not enabled"
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
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "LANG=C systemctl is-active nfs-kernel-server 2>/dev/null | grep -q 'inactive' || echo nfs_enabled; LANG=C systemctl is-active smbd 2>/dev/null | grep -q 'inactive' || echo smb_enabled",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "systemctl stop smbd && systemctl disable smbd; systemctl stop nfs-kernel-server && systemctl disable nfs-kernel-server",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "Disabling file sharing on your Linux system can significantly enhance your data security. This action ensures that your files are not inadvertently accessible to unauthorized users over the network."
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "Désactiver le partage de fichiers sur votre système Linux peut considérablement améliorer la sécurité de vos données. Cette action garantit que vos fichiers ne sont pas accessibles par inadvertance à des utilisateurs non autorisés sur le réseau."
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "apt update -qq > /dev/null 2>&1 || true && apt install samba -y > /dev/null 2>&1 && systemctl start smbd && systemctl enable smbd && apt install nfs-kernel-server -y > /dev/null 2>&1 && systemctl start nfs-kernel-server && systemctl enable nfs-kernel-server",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "If you re-enable file sharing services can allow for file sharing capabilities, make sure that appropriate security measures and user permissions are in place to protect sensitive data."
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "Si vous éactivez les services de partage de fichiers, assurez-vous que des mesures de sécurité appropriées et des permissions utilisateur sont en place pour protéger les données sensibles."
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
        "CIS Benchmark Level 1,Lock inactive user accounts",
        "ISO 27001/2,A.11.2.8-Unattended User Equipment",
        "SOC 2,CC6.1-Logical Access"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Screen saver requires password disabled",
          "summary": "When the screen saver is active, we recommend that a password is required to exit it. Otherwise anyone could access your computer while you are away."
        },
        {
          "locale": "FR",
          "title": "Économiseur d'écran nécessite un mot de passe désactivé",
          "summary": "Lorsque l'économiseur d'écran est actif, nous recommandons qu'un mot de passe soit requis pour en sortir. Sinon, n'importe qui pourrait accéder à votre ordinateur pendant votre absence."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "LANG=C gsettings get org.gnome.desktop.screensaver lock-enabled | grep -q 'true' || echo screensaver_lock_disabled",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "gsettings set org.gnome.desktop.screensaver lock-enabled true",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "Enabling screen locking on your Linux system ensures that a password is required to exit the screensaver, protecting your system from unauthorized access when unattended."
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "L'activation du verrouillage de l'écran sur votre système Linux garantit qu'un mot de passe est requis pour quitter l'économiseur d'écran, protégeant votre système contre les accès non autorisés en votre absence."
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "gsettings set org.gnome.desktop.screensaver lock-enabled false",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "Disabling screen locking reduces the security of your system by allowing anyone to access it when the screensaver is active."
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "Désactiver le verrouillage de l'écran réduit la sécurité de votre système en permettant à quiconque d'y accéder lorsque l'économiseur d'écran est actif."
          }
        ]
      }
    },
    {
      "name": "secure boot disabled",
      "metrictype": "bool",
      "dimension": "system services",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 2,Ensure Secure Boot is enabled"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Secure boot disabled",
          "summary": "Secure Boot is a security standard developed to ensure that a device boots using only software that is trusted by the Original Equipment Manufacturer (OEM). Enabling Secure Boot helps protect against bootloader attacks."
        },
        {
          "locale": "FR",
          "title": "Secure Boot désactivé",
          "summary": "Le Secure Boot est une norme de sécurité développée pour garantir qu'un appareil démarre uniquement avec des logiciels de confiance par le fabricant d'équipements d'origine (OEM). Activer Secure Boot aide à protéger contre les attaques de démarrage."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "LANG=C mokutil --sb-state | grep -q 'SecureBoot enabled' || echo secure_boot_disabled",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://wiki.debian.org/SecureBoot"
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://wiki.debian.org/SecureBoot"
          }
        ]
      }
    },
    {
      "name": "password is too weak",
      "metrictype": "bool",
      "dimension": "credentials",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Configure Password Policy Requirements"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Weak password policy",
          "summary": "Enforcing a strong password policy is essential to protect against unauthorized access. Ensure that the system has a robust password policy implemented."
        },
        {
          "locale": "FR",
          "title": "Politique de mot de passe faible",
          "summary": "L'application d'une politique de mot de passe robuste est essentielle pour se protéger contre les accès non autorisés. Assurez-vous que le système dispose d'une politique de mot de passe solide."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "[ ! -f /etc/security/pwquality.conf ] && echo 'weak password_policy: pwquality is not in use' || ! grep -qvE '^\\s*#|^\\s*$' /etc/security/pwquality.conf && echo 'weak password policy: conf file uses defaults'",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://manpages.ubuntu.com/manpages/oracular/en/man3/pwquality.3.html"
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://manpages.ubuntu.com/manpages/oracular/en/man3/pwquality.3.html"
          }
        ]
      }
    },
    {
      "name": "Business rule not respected",
      "metrictype": "bool",
      "dimension": "applications",
      "severity": 1,
      "scope": "generic",
      "tags": [],
      "description": [
        {
          "locale": "EN",
          "title": "Business rule not respected",
          "summary": "One or more business rules are not respected. Please check the command output for more details."
        },
        {
          "locale": "FR",
          "title": "Règle métier non respectée",
          "summary": "Une ou plusieurs règles métier ne sont pas respectées. Veuillez vérifier la sortie de la commande pour plus de détails."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "business_rules",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "Refer to the business rules documentation for more details."
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "Consultez la documentation des règles métier pour plus de détails."
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 3,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "Refer to the business rules documentation for more details."
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "Consultez la documentation des règles métier pour plus de détails."
          }
        ]
      }
    }
  ]
}"#;
