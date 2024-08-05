// Built in default threat model
pub static THREAT_METRICS_LINUX: &str = r#"{
  "name": "threat model Linux",
  "extends": "none",
  "date": "August 05th 2024",
  "signature": "b5d1933465a4a4bb8a17695401f12d7a8209fa138857f5c8450840c229b813c4",
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
        "minversion": 5,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "helper_check",
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
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "installer",
        "elevation": "user",
        "target": "https://github.com/edamametechnologies/edamame_helper/releases/download",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "apt remove edamame_helper",
        "education": []
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
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sentinelctl version 2>/dev/null | grep -q 'Agent version' || echo epp_disabled",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://help.ubuntu.com/community/Antivirus"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://doc.ubuntu-fr.org/antivirus"
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://help.ubuntu.com/community/Antivirus"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://doc.ubuntu-fr.org/antivirus"
          }
        ]
      }
    },
    {
      "name": "encrypted private folder disabled",
      "metrictype": "bool",
      "dimension": "system services",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,ubuntu_security/home_encryption_enforce",
        "ISO 27001/2,Information Security Incident Management",
        "PCI-DSS,Requirement-3.4",
        "SOC 2,CC-Data Protection"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Private directory disabled",
          "summary": "Your home folder private encrypted directory is not enabled. Enabling home folder encryption helps protect your personal data from unauthorized access."
        },
        {
          "locale": "FR",
          "title": "Dossier privé désactivé",
          "summary": "Le dossier privé de votre dossier personnel n'est pas crypté. Activer le cryptage du dossier personnel aide à protéger vos données personnelles contre tout accès non autorisé."
        }
      ],
      "implementation": {
        "system": "Ubuntu",
        "minversion": 20,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "ecryptfs-setup-private 2>&1 | grep -q 'wrapped-passphrase file already exists' || echo encryption_inactive",
        "education": []
      },
      "remediation": {
        "system": "Ubuntu",
        "minversion": 20,
        "maxversion": 0,
        "class": "link",
        "elevation": "",
        "target": "https://help.ubuntu.com/community/EncryptedHome",
        "education": []
      },
      "rollback": {
        "system": "Ubuntu",
        "minversion": 20,
        "maxversion": 0,
        "class": "link",
        "elevation": "",
        "target": "https://help.ubuntu.com/community/EncryptedHome",
        "education": []
      }
    },
    {
      "name": "encrypted disk disabled",
      "metrictype": "bool",
      "dimension": "system services",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,ubuntu_security/disk_encryption_enforce",
        "ISO 27001/2,Information Security Incident Management",
        "PCI-DSS,Requirement-3.4",
        "SOC 2,CC-Data Protection"
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
          "summary": "Votre disque principal et votre swap ne sont pas crypté. Activer le cryptage du disque aide à protéger vos données contre tout accès non autorisé."
        }
      ],
      "implementation": {
        "system": "Ubuntu",
        "minversion": 20,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo apt install virt-what -y > /dev/null 2>&1 && output=$(sudo virt-what) && [ -z \"$output\" ] && { lsblk -o MOUNTPOINT,FSTYPE | grep \"/ \" | grep -q 'crypt' || echo encryption_disabled; lsblk -o MOUNTPOINT,FSTYPE | grep '/swap' | grep -q 'crypt' || echo encryption_disabled; }",
        "education": []
      },
      "remediation": {
        "system": "Ubuntu",
        "minversion": 20,
        "maxversion": 0,
        "class": "link",
        "elevation": "",
        "target": "https://help.ubuntu.com/community/FullDiskEncryptionHowto",
        "education": []
      },
      "rollback": {
        "system": "Ubuntu",
        "minversion": 20,
        "maxversion": 0,
        "class": "link",
        "elevation": "",
        "target": "https://help.ubuntu.com/community/FullDiskEncryptionHowto",
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
        "minversion": 5,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "pwned -i 365",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
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
        "minversion": 5,
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
        "ISO 27001/2,Information Security Incident Management",
        "PCI-DSS,Requirement-12.10",
        "SOC 2,CC-Incident Response",
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
        "minversion": 5,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "lanscan",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
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
        "minversion": 5,
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
        "CIS Benchmark Level 1,File Permissions",
        "ISO 27001/2,Communications Security",
        "PCI-DSS,Requirement-1",
        "SOC 2,CC-System Operations"
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
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "stat /etc/passwd | grep '(0644/-rw-r--r--)' | grep -v grep > /dev/null || echo bad_permissions",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo chmod 644 /etc/passwd",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 5,
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
        "CIS Benchmark Level 1,File Permissions",
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-7",
        "SOC 2,CC-System Operations"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "File permissions /etc/shadow",
          "summary": "The /etc/shadow file in Unix and Linux systems stores encrypted password data for each user and has stricter permissions than /etc/passwd. This is because /etc/shadow contains sensitive data.\nThe recommended permissions for the /etc/shadow file are 600:\n6 (read and write) for the owner, who should be the root or superuser. This allows the system to modify the file when passwords are changed.\n0 for the group and others. This means no permissions are given to the group or others, meaning they cannot read, write, or execute the file."
        },
        {
          "locale": "FR",
          "title": "Permissions du fichier /etc/shadow",
          "summary": "Le fichier `/etc/shadow` dans les systèmes Unix et Linux stocke les données de mot de passe cryptées pour chaque utilisateur et a des permissions plus strictes que `/etc/passwd`. Cela est dû au fait que `/etc/shadow` contient des données sensibles.\nLes permissions recommandées pour le fichier `/etc/shadow` sont `600` :\n- `6` (lecture et écriture) pour le propriétaire, qui devrait être l'utilisateur root ou superutilisateur. Cela permet au système de modifier le fichier lorsque les mots de passe sont changés.\n- `0` pour le groupe et les autres. Cela signifie qu'aucune permission n'est donnée au groupe ou aux autres, ce qui signifie qu'ils ne peuvent pas lire, écrire ou exécuter le fichier."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "stat /etc/shadow | grep '(0600/-rw-------)' | grep -v grep > /dev/null || echo bad_permissions",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo chmod 600 /etc/shadow",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 5,
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
      "tags": [
        "CIS Benchmark Level 1,Filesystem Configuration",
        "ISO 27001/2,System Acquisition, Development and Maintenance",
        "PCI-DSS,Requirement-2",
        "SOC 2,CC-Configuration Management"
      ],
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
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "stat /etc/fstab | grep '(0644/-rw-r--r--)' | grep -v grep > /dev/null || echo bad_permissions",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo chmod 644 /etc/fstab",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 5,
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
        "CIS Benchmark Level 1,User and Group Settings",
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-7",
        "SOC 2,CC-Access Control"
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
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "stat /etc/group | grep '(0644/-rw-r--r--)' | grep -v grep > /dev/null || echo bad_permissions",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo chmod 644 /etc/group",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 5,
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
        "CIS Benchmark Level 1,File Ownership and Permissions",
        "ISO 27001/2,Information Security Policies",
        "PCI-DSS,Requirement-2",
        "SOC 2,CC-System Operations"
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
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "ls -l /etc/group | grep 'root root' | grep -v grep > /dev/null || echo bad_group",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo chown root:root /etc/group",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 5,
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
        "CIS Benchmark Level 1,File Ownership and Permissions",
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-7",
        "SOC 2,CC-System Operations"
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
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "ls -l /etc/shadow | grep 'root shadow' | grep -v grep > /dev/null || echo bad_group",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo chown root:shadow /etc/shadow",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 5,
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
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "apt list --upgradeable 2>/dev/null | grep 'upgradable'",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "sudo apt update && sudo apt upgrade -y",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 5,
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
        "CIS Benchmark Level 1,Firewall Configuration",
        "ISO 27001/2,Network Security",
        "PCI-DSS,Requirement-1",
        "SOC 2,CC-Network Security"
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
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo ufw status | grep -q 'Status: active' || echo firewall_disabled",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo apt install ufw -y > /dev/null 2>&1 && sudo ufw enable",
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
        "minversion": 5,
        "maxversion": 0,
        "class": "",
        "elevation": "admin",
        "target": "sudo ufw disable",
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
        "CIS Benchmark Level 1,linux_security/sysprefs_ssh_disable",
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
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "systemctl is-active ssh | grep -q 'inactive' || echo remote_login_enabled",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo systemctl stop ssh && sudo systemctl disable ssh",
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
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo systemctl enable ssh && sudo systemctl start ssh",
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
        "CIS Benchmark Level 1,linux_security/sysprefs_remote_management_disable",
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
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "systemctl is-active xrdp 2>/dev/null | grep -q 'inactive' || echo rdp_enabled",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo systemctl stop xrdp && sudo systemctl disable xrdp",
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
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo apt install xrdp -y > /dev/null 2>&1 && sudo systemctl start xrdp && sudo systemctl enable xrdp",
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
        "CIS Benchmark Level 1,linux_security/sysprefs_smbd_disable",
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
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "systemctl is-active nfs-kernel-server 2>/dev/null | grep -q 'inactive' || echo nfs_enabled;  systemctl is-active smbd 2>/dev/null | grep -q 'inactive' || echo smb_enabled",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo systemctl stop smbd && sudo systemctl disable smbd; sudo systemctl stop nfs-kernel-server && sudo systemctl disable nfs-kernel-server",
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
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sudo apt install samba -y > /dev/null 2>&1 && sudo systemctl start smbd && sudo systemctl enable smbd; sudo apt install nfs-kernel-server -y > /dev/null 2>&1 && sudo systemctl start nfs-kernel-server && sudo systemctl enable nfs-kernel-server",
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
        "CIS Benchmark Level 1,linux_security/sysprefs_screensaver_password_enable",
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-8",
        "SOC 2,CC-Logical Access"
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
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "gsettings get org.gnome.desktop.screensaver lock-enabled",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
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
        "minversion": 5,
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
        "CIS Benchmark Level 1,linux_security/secure_boot_enable",
        "ISO 27001/2,System and Information Integrity",
        "PCI-DSS,Requirement-10",
        "SOC 2,CC-System Operations"
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
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "mokutil --sb-state | grep 'SecureBoot enabled' || echo secure_boot_disabled",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://wiki.debian.org/SecureBoot"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://wiki.debian.org/SecureBoot"
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "link",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://wiki.debian.org/SecureBoot"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://wiki.debian.org/SecureBoot"
          }
        ]
      }
    },
    {
      "name": "password policy is too weak",
      "metrictype": "bool",
      "dimension": "credentials",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,linux_security/password_policy",
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-8",
        "SOC 2,CC-Access Control"
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
        "minversion": 5,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "[ -f /etc/security/pwquality.conf ] && grep -E 'minlen|dcredit|ucredit|ocredit|lcredit' /etc/security/pwquality.conf || echo weak_password_policy",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://manpages.ubuntu.com/manpages/oracular/en/man3/pwquality.3.html"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://manpages.ubuntu.com/manpages/oracular/en/man3/pwquality.3.html"
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 5,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://manpages.ubuntu.com/manpages/oracular/en/man3/pwquality.3.html"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://manpages.ubuntu.com/manpages/oracular/en/man3/pwquality.3.html"
          }
        ]
      }
    }
  ]
}"#;
