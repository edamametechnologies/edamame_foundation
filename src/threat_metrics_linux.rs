// Built in default threat model
pub static THREAT_METRICS_LINUX: &str = r#"{
  "name": "threat model Linux",
  "extends": "none",
  "date": "December 13th 2023",
  "signature": "940ca101ecce327bb30e70f77289b072fd73608e9c0bf0c7e75ae4961e828dbc",
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
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "helper_check",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "installer",
        "elevation": "user",
        "target": "https://github.com/edamametechnologies/edamame_helper/releases/download",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "",
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
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "sentinelctl version 2>/dev/null | grep -q \"Agent version\" || echo noepp",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 6,
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
        "minversion": 6,
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
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "pwned -i 365",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 6,
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
        "system": "Linux",
        "minversion": 6,
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
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "lanscan",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 6,
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
        "system": "Linux",
        "minversion": 6,
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
      "name": "/etc/passwd permissions",
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
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "stat /etc/passwd | grep '(0644/-rw-r--r--)' | grep -v grep > /dev/null || echo bad_permissions",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "chmod 664 /etc/passwd",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": []
      }
    },
    {
      "name": "/etc/shadow permissions",
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
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "stat /etc/shadow | grep '(0600/-rw-------)' | grep -v grep > /dev/null || echo bad_permissions",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "chmod 600 /etc/shadow",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": []
      }
    },
    {
      "name": "/etc/fstab permissions",
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
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "stat /etc/fstab | grep '(0644/-rw-r--r--)' | grep -v grep > /dev/null || echo bad_permissions",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "chmod 644 /etc/fstab",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": []
      }
    },
    {
      "name": "/etc/group permissions",
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
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "stat /etc/group | grep '(0644/-rw-r--r--)' | grep -v grep > /dev/null || echo bad_permissions",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "chmod 644 /etc/group",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": []
      }
    },
    {
      "name": "/etc/group group",
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
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "ls -l /etc/group | grep 'root root' | grep -v grep > /dev/null || echo bad_group",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "chown root /etc/group",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": []
      }
    },
    {
      "name": "/etc/shadow group",
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
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "ls -l /etc/shadow | grep 'root root' | grep -v grep > /dev/null || echo bad_group",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "chown root /etc/shadow",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": []
      }
    },
    {
      "name": "restrict cron to root",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Job Scheduling",
        "ISO 27001/2,Operations Security",
        "PCI-DSS,Requirement-6",
        "SOC 2,CC-System Operations"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Cron is not restricted to root only",
          "summary": "Cron is a time-based job scheduler in Unix-like operating systems. Users can schedule jobs (commands or scripts) to run periodically at fixed times, dates, or intervals. It's a powerful tool, but can also pose security risks if not managed properly. Restricting cron jobs to the root user is generally considered good practice."
        },
        {
          "locale": "FR",
          "title": "Cron n'est pas restreint à l'utilisateur root",
          "summary": "Cron est un planificateur de tâches basé sur le temps dans les systèmes d'exploitation de type Unix. Les utilisateurs peuvent programmer des tâches (commandes ou scripts) pour qu'elles s'exécutent périodiquement à des heures, des dates ou des intervalles fixes. C'est un outil puissant, mais qui peut également poser des risques de sécurité s'il n'est pas géré correctement. Restreindre les tâches cron à l'utilisateur root est généralement considéré comme une bonne pratique."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "cd /etc ; [ -f cron.deny ] && echo bad_config ; grep -v root cron.allow",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "cd /etc ; [ -f cron.deny ] && mv cron.deny cron.deny.edamame_save ; [ -f cron.allow ] && mv cron.allow cron.allow.edamame_save ; echo root > cron.allow ; chown root cron.allow ; chmod 400 cron.allow",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": []
      }
    },
    {
      "name": "manual system updates",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,System Patching",
        "ISO 27001/2,Information Systems Maintenance",
        "PCI-DSS,Requirement-6",
        "SOC 2,CC-System Operations"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Missing system updates",
          "summary": "Keeping a Linux system (or any operating system) up-to-date is crucial for several reasons, particularly when it comes to security: developers regularly find and fix security vulnerabilities in software. These fixes, known as patches, are distributed via updates. By regularly updating your system, you ensure these patches are applied promptly, reducing the chance of a successful attack."
        },
        {
          "locale": "FR",
          "title": "Système non à jour",
          "summary": "Garder un système Linux (ou tout autre système d'exploitation) à jour est crucial pour plusieurs raisons, en particulier en ce qui concerne la sécurité : les développeurs trouvent et corrigent régulièrement des vulnérabilités de sécurité dans les logiciels. Ces correctifs, appelés patches, sont distribués via des mises à jour. En mettant régulièrement à jour votre système, vous assurez l'application rapide de ces patches, réduisant ainsi les chances d'une attaque réussie."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "checkupdates; [ $? -eq 0 ] && echo updates_required",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "pacman -Syu --noconfirm",
        "education": []
      },
      "rollback": {
        "system": "Linux",
        "minversion": 6,
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
          "title": "Uncomplicated firewall (ufw) not installed",
          "summary": "A firewall is a crucial part of any network security framework. Firewalls control the incoming and outgoing network traffic based on predetermined security rules. They establish a barrier between trusted internal networks and untrusted external networks. It can also block unauthorized access to or from private networks, preventing intruders from accessing sensitive information. Uncomplicated firewall provides a command line interface and aims to be uncomplicated and easy to use."
        },
        {
          "locale": "FR",
          "title": "Uncomplicated firewall (ufw) non installé",
          "summary": "Un pare-feu est un élément crucial de tout cadre de sécurité réseau. Les pare-feu contrôlent le trafic réseau entrant et sortant en fonction de règles de sécurité prédéterminées. Ils établissent une barrière entre les réseaux internes de confiance et les réseaux externes non fiables. Il peut également bloquer l'accès non autorisé vers ou depuis des réseaux privés, empêchant les intrus d'accéder à des informations sensibles. Uncomplicated firewall fournit une interface en ligne de commande et vise à être simple d'utilisation."
        }
      ],
      "implementation": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "pacman -Qi ufw > /dev/null || echo not_found",
        "education": []
      },
      "remediation": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "pacman -S ufw; ufw enable; ufw default deny; ufw allow from 192.168.0.0/24; ufw allow Deluge; ufw limit ssh",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://wiki.archlinux.org/title/Uncomplicated_Firewall"
          }
        ]
      },
      "rollback": {
        "system": "Linux",
        "minversion": 6,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "pacman -R ufw",
        "education": []
      }
    }
  ]
}"#;
