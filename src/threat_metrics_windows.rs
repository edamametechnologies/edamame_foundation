// Built in default threat model
pub static THREAT_METRICS_WINDOWS: &str = r#"{
  "name": "threat model Windows",
  "extends": "none",
  "date": "April 10th 2024",
  "signature": "ac0cbf0c62e868aa776c35cfc7646cfe1448ae44bed474ae218f6427b1eb43a2",
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
        "system": "Windows",
        "minversion": 12,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "helper_check",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 12,
        "maxversion": 0,
        "class": "installer",
        "elevation": "user",
        "target": "https://github.com/edamametechnologies/edamame_helper/releases/download",
        "education": []
      },
      "rollback": {
        "system": "Windows",
        "minversion": 12,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=xORy1bFBKCI"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=cOmJt_U8WMs"
          }
        ]
      }
    },
    {
      "name": "Cached logon credentials enabled",
      "metrictype": "bool",
      "dimension": "credentials",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "ISO 27001/2,Access Control",
        "PCI-DSS,Requirement-8.2.3",
        "SOC 2,CC-Logical Access Controls"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Cached logon credentials enabled",
          "summary": "Cached logon credentials are a security risk as they can be used by attackers to gain access to your system. They are stored on your system and can be retrieved by attackers who gain access to your computer or network. We recommend disabling cached logon credentials to increase the security of your system."
        },
        {
          "locale": "FR",
          "title": "Activation de la mise en cache des identifiants de connexion",
          "summary": "Les identifiants de connexion mis en cache représentent un risque pour la sécurité car ils peuvent être utilisés par des pirates pour accéder à votre système. Ils sont stockés sur votre système et peuvent être récupérés par des pirates qui accèdent à votre ordinateur ou à votre réseau. Nous vous recommandons de désactiver les identifiants de connexion mis en cache afin de renforcer la sécurité de votre système."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "if(((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI' -Name 'DisablePasswordCaching' -ErrorAction SilentlyContinue).DisablePasswordCaching) -ne 1) { 'Password caching is not disabled' } else { '' }",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling cached logon credentials enhances the security of your Windows system by preventing attackers from utilizing cached information to gain unauthorized access. Use the provided CLI command to modify the registry setting, effectively disabling password caching. This action requires administrative privileges.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver les identifiants de connexion mis en cache améliore la sécurité de votre système Windows en empêchant les attaquants d'utiliser des informations mises en cache pour accéder sans autorisation. Utilisez la commande CLI fournie pour modifier le paramètre du registre, désactivant ainsi efficacement la mise en cache des mots de passe. Cette action nécessite des privilèges administratifs.</p>"
          }
        ]
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI /v DisablePasswordCaching /t REG_DWORD /d 1 /f",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Re-enabling cached logon credentials allows for the storage of credentials on the system for future logons. While this may improve convenience, it can also increase security risks. If you need to enable it for specific scenarios, use the provided CLI command with caution and ensure your system's physical security.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Réactiver les identifiants de connexion mis en cache permet de stocker des identifiants sur le système pour les connexions futures. Bien que cela puisse améliorer la commodité, cela peut également augmenter les risques de sécurité. Si vous devez l'activer pour des scénarios spécifiques, utilisez la commande CLI fournie avec prudence et assurez-vous de la sécurité physique de votre système.</p>"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI /v DisablePasswordCaching /t REG_DWORD /d 0 /f",
        "education": []
      }
    },
    {
      "name": "no EPP",
      "metrictype": "bool",
      "dimension": "applications",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Security Configuration Benchmarks",
        "ISO 27001/2,Malware Protection",
        "PCI-DSS,Requirement-5",
        "SOC 2,CC-Malware Protection"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "No antivirus enabled",
          "summary": "You don't have any antivirus installed (Windows Defender, Sentinel One...). We recommend you to enable one."
        },
        {
          "locale": "FR",
          "title": "Pas d'antivirus activé",
          "summary": "Vous n'avez pas d'antivirus installé (Windows Defender, Sentinel One...). Nous vous recommandons d'en activer un."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "Function Get-AVStatus { [cmdletbinding()] Param() Process { $AV = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntivirusProduct'; $enabledAVs = $AV | Where-Object { $productState = '0x{0:x}' -f $_.ProductState; $enabled = $productState.Substring(3, 2) -match '10|11'; return $enabled }; if (-not $enabledAVs) { Write-Output 'no epp' } } }; Get-AVStatus",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://support.microsoft.com/en-us/windows/stay-protected-with-windows-security-2ae0363d-0ada-c064-8b56-6a39afb6a963"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://support.microsoft.com/fr-fr/windows/rester-prot%C3%A9g%C3%A9-avec-s%C3%A9curit%C3%A9-windows-2ae0363d-0ada-c064-8b56-6a39afb6a963"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://support.microsoft.com/en-us/windows/stay-protected-with-windows-security-2ae0363d-0ada-c064-8b56-6a39afb6a963"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://support.microsoft.com/fr-fr/windows/rester-prot%C3%A9g%C3%A9-avec-s%C3%A9curit%C3%A9-windows-2ae0363d-0ada-c064-8b56-6a39afb6a963"
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
        "CIS Benchmark Level 1,windows_security/bitlocker_enforce",
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
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "admin",
        "target": "manage-bde -status | findstr 'Protection Off'",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=PtMyu9xrJ_E"
          },
          {
            "locale": "FR",
            "class": "youtube",
            "target": "https://www.youtube.com/watch?v=RqWzTzUVYaM"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://www.youtube.com/watch?v=lY0Iz0NpAoU"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://www.youtube.com/watch?v=Cj4UUMxm6D8"
          }
        ]
      }
    },
    {
      "name": "UAC disabled",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 2,Section: 1.1.1",
        "ISO 27001/2,Control: A.9.4.4",
        "PCI-DSS,Requirement-7.1",
        "SOC 2,CC-User Access"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "User Account Control disabled",
          "summary": "User Account Control (UAC) is a security feature in Windows that helps prevent unauthorized changes to your computer. If UAC is disabled, it's easier for malware to make changes to your system without your knowledge. You should enable UAC to protect your system from such attacks."
        },
        {
          "locale": "FR",
          "title": "Contrôle de compte d'utilisateur désactivé",
          "summary": "Le Contrôle de compte d'utilisateur (UAC) est une fonctionnalité de sécurité dans Windows qui aide à prévenir les modifications non autorisées sur votre ordinateur. Si UAC est désactivé, il est plus facile pour les logiciels malveillants de faire des changements sur votre système sans votre connaissance. Vous devez activer UAC pour protéger votre système contre de telles attaques."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "if((Get-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue).EnableLUA -eq 0) { 'UAC disabled' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1 -Type DWord",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Enabling User Account Control (UAC) is crucial for security. It prompts for authorization on actions that could affect your system's operation or change settings that require administrative privileges. To enable UAC, use the command <code>Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1 -Type DWord</code>. This ensures that any attempt to make changes to your system is authorized by you, significantly reducing the risk of malware infections.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Activer le Contrôle de compte d'utilisateur (UAC) est crucial pour la sécurité. Il demande une autorisation pour les actions qui pourraient affecter le fonctionnement de votre système ou modifier les paramètres nécessitant des privilèges administratifs. Pour activer l'UAC, utilisez la commande <code>Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1 -Type DWord</code>. Cela garantit que toute tentative de modification de votre système est autorisée par vous, réduisant considérablement le risque d'infections par des logiciels malveillants.</p>"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 0 -Type DWord",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>While it's generally not recommended, there might be specific scenarios where you need to disable UAC, such as for troubleshooting or running certain applications that are not compatible with UAC. If you must disable it, use the command <code>Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 0 -Type DWord</code>, but be aware of the increased security risk. Always ensure to re-enable UAC as soon as possible.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Bien que cela ne soit généralement pas recommandé, il pourrait y avoir des scénarios spécifiques nécessitant la désactivation de l'UAC, comme pour le dépannage ou l'exécution de certaines applications non compatibles avec l'UAC. Si vous devez le désactiver, utilisez la commande <code>Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 0 -Type DWord</code>, mais soyez conscient du risque de sécurité accru. Assurez-vous toujours de réactiver l'UAC dès que possible.</p>"
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
        "CIS Benchmark Level 2,Section: 2.3.1.1",
        "ISO 27001/2,Control: A.9.3.1",
        "PCI-DSS,Requirement-8.1.5",
        "SOC 2,CC-User Authentication"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Automatic logon enabled",
          "summary": "Automatic logon allows the system to automatically log on a user after booting up. This can be a security risk if the system is not physically secured as anyone can access the system without providing any credentials. It is recommended to disable automatic logon."
        },
        {
          "locale": "FR",
          "title": "Connexion automatique activée",
          "summary": "La connexion automatique permet au système de connecter automatiquement un utilisateur après le démarrage. Cela peut être un risque pour la sécurité si le système n'est pas physiquement sécurisé car n'importe qui peut accéder au système sans fournir de credentials. Il est recommandé de désactiver la connexion automatique."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "if((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue).AutoAdminLogon -eq '1') { 'Automatic logon enabled' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 0",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling automatic login is crucial for enhancing the security of your Windows system. When automatic login is enabled, anyone with physical access to the computer can gain access without needing to enter a username or password. To disable this feature, use the command <code>Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 0</code>. This action requires you to enter your credentials upon startup, thereby providing an additional layer of security.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver la connexion automatique est crucial pour renforcer la sécurité de votre système Windows. Lorsque la connexion automatique est activée, toute personne ayant accès physique à l'ordinateur peut y accéder sans avoir besoin de saisir un nom d'utilisateur ou un mot de passe. Pour désactiver cette fonctionnalité, utilisez la commande <code>Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 0</code>. Cette action nécessite que vous saisissiez vos identifiants au démarrage, fournissant ainsi une couche supplémentaire de sécurité.</p>"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 1",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Re-enabling automatic login should be done with caution and only in environments where physical security is guaranteed. This feature can be convenient for systems that do not require strict security measures and are in secure locations. To re-enable automatic login, use the command <code>Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 1</code>. Remember, this lowers the security of your system by allowing access without credentials.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Réactiver la connexion automatique doit être fait avec prudence et uniquement dans des environnements où la sécurité physique est garantie. Cette fonctionnalité peut être pratique pour les systèmes qui n'exigent pas de mesures de sécurité strictes et qui se trouvent dans des lieux sécurisés. Pour réactiver la connexion automatique, utilisez la commande <code>Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 1</code>. Rappelez-vous, cela diminue la sécurité de votre système en permettant l'accès sans identifiants.</p>"
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
        "system": "Windows",
        "minversion": 12,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "pwned -i 365",
        "education": []
      },
      "remediation": {
        "system": "Windows",
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
        "system": "Windows",
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
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "internal",
        "elevation": "user",
        "target": "lanscan",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
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
        "system": "Windows",
        "minversion": 10,
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
      "name": "Windows Script Host enabled",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Section: 9.1.2",
        "ISO 27001/2,Control: A.12.2.1",
        "PCI-DSS,Requirement-2.2.2",
        "SOC 2,CC-Malicious Code Prevention"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Windows Script Host enabled",
          "summary": "Windows Script Host is a built-in Windows scripting environment that allows running of VBScript, JScript, and other scripting languages. Disabling it can help mitigate some types of malware attacks."
        },
        {
          "locale": "FR",
          "title": "Windows Script Host activé",
          "summary": "Windows Script Host est un environnement de script Windows intégré qui permet l'exécution de VBScript, JScript et d'autres langages de script. Le désactiver peut aider à atténuer certains types d'attaques de logiciels malveillants."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "if((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings' -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 1) { 'Windows Script Host enabled' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "reg add HKLM\\SOFTWARE\\Microsoft\\'Windows Script Host'\\Settings /v Enabled /t REG_DWORD /d 0 /f",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling Windows Script Host (WSH) is a preventative measure against certain types of malware attacks that utilize scripting languages like VBScript or JScript. To disable WSH, execute the command <code>reg add HKLM\\SOFTWARE\\Microsoft\\'Windows Script Host'\\Settings /v Enabled /t REG_DWORD /d 0 /f</code>. This action prevents scripts from running, thereby enhancing your system's security against script-based threats.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver Windows Script Host (WSH) est une mesure préventive contre certains types d'attaques de logiciels malveillants qui utilisent des langages de script comme VBScript ou JScript. Pour désactiver WSH, exécutez la commande <code>reg add HKLM\\SOFTWARE\\Microsoft\\'Windows Script Host'\\Settings /v Enabled /t REG_DWORD /d 0 /f</code>. Cette action empêche l'exécution de scripts, renforçant ainsi la sécurité de votre système contre les menaces basées sur des scripts.</p>"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "reg add HKLM\\SOFTWARE\\Microsoft\\'Windows Script Host'\\Settings /v Enabled /t REG_DWORD /d 1 /f",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Enabling Windows Script Host (WSH) should be considered carefully, especially if specific scripts are necessary for your operations. To re-enable WSH, use the command <code>reg add HKLM\\SOFTWARE\\Microsoft\\'Windows Script Host'\\Settings /v Enabled /t REG_DWORD /d 1 /f</code>. Be mindful of the scripts you execute to maintain system security.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>L'activation de Windows Script Host (WSH) doit être considérée avec soin, notamment si des scripts spécifiques sont nécessaires pour vos opérations. Pour réactiver WSH, utilisez la commande <code>reg add HKLM\\SOFTWARE\\Microsoft\\'Windows Script Host'\\Settings /v Enabled /t REG_DWORD /d 1 /f</code>. Soyez attentif aux scripts que vous exécutez pour maintenir la sécurité du système.</p>"
          }
        ]
      }
    },
    {
      "name": "remote desktop enabled",
      "metrictype": "bool",
      "dimension": "network",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Section: 8.1.1",
        "ISO 27001/2,Control: A.13.7.1",
        "PCI-DSS,Requirement-2.3",
        "SOC 2,CC-Network Security"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Remote Desktop Protocol (RDP) enabled",
          "summary": "RDP allows users to remotely access and control a Windows computer from another location. While this can be convenient, it also presents a significant security risk if left enabled and unprotected. An attacker could potentially gain access to your computer and compromise your sensitive data or even take control of your system."
        },
        {
          "locale": "FR",
          "title": "Protocole de Bureau à distance (RDP) activé",
          "summary": "RDP permet aux utilisateurs d'accéder à distance et de contrôler un ordinateur Windows à partir d'un autre emplacement. Bien que cela puisse être pratique, cela présente également un risque de sécurité important s'il est laissé activé et non protégé. Un attaquant pourrait potentiellement accéder à votre ordinateur et compromettre vos données sensibles ou même prendre le contrôle de votre système."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "if((Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0) { 'Terminal Services connections allowed' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling Remote Desktop Protocol (RDP) is crucial for securing your system against unauthorized remote access. To disable RDP and protect your computer, execute the command: <code>Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1</code>. This ensures that no remote connections can be established, significantly reducing the risk of cyber attacks.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver le Protocole de Bureau à distance (RDP) est crucial pour sécuriser votre système contre l'accès à distance non autorisé. Pour désactiver RDP et protéger votre ordinateur, exécutez la commande : <code>Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1</code>. Cela garantit qu'aucune connexion à distance ne peut être établie, réduisant considérablement le risque d'attaques cybernétiques.</p>"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>If you need to enable Remote Desktop Protocol (RDP) for specific purposes, ensure your system is secured with strong passwords and access is restricted to trusted users only. To re-enable RDP, use the command: <code>Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0</code>. Additionally, consider implementing network level authentication and firewall rules to safeguard your system.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Si vous devez activer le Protocole de Bureau à distance (RDP) pour des besoins spécifiques, assurez-vous que votre système est sécurisé avec des mots de passe forts et que l'accès est limité aux utilisateurs de confiance uniquement. Pour réactiver RDP, utilisez la commande : <code>Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0</code>. De plus, envisagez de mettre en œuvre une authentification au niveau du réseau et des règles de pare-feu pour protéger votre système.</p>"
          }
        ]
      }
    },
    {
      "name": "manual system updates",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Section: 2.3.1",
        "ISO 27001/2,Control: A.12.6.1",
        "PCI-DSS,Requirement-6.1",
        "SOC 2,CC-System Monitoring"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Windows Update disabled",
          "summary": "Disabling Windows Update prevents critical security patches and updates from being installed on your system, leaving your system vulnerable to known exploits and threats. It is highly recommended that you enable Windows Update to ensure your system is up to date with the latest security patches."
        },
        {
          "locale": "FR",
          "title": "Mise à jour Windows désactivée",
          "summary": "La désactivation de la mise à jour de Windows empêche l'installation des correctifs et des mises à jour de sécurité critiques sur votre système, laissant votre système vulnérable aux exploits et menaces connus. Il est fortement recommandé d'activer la mise à jour de Windows pour garantir que votre système est à jour avec les derniers correctifs de sécurité."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "if((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoUpdate -ErrorAction SilentlyContinue).NoAutoUpdate -ne 0) { 'NoAutoUpdate is set' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Enabling automatic updates is crucial for maintaining system security. To ensure your system automatically downloads and installs updates, execute the provided command. This action helps protect your computer against vulnerabilities by keeping it updated with the latest security patches.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Activer les mises à jour automatiques est crucial pour maintenir la sécurité du système. Pour que votre système télécharge et installe automatiquement les mises à jour, exécutez la commande fournie. Cette action aide à protéger votre ordinateur contre les vulnérabilités en le gardant à jour avec les derniers correctifs de sécurité.</p>"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>If you need to disable automatic updates, be aware that this may expose your system to security risks. Manual updates require regular monitoring to ensure your system's security. Use the provided command to switch back to manual updates, but consider the potential vulnerabilities and ensure to manually check for updates regularly.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Si vous devez désactiver les mises à jour automatiques, sachez que cela peut exposer votre système à des risques de sécurité. Les mises à jour manuelles nécessitent une surveillance régulière pour garantir la sécurité de votre système. Utilisez la commande fournie pour revenir aux mises à jour manuelles, mais prenez en compte les vulnérabilités potentielles et assurez-vous de vérifier manuellement les mises à jour régulièrement.</p>"
          }
        ]
      }
    },
    {
      "name": "guest account enabled",
      "metrictype": "bool",
      "dimension": "credentials",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Section: 1.1.2",
        "ISO 27001/2,Control: A.9.2.1",
        "PCI-DSS,Requirement-8.1.6",
        "SOC 2,CC-User Access"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Guest account enabled",
          "summary": "The Guest account is a default account in Windows, which allows users to access the system with limited privileges. It's recommended to disable this account to prevent unauthorized access to your system and data."
        },
        {
          "locale": "FR",
          "title": "Compte Invité activé",
          "summary": "Le compte Invité est un compte par défaut dans Windows, qui permet aux utilisateurs d'accéder au système avec des privilèges limités. Il est recommandé de désactiver ce compte pour empêcher tout accès non autorisé à votre système et à vos données."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "$guestName = (Get-WmiObject Win32_UserAccount | Where-Object {$_.SID -like '*-501'} | Select-Object -ExpandProperty Name); if(net user $guestName | findstr /c:'active' | findstr /c:'Yes') { 'Guest account active' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "$guestName = (Get-WmiObject Win32_UserAccount | Where-Object {$_.SID -like '*-501'} | Select-Object -ExpandProperty Name); Disable-LocalUser -Name $guestName",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling the Guest account is a critical step towards securing your Windows system. The Guest account, by default, has limited access but can still be a potential entry point for unauthorized access. Use the provided CLI command to disable this account and protect your system from unnecessary exposure.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver le compte Invité est une étape cruciale pour sécuriser votre système Windows. Le compte Invité, par défaut, a un accès limité mais peut encore être un point d'entrée potentiel pour un accès non autorisé. Utilisez la commande CLI fournie pour désactiver ce compte et protéger votre système d'une exposition inutile.</p>"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "$guestName = (Get-WmiObject Win32_UserAccount | Where-Object {$_.SID -like '*-501'} | Select-Object -ExpandProperty Name); Enable-LocalUser -Name $guestName",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>If there's a specific need to enable the Guest account, it should be done with caution. Ensure that the use of the Guest account is monitored and that its access is limited to only what is necessary. Use the provided CLI command to re-enable the Guest account as needed.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>S'il y a un besoin spécifique d'activer le compte Invité, cela devrait être fait avec prudence. Assurez-vous que l'utilisation du compte Invité est surveillée et que son accès est limité à ce qui est nécessaire. Utilisez la commande CLI fournie pour réactiver le compte Invité selon les besoins.</p>"
          }
        ]
      }
    },
    {
      "name": "root user enabled",
      "metrictype": "bool",
      "dimension": "credentials",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Section: 1.1.1",
        "ISO 27001/2,Control: A.9.4.2",
        "PCI-DSS,Requirement-2.3",
        "SOC 2,CC-User Access"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Built-in Administrator account enabled",
          "summary": "The Built-in Administrator account is a powerful account that has full access to the system. Having this account enabled is a security risk as it is a common target for attackers. It should be disabled unless it is absolutely necessary to enable it."
        },
        {
          "locale": "FR",
          "title": "Compte administrateur intégré activé",
          "summary": "Le compte administrateur intégré est un compte puissant qui a un accès complet au système. Avoir ce compte activé représente un risque de sécurité car c'est une cible courante pour les attaquants. Il devrait être désactivé sauf s'il est absolument nécessaire de l'activer."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "$adminName = (Get-WmiObject Win32_UserAccount | Where-Object {$_.SID -like '*-500'} | Select-Object -ExpandProperty Name); if(((net user $adminName) | findstr /C:'Account active') -match 'Yes') { Write-Output 'Built-in Administrator account enabled' } else { Write-Output '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "$adminName = (Get-WmiObject Win32_UserAccount | Where-Object {$_.SID -like '*-500'} | Select-Object -ExpandProperty Name); net user $adminName /active:no",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling the built-in Administrator account reduces the risk of unauthorized system changes and potential security breaches. This account has full system access and should be disabled in a normal user environment. Use the provided CLI command for disabling the Administrator account to enhance your system's security posture.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver le compte administrateur intégré réduit le risque de modifications non autorisées du système et de violations potentielles de la sécurité. Ce compte a un accès complet au système et devrait être désactivé dans un environnement utilisateur normal. Utilisez la commande CLI fournie pour désactiver le compte administrateur afin d'améliorer la posture de sécurité de votre système.</p>"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "$adminName = (Get-WmiObject Win32_UserAccount | Where-Object {$_.SID -like '*-500'} | Select-Object -ExpandProperty Name); net user $adminName /active:yes",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Re-enabling the built-in Administrator account should be done with specific operational requirements in mind. Ensure that its use is strictly controlled and monitored. Use the provided CLI command to re-enable the Administrator account when necessary, but always prioritize security and minimize its use to when absolutely needed.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Réactiver le compte administrateur intégré doit être fait en tenant compte de besoins opérationnels spécifiques. Assurez-vous que son utilisation est strictement contrôlée et surveillée. Utilisez la commande CLI fournie pour réactiver le compte administrateur lorsque nécessaire, mais toujours prioriser la sécurité et minimiser son utilisation à quand absolument nécessaire.</p>"
          }
        ]
      }
    },
    {
      "name": "local firewall disabled",
      "metrictype": "bool",
      "dimension": "network",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Section: 9.3.1",
        "ISO 27001/2,Control: A.13.1.1",
        "PCI-DSS,Requirement-1.4",
        "SOC 2,CC-Network Security"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Windows Firewall disabled",
          "summary": "Windows Firewall is a built-in feature of Windows that helps to protect your computer from unauthorized access. When it's disabled, your computer is vulnerable to attacks from the network. We recommend that you enable it."
        },
        {
          "locale": "FR",
          "title": "Pare-feu Windows désactivé",
          "summary": "Le pare-feu Windows est une fonctionnalité intégrée de Windows qui aide à protéger votre ordinateur contre les accès non autorisés. Lorsqu'il est désactivé, votre ordinateur est vulnérable aux attaques en provenance du réseau. Nous vous recommandons de l'activer."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "if((Get-NetFirewallProfile -All | Where-Object { $_.Enabled -eq 'False' })) { 'One or more firewall profiles are disabled' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Enabling Windows Firewall is crucial for defending your computer against unauthorized network access and potential cyber threats. The Windows Firewall provides a first line of defense by controlling incoming and outgoing network traffic based on security rules. By using the provided CLI command, you can ensure that your firewall is active and contributing to the overall security of your system.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Activer le pare-feu Windows est essentiel pour défendre votre ordinateur contre les accès réseau non autorisés et les menaces cybernétiques potentielles. Le pare-feu Windows offre une première ligne de défense en contrôlant le trafic réseau entrant et sortant en fonction des règles de sécurité. En utilisant la commande CLI fournie, vous pouvez vous assurer que votre pare-feu est actif et contribue à la sécurité globale de votre système.</p>"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling the Windows Firewall should be considered only under specific circumstances where it is necessary for certain applications or services to function correctly. However, this action increases your system's vulnerability to network-based attacks. Ensure alternative security measures are in place before proceeding with the provided CLI command to disable the firewall.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver le pare-feu Windows ne devrait être envisagé que dans des circonstances spécifiques où cela est nécessaire pour le bon fonctionnement de certaines applications ou services. Cependant, cette action augmente la vulnérabilité de votre système aux attaques basées sur le réseau. Assurez-vous que des mesures de sécurité alternatives sont en place avant de procéder avec la commande CLI fournie pour désactiver le pare-feu.</p>"
          }
        ]
      }
    },
    {
      "name": "Remote Registry Service enabled",
      "metrictype": "bool",
      "dimension": "system services",
      "severity": 3,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Section: 2.2.4",
        "ISO 27001/2,Control: A.9.4.1",
        "PCI-DSS,Requirement-2.2",
        "SOC 2,CC-System Configuration and Maintenance"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Remote Registry Service enabled",
          "summary": "The Remote Registry Service allows remote access to the Windows Registry. This can be a security risk if not properly secured."
        },
        {
          "locale": "FR",
          "title": "Service Registre Distant activé",
          "summary": "Le Service Registre Distant permet l'accès distant au Registre de Windows. Cela peut être un risque de sécurité si cela n'est pas correctement sécurisé."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "if((Get-Service -Name RemoteRegistry).Status -eq 'Running') { 'RemoteRegistry service is running' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "(sc.exe config RemoteRegistry start= disabled) -and (sc.exe stop RemoteRegistry)",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling the Remote Registry Service is recommended to reduce the attack surface of your Windows system. This service, if left enabled, can provide a potential pathway for attackers to modify registry settings remotely, leading to unauthorized changes or malicious activities. Secure your system by using the provided CLI command to disable this service.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Il est recommandé de désactiver le Service Registre Distant pour réduire la surface d'attaque de votre système Windows. Ce service, s'il reste activé, peut fournir un chemin potentiel pour que les attaquants modifient à distance les paramètres du registre, conduisant à des changements non autorisés ou à des activités malveillantes. Sécurisez votre système en utilisant la commande CLI fournie pour désactiver ce service.</p>"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "(sc.exe config RemoteRegistry start= auto) -and (sc.exe start RemoteRegistry)",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Re-enabling the Remote Registry Service should be done with caution and only if it is strictly necessary for your operational needs. Keep in mind that this can expose your system to additional risks. Ensure that appropriate security controls and monitoring are in place before using the provided CLI command to re-enable this service.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Réactiver le Service Registre Distant doit être fait avec prudence et seulement si cela est strictement nécessaire pour vos besoins opérationnels. Gardez à l'esprit que cela peut exposer votre système à des risques supplémentaires. Assurez-vous que des contrôles de sécurité appropriés et une surveillance sont en place avant d'utiliser la commande CLI fournie pour réactiver ce service.</p>"
          }
        ]
      }
    },
    {
      "name": "LM and NTLMv1 enabled",
      "metrictype": "bool",
      "dimension": "credentials",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Section: 2.3.11.9",
        "ISO 27001/2,Control: A.9.2.3",
        "PCI-DSS,Requirement-8.2.1",
        "SOC 2,CC-User Authentication"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "LM and NTLMv1 protocols enabled",
          "summary": "The LM and NTLMv1 protocols are outdated and insecure authentication protocols. They should be disabled to prevent potential security threats. Leaving these protocols enabled can allow attackers to potentially crack passwords and gain unauthorized access to sensitive information."
        },
        {
          "locale": "FR",
          "title": "Protocoles LM et NTLMv1 activés",
          "summary": "Les protocoles LM et NTLMv1 sont des protocoles d'authentification obsolètes et peu sûrs. Ils doivent être désactivés pour prévenir les menaces potentielles à la sécurité. Le fait de laisser ces protocoles activés peut permettre à des attaquants de déchiffrer des mots de passe et d'obtenir un accès non autorisé à des informations sensibles."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 0,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "if(((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA' -ErrorAction SilentlyContinue).LMCompatibilityLevel -lt 5) -or ((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinClientSec -lt 537395200) -or ((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinServerSec -lt 537395200)) { 'Weak NTLM settings' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 0,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA' -Name 'LMCompatibilityLevel' -Value '5' -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0' -Name 'NtlmMinClientSec' -Value '537395200' -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0' -Name 'NtlmMinServerSec' -Value '537395200' -Type DWord",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling LM and NTLMv1 protocols enhances security by preventing the use of these older, less secure authentication methods. Modern authentication protocols offer stronger encryption and better protection against attacks. Follow the provided CLI command to update your system's settings to use more secure authentication methods.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver les protocoles LM et NTLMv1 améliore la sécurité en empêchant l'utilisation de ces méthodes d'authentification plus anciennes et moins sécurisées. Les protocoles d'authentification modernes offrent un cryptage plus fort et une meilleure protection contre les attaques. Suivez la commande CLI fournie pour mettre à jour les paramètres de votre système afin d'utiliser des méthodes d'authentification plus sécurisées.</p>"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 0,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA' -Name 'LmCompatibilityLevel' -Value '1' -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0' -Name 'NtlmMinClientSec' -Value '262144' -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0' -Name 'NtlmMinServerSec' -Value '537395200' -Type DWord",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Re-enabling LM and NTLMv1 should be done with caution and only if there is a specific requirement for these older protocols due to legacy systems or applications. Be aware that enabling these protocols can expose your system to increased security risks. Ensure that you have strong mitigations and monitoring in place.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Réactiver LM et NTLMv1 doit être fait avec prudence et seulement s'il existe une exigence spécifique pour ces protocoles plus anciens en raison de systèmes ou d'applications hérités. Soyez conscient que l'activation de ces protocoles peut exposer votre système à des risques de sécurité accrus. Assurez-vous que vous avez en place de fortes atténuations et une surveillance.</p>"
          }
        ]
      }
    },
    {
      "name": "Lsass process protection",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Section: 2.2.39",
        "ISO 27001/2,Control: A.12.1.2",
        "PCI-DSS,Requirement-6.2",
        "SOC 2,CC-System Integrity"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Lsass.exe process protection not enabled",
          "summary": "Lsass.exe is a critical system process that handles user authentication. It contains sensitive information such as passwords and security tokens. If this process is compromised, it could lead to a security breach. Enabling Lsass.exe process protection helps prevent attacks against this process. This content will show you how to enable Lsass.exe process protection."
        },
        {
          "locale": "FR",
          "title": "Protection du processus Lsass.exe désactivée",
          "summary": "Lsass.exe est un processus système essentiel qui gère l'authentification de l'utilisateur. Il contient des informations sensibles telles que des mots de passe et des jetons de sécurité. Si ce processus est compromis, cela peut entraîner une violation de sécurité. L'activation de la protection du processus Lsass.exe aide à prévenir les attaques contre ce processus. Ce contenu vous montrera comment activer la protection du processus Lsass.exe."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "if((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL -eq 0) { 'RunAsPPL is a REG_DWORD with value 0' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Enabling Lsass process protection is crucial for securing the system against attacks targeting the Local Security Authority Subsystem Service (LSASS), which handles user logins and password changes. This setting ensures that the LSASS process runs with additional protections, making it harder for attackers to exploit vulnerabilities. Implement the provided CLI command to enhance the security of your system.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Activer la protection du processus Lsass est crucial pour sécuriser le système contre les attaques ciblant le Service de sous-système d'autorité de sécurité locale (LSASS), qui gère les connexions des utilisateurs et les changements de mot de passe. Ce paramètre garantit que le processus LSASS fonctionne avec des protections supplémentaires, rendant plus difficile pour les attaquants d'exploiter les vulnérabilités. Implémentez la commande CLI fournie pour renforcer la sécurité de votre système.</p>"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Disabling Lsass process protection should be carefully considered as it removes additional security layers from the LSASS process. If you must disable this protection due to compatibility issues or other specific requirements, ensure you understand the risks and have alternative security measures in place.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Désactiver la protection du processus Lsass doit être soigneusement considéré car cela supprime des couches de sécurité supplémentaires du processus LSASS. Si vous devez désactiver cette protection en raison de problèmes de compatibilité ou d'autres exigences spécifiques, assurez-vous de comprendre les risques et d'avoir des mesures de sécurité alternatives en place.</p>"
          }
        ]
      }
    },
    {
      "name": "PS execution policy unrestricted",
      "metrictype": "bool",
      "dimension": "system integrity",
      "severity": 4,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1,Section: 1.1.3",
        "ISO 27001/2,Control: A.12.4.2",
        "PCI-DSS,Requirement-2.2.4",
        "SOC 2,CC-System Hardening"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "PowerShell execution policy not securely configured",
          "summary": "PowerShell is a powerful command-line tool that is built into Windows, and is often used by attackers to carry out malicious activities. The execution policy determines which scripts are allowed to run on a Windows system. If the execution policy is set to Unrestricted, it could allow an attacker to run malicious scripts on your system."
        },
        {
          "locale": "FR",
          "title": "La stratégie d'exécution de PowerShell n'est pas sécurisée",
          "summary": "PowerShell est un outil en ligne de commande puissant intégré à Windows, souvent utilisé par des attaquants pour effectuer des activités malveillantes. La stratégie d'exécution détermine les scripts autorisés à s'exécuter sur un système Windows. Si la stratégie d'exécution est pas définie sur Unrestricted, cela pourrait permettre à un attaquant d'exécuter des scripts malveillants sur votre système."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "$currentUserPolicy= Get-ExecutionPolicy -Scope CurrentUser; if($currentUserPolicy -eq 'Unrestricted') { 'Execution Policy is unrestricted' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ExecutionPolicy -ExecutionPolicy Default -Scope CurrentUser",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Setting PowerShell's execution policy to Default helps prevent the execution of malicious scripts by requiring that all scripts and configuration files downloaded from the Internet are signed by a trusted publisher. This setting is a balance between security and functionality, allowing locally created scripts to run while protecting against untrusted scripts. Apply the provided CLI command to adjust your PowerShell execution policy.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Définir la politique d'exécution de PowerShell sur Default aide à prévenir l'exécution de scripts malveillants en exigeant que tous les scripts et fichiers de configuration téléchargés depuis Internet soient signés par un éditeur de confiance. Ce paramètre est un équilibre entre sécurité et fonctionnalité, permettant l'exécution de scripts créés localement tout en protégeant contre les scripts non fiables. Appliquez la commande CLI fournie pour ajuster votre politique d'exécution PowerShell.</p>"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Reverting PowerShell's execution policy to Unrestricted removes the requirement for scripts to be signed, significantly increasing the risk of executing malicious scripts. Only proceed with this action if there is a compelling need and you have adequate security measures to mitigate potential risks. Be sure to apply strict controls and monitoring to detect and respond to malicious activities.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Revenir à la politique d'exécution de PowerShell sur Non restreint supprime l'exigence pour les scripts d'être signés, augmentant considérablement le risque d'exécuter des scripts malveillants. Ne procédez à cette action que s'il y a un besoin impérieux et que vous disposez de mesures de sécurité adéquates pour atténuer les risques potentiels. Assurez-vous d'appliquer des contrôles stricts et une surveillance pour détecter et répondre aux activités malveillantes.</p>"
          }
        ]
      }
    },
    {
      "name": "Chrome not uptodate",
      "metrictype": "bool",
      "dimension": "applications",
      "severity": 3,
      "scope": "generic",
      "tags": [
        "ISO 27001/2,Application Security",
        "PCI-DSS,Requirement-6",
        "SOC 2,CC-System Operations"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "Chrome browser not up to date",
          "summary": "Your Google Chrome browser is not up to date. Running the latest version ensures you have the latest security features and performance improvements."
        },
        {
          "locale": "FR",
          "title": "Navigateur Chrome non à jour",
          "summary": "Votre navigateur Google Chrome n'est pas à jour. Exécuter la dernière version garantit que vous disposez des dernières fonctionnalités de sécurité et des améliorations de performance."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "$path = 'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome'; if (Test-Path $path) { $local_version = (Get-ItemProperty -Path $path).DisplayVersion; $web_content = Invoke-WebRequest -UseBasicParsing 'https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1'; $latest_version = ($web_content.Content | ConvertFrom-Json)[0].version; if ([version]$latest_version -le [version]$local_version) { Write-Output '' } else { Write-Output \"Chrome is not up to date (Installed: $local_version, Latest: $latest_version)\"; } } else { Write-Output '' }\n",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://support.google.com/chrome/answer/95414?hl=en"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://support.google.com/chrome/answer/95414?hl=fr"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "",
        "elevation": "",
        "target": "",
        "education": [
          {
            "locale": "EN",
            "class": "link",
            "target": "https://support.google.com/chrome/a/answer/6350036?hl=en"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://support.google.com/chrome/a/answer/6350036?hl=fr"
          }
        ]
      }
    },
    {
      "name": "SMBv1 enabled",
      "metrictype": "bool",
      "dimension": "network",
      "severity": 5,
      "scope": "generic",
      "tags": [
        "CIS Benchmark Level 1",
        "windows_security/smb1_protocol_disabled",
        "need_restart"
      ],
      "description": [
        {
          "locale": "EN",
          "title": "SMBv1 Protocol Enabled",
          "summary": "The SMBv1 protocol is enabled on your system. This protocol is outdated and has known vulnerabilities that can allow attackers to take over your system. It should be disabled to improve your system's security."
        },
        {
          "locale": "FR",
          "title": "Protocole SMBv1 activé",
          "summary": "Le protocole SMBv1 est activé sur votre système. Ce protocole est obsolète et présente des vulnérabilités connues qui peuvent permettre aux attaquants de prendre le contrôle de votre système. Il devrait être désactivé pour améliorer la sécurité de votre système."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "if((Get-SmbServerConfiguration).EnableSMB1Protocol -eq $true) { 'SMBv1 enabled' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -norestart",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Following the automatic changes, a system restart is required to activate the remediation.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Après les modifications automatiques, un redémarrage du système est requis pour activer la remédiation.</p>"
          }
        ]
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -norestart",
        "education": [
          {
            "locale": "EN",
            "class": "html",
            "target": "<p>Following the automatic changes, a system restart is required to activate the rollback.</p>"
          },
          {
            "locale": "FR",
            "class": "html",
            "target": "<p>Après les modifications automatiques, un redémarrage du système est requis pour activer le retour en arrière.</p>"
          }
        ]
      }
    }
  ]
}"#;
