// Built in default threat model
pub static THREAT_METRICS_WINDOWS: &str = r#"{
  "name": "threat model Windows",
  "extends": "none",
  "date": "November 10th 2023",
  "signature": "fe5817d78e4c3049d679fa65776f19aaac0936ebd4a67eaffbc0053836f5db8a",
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
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI /v DisablePasswordCaching /t REG_DWORD /d 1 /f",
        "education": []
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
        "target": "if (-not (SentinelCtl.exe version 2>&1 | Select-String -Pattern \"Agent version\") -and ((Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring) -eq $true)) { Write-Output \"noepp\" }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-MpPreference -DisableRealtimeMonitoring $false",
        "education": []
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-MpPreference -DisableRealtimeMonitoring $true",
        "education": []
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
        "education": []
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 0 -Type DWord",
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
        "education": []
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 1",
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
          "summary": "Your email address has recently appeared in a data breach, please review the breach and change your passwords accordingly."
        },
        {
          "locale": "FR",
          "title": "Adresse e-mail compromise",
          "summary": "Votre adresse e-mail est apparue récemment dans une fuite de données, veuillez examiner la fuite et modifier vos mots de passe en conséquence."
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
            "class": "link",
            "target": "https://haveibeenpwned.com/"
          },
          {
            "locale": "FR",
            "class": "link",
            "target": "https://haveibeenpwned.com/"
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
        "education": []
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "reg add HKLM\\SOFTWARE\\Microsoft\\'Windows Script Host'\\Settings /v Enabled /t REG_DWORD /d 1 /f",
        "education": []
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
        "education": []
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0",
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
        "education": []
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f",
        "education": []
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
        "target": "if(net user guest | findstr /c:'active' | findstr /c:'Yes') { 'Guest account active' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Disable-LocalUser -Name Guest",
        "education": []
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Enable-LocalUser -Name Guest",
        "education": []
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
        "target": "if((net user Administrator | findstr /C:'Account active') -match 'Yes') { 'Administrator account is active' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "net user Administrator /active:no",
        "education": []
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "net user Administrator /active:yes",
        "education": []
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
        "education": []
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False",
        "education": []
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
          "title": "Service Registre distant activé",
          "summary": "Le Service Registre distant permet l'accès distant au Registre de Windows. Cela peut être un risque de sécurité si cela n'est pas correctement sécurisé."
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
        "education": []
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "(sc.exe config RemoteRegistry start= auto) -and (sc.exe start RemoteRegistry)",
        "education": []
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
        "education": []
      },
      "rollback": {
        "system": "Windows",
        "minversion": 0,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA' -Name 'LmCompatibilityLevel' -Value '1' -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0' -Name 'NtlmMinClientSec' -Value '262144' -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0' -Name 'NtlmMinServerSec' -Value '537395200' -Type DWord",
        "education": []
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
        "education": []
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f",
        "education": []
      }
    },
    {
      "name": "ps not RemoteSigned",
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
          "title": "PowerShell execution policy not set to RemoteSigned",
          "summary": "PowerShell is a powerful command-line tool that is built into Windows, and is often used by attackers to carry out malicious activities. The execution policy determines which scripts are allowed to run on a Windows system. If the execution policy is not set to RemoteSigned, it could allow an attacker to run malicious scripts on your system."
        },
        {
          "locale": "FR",
          "title": "La stratégie d'exécution de PowerShell n'est pas définie sur RemoteSigned",
          "summary": "PowerShell est un outil en ligne de commande puissant intégré à Windows, souvent utilisé par des attaquants pour effectuer des activités malveillantes. La stratégie d'exécution détermine les scripts autorisés à s'exécuter sur un système Windows. Si la stratégie d'exécution n'est pas définie sur RemoteSigned, cela pourrait permettre à un attaquant d'exécuter des scripts malveillants sur votre système."
        }
      ],
      "implementation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "user",
        "target": "if((Get-ExecutionPolicy) -ne 'RemoteSigned') { 'Execution Policy not RemoteSigned' } else { '' }",
        "education": []
      },
      "remediation": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force",
        "education": []
      },
      "rollback": {
        "system": "Windows",
        "minversion": 10,
        "maxversion": 0,
        "class": "cli",
        "elevation": "system",
        "target": "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force",
        "education": []
      }
    }
  ]
}"#;
