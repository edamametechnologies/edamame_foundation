// Built in default threat model
pub static THREAT_METRICS_WINDOWS: &str = r#"{
  "date": "April 11th 2025",
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
        "minversion": 10,
        "system": "Windows",
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
        "minversion": 10,
        "system": "Windows",
        "target": "https://github.com/edamametechnologies/edamame_helper/releases/download"
      },
      "rollback": {
        "class": "",
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
        "elevation": "",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
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
          "summary": "Cached logon credentials are a security risk as they can be used by attackers to gain access to your system. They are stored on your system and can be retrieved by attackers who gain access to your computer or network. We recommend disabling cached logon credentials to increase the security of your system.",
          "title": "Cached logon credentials enabled"
        },
        {
          "locale": "FR",
          "summary": "Les identifiants de connexion mis en cache représentent un risque pour la sécurité car ils peuvent être utilisés par des pirates pour accéder à votre système. Ils sont stockés sur votre système et peuvent être récupérés par des pirates qui accèdent à votre ordinateur ou à votre réseau. Nous vous recommandons de désactiver les identifiants de connexion mis en cache afin de renforcer la sécurité de votre système.",
          "title": "Activation de la mise en cache des identifiants de connexion"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling cached logon credentials enhances the security of your Windows system by preventing attackers from utilizing cached information to gain unauthorized access. Use the provided CLI command to modify the registry setting, effectively disabling password caching. This action requires administrative privileges."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver les identifiants de connexion mis en cache améliore la sécurité de votre système Windows en empêchant les attaquants d'utiliser des informations mises en cache pour accéder sans autorisation. Utilisez la commande CLI fournie pour modifier le paramètre du registre, désactivant ainsi efficacement la mise en cache des mots de passe. Cette action nécessite des privilèges administratifs."
          }
        ],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "if(((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI' -Name 'DisablePasswordCaching' -ErrorAction SilentlyContinue).DisablePasswordCaching) -ne 1) { 'Password caching is not disabled' } else { '' }"
      },
      "metrictype": "bool",
      "name": "Cached logon credentials enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Re-enabling cached logon credentials allows for the storage of credentials on the system for future logons. While this may improve convenience, it can also increase security risks. If you need to enable it for specific scenarios, use the provided CLI command with caution and ensure your system's physical security."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Réactiver les identifiants de connexion mis en cache permet de stocker des identifiants sur le système pour les connexions futures. Bien que cela puisse améliorer la commodité, cela peut également augmenter les risques de sécurité. Si vous devez l'activer pour des scénarios spécifiques, utilisez la commande CLI fournie avec prudence et assurez-vous de la sécurité physique de votre système."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI /v DisablePasswordCaching /t REG_DWORD /d 1 /f"
      },
      "rollback": {
        "class": "cli",
        "education": [],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI /v DisablePasswordCaching /t REG_DWORD /d 0 /f"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Interactive logon: Number of previous logons to cache"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "You don't have any antivirus installed (Windows Defender, Sentinel One...). We recommend you to enable one.",
          "title": "No antivirus enabled"
        },
        {
          "locale": "FR",
          "summary": "Vous n'avez pas d'antivirus installé (Windows Defender, Sentinel One...). Nous vous recommandons d'en activer un.",
          "title": "Pas d'antivirus activé"
        }
      ],
      "dimension": "applications",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "Function Get-AVStatus { [cmdletbinding()] Param() Process { $AV = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntivirusProduct'; $enabledAVs = $AV | Where-Object { $productState = '0x{0:x}' -f $_.ProductState; $enabled = $productState.Substring(3, 2) -match '10|11'; return $enabled }; if (-not $enabledAVs) { Write-Output 'epp_disabled' } } }; Get-AVStatus"
      },
      "metrictype": "bool",
      "name": "no EPP",
      "remediation": {
        "class": "link",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "This remediation will direct you to the Windows Security settings where you can enable or install an antivirus program. Ensure you have a robust antivirus solution enabled to protect your system from malware and other threats. For more detailed instructions, visit the <a href='https://support.microsoft.com/en-us/windows/stay-protected-with-windows-security-2ae0363d-0ada-c064-8b56-6a39afb6a963'>support page</a>."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Cette remédiation vous dirigera vers les paramètres de Sécurité Windows où vous pourrez activer ou installer un programme antivirus. Assurez-vous d'avoir une solution antivirus robuste activée pour protéger votre système contre les logiciels malveillants et autres menaces. Pour des instructions plus détaillées, visitez la <a href='https://support.microsoft.com/fr-fr/windows/rester-prot%C3%A9g%C3%A9-avec-s%C3%A9curit%C3%A9-windows-2ae0363d-0ada-c064-8b56-6a39afb6a963'>page de support</a>."
          }
        ],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "ms-settings:windowsdefender"
      },
      "rollback": {
        "class": "link",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "If you need to revert the changes, go back to the Windows Security settings and adjust your antivirus settings accordingly. Ensure you understand the security implications of any changes you make. For more information, visit the <a href='https://support.microsoft.com/en-us/windows/stay-protected-with-windows-security-2ae0363d-0ada-c064-8b56-6a39afb6a963'>support page</a>."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Si vous devez annuler les modifications, retournez dans les paramètres de Sécurité Windows et ajustez les paramètres de votre antivirus en conséquence. Assurez-vous de comprendre les implications de sécurité des modifications apportées. Pour plus d'informations, visitez la <a href='https://support.microsoft.com/fr-fr/windows/rester-prot%C3%A9g%C3%A9-avec-s%C3%A9curit%C3%A9-windows-2ae0363d-0ada-c064-8b56-6a39afb6a963'>page de support</a>."
          }
        ],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "ms-settings:windowsdefender"
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 1,Configure Microsoft Defender Antivirus",
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
        "minversion": 10,
        "system": "Windows",
        "target": "$installed = @(Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match '1Password|LastPass|KeePass|Bitwarden|Dashlane' }).Count; if ($installed -eq 0) { Write-Output 'No password manager installed' }"
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
        "minversion": 10,
        "system": "Windows",
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
        "minversion": 10,
        "system": "Windows",
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
        "minversion": 10,
        "system": "Windows",
        "target": "if ((Get-WmiObject -Class Win32_ComputerSystem).Model -notmatch 'Virtual') { if ((Get-BitLockerVolume).ProtectionStatus -eq 'Off') { Write-Output 'File system not encrypted' } }"
      },
      "metrictype": "bool",
      "name": "encrypted disk disabled",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.microsoft.com/en-us/windows/turn-on-device-encryption-0c453637-bc88-7d95-5074-dc66c78d6d5b"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.microsoft.com/fr-fr/windows/activer-le-chiffrement-de-l-appareil-0c453637-bc88-7d95-5074-dc66c78d6d5b"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.microsoft.com/en-us/windows/turn-off-bitlocker-drive-encryption-0026063e-abe0-0e75-12dc-f6239c715f5d"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.microsoft.com/fr-fr/windows/d%C3%A9sactiver-bitlocker-c98bb8d0-0fe7-88d8-7436-c29e90abef0c"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": ""
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Configure BitLocker Drive Encryption",
        "ISO 27001/2,A.8.3.1-Media Protection",
        "SOC 2,CC6.7-Data Protection"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "User Account Control (UAC) is a security feature in Windows that helps prevent unauthorized changes to your computer. If UAC is disabled, it's easier for malware to make changes to your system without your knowledge. You should enable UAC to protect your system from such attacks.",
          "title": "User Account Control disabled"
        },
        {
          "locale": "FR",
          "summary": "Le Contrôle de compte d'utilisateur (UAC) est une fonctionnalité de sécurité dans Windows qui aide à prévenir les modifications non autorisées sur votre ordinateur. Si UAC est désactivé, il est plus facile pour les logiciels malveillants de faire des changements sur votre système sans votre connaissance. Vous devez activer UAC pour protéger votre système contre de telles attaques.",
          "title": "Contrôle de compte d'utilisateur désactivé"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "if((Get-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue).EnableLUA -eq 0) { 'UAC disabled' } else { '' }"
      },
      "metrictype": "bool",
      "name": "UAC disabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Enabling User Account Control (UAC) is crucial for security. It prompts for authorization on actions that could affect your system's operation or change settings that require administrative privileges. This ensures that any attempt to make changes to your system is authorized by you, significantly reducing the risk of malware infections."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Activer le Contrôle de compte d'utilisateur (UAC) est crucial pour la sécurité. Il demande une autorisation pour les actions qui pourraient affecter le fonctionnement de votre système ou modifier les paramètres nécessitant des privilèges administratifs. Cela garantit que toute tentative de modification de votre système est autorisée par vous, réduisant considérablement le risque d'infections par des logiciels malveillants."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1 -Type DWord"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "While it's generally not recommended, there might be specific scenarios where you need to disable UAC, such as for troubleshooting or running certain applications that are not compatible with UAC. Always ensure to re-enable UAC as soon as possible."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Bien que cela ne soit généralement pas recommandé, il pourrait y avoir des scénarios spécifiques nécessitant la désactivation de l'UAC, comme pour le dépannage ou l'exécution de certaines applications non compatibles avec l'UAC. Assurez-vous toujours de réactiver l'UAC dès que possible."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 0 -Type DWord"
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 1,User Account Control: Admin Approval Mode"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Automatic logon allows the system to automatically log on a user after booting up. This can be a security risk if the system is not physically secured as anyone can access the system without providing any credentials. It is recommended to disable automatic logon.",
          "title": "Automatic logon enabled"
        },
        {
          "locale": "FR",
          "summary": "La connexion automatique permet au système de connecter automatiquement un utilisateur après le démarrage. Cela peut être un risque pour la sécurité si le système n'est pas physiquement sécurisé car n'importe qui peut accéder au système sans fournir de credentials. Il est recommandé de désactiver la connexion automatique.",
          "title": "Connexion automatique activée"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "if((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue).AutoAdminLogon -eq '1') { 'Automatic logon enabled' } else { '' }"
      },
      "metrictype": "bool",
      "name": "automatic login enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling automatic login is crucial for enhancing the security of your Windows system. When automatic login is enabled, anyone with physical access to the computer can gain access without needing to enter a username or password. This action requires you to enter your credentials upon startup, thereby providing an additional layer of security."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver la connexion automatique est crucial pour renforcer la sécurité de votre système Windows. Lorsque la connexion automatique est activée, toute personne ayant accès physique à l'ordinateur peut y accéder sans avoir besoin de saisir un nom d'utilisateur ou un mot de passe. Cette action nécessite que vous saisissiez vos identifiants au démarrage, fournissant ainsi une couche supplémentaire de sécurité."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 0"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Re-enabling automatic login should be done with caution and only in environments where physical security is guaranteed. This feature can be convenient for systems that do not require strict security measures and are in secure locations. Remember, this lowers the security of your system by allowing access without credentials."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Réactiver la connexion automatique doit être fait avec prudence et uniquement dans des environnements où la sécurité physique est garantie. Cette fonctionnalité peut être pratique pour les systèmes qui n'exigent pas de mesures de sécurité strictes et qui se trouvent dans des lieux sécurisés. Rappelez-vous, cela diminue la sécurité de votre système en permettant l'accès sans identifiants."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 1"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Disable Automatic Logon"
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
        "minversion": 10,
        "system": "Windows",
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
        "minversion": 10,
        "system": "Windows",
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
        "minversion": 10,
        "system": "Windows",
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
        "minversion": 10,
        "system": "Windows",
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
        "minversion": 10,
        "system": "Windows",
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
        "minversion": 10,
        "system": "Windows",
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
          "title": "Unverified or egress traffic"
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
        "minversion": 10,
        "system": "Windows",
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
        "minversion": 10,
        "system": "Windows",
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
        "minversion": 10,
        "system": "Windows",
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
          "summary": "Windows Script Host is a built-in Windows scripting environment that allows running of VBScript, JScript, and other scripting languages. Disabling it can help mitigate some types of malware attacks.",
          "title": "Windows Script Host enabled"
        },
        {
          "locale": "FR",
          "summary": "Windows Script Host est un environnement de script Windows intégré qui permet l'exécution de VBScript, JScript et d'autres langages de script. Le désactiver peut aider à atténuer certains types d'attaques de logiciels malveillants.",
          "title": "Windows Script Host activé"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "if((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings' -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 1) { 'Windows Script Host enabled' } else { '' }"
      },
      "metrictype": "bool",
      "name": "Windows Script Host enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling Windows Script Host (WSH) is a preventative measure against certain types of malware attacks that utilize scripting languages like VBScript or JScript. This action prevents scripts from running, thereby enhancing your system's security against script-based threats."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver Windows Script Host (WSH) est une mesure préventive contre certains types d'attaques de logiciels malveillants qui utilisent des langages de script comme VBScript ou JScript. Cette action empêche l'exécution de scripts, renforçant ainsi la sécurité de votre système contre les menaces basées sur des scripts."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "reg add HKLM\\SOFTWARE\\Microsoft\\'Windows Script Host'\\Settings /v Enabled /t REG_DWORD /d 0 /f"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Enabling Windows Script Host (WSH) should be considered carefully, especially if specific scripts are necessary for your operations. Be mindful of the scripts you execute to maintain system security."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "L'activation de Windows Script Host (WSH) doit être considérée avec soin, notamment si des scripts spécifiques sont nécessaires pour vos opérations. Soyez attentif aux scripts que vous exécutez pour maintenir la sécurité du système."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "reg add HKLM\\SOFTWARE\\Microsoft\\'Windows Script Host'\\Settings /v Enabled /t REG_DWORD /d 1 /f"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Disable Windows Script Host"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "RDP allows users to remotely access and control a Windows computer from another location. While this can be convenient, it also presents a significant security risk if left enabled and unprotected. An attacker could potentially gain access to your computer and compromise your sensitive data or even take control of your system.",
          "title": "Remote Desktop Protocol (RDP) enabled"
        },
        {
          "locale": "FR",
          "summary": "RDP permet aux utilisateurs d'accéder à distance et de contrôler un ordinateur Windows à partir d'un autre emplacement. Bien que cela puisse être pratique, cela présente également un risque de sécurité important s'il est laissé activé et non protégé. Un attaquant pourrait potentiellement accéder à votre ordinateur et compromettre vos données sensibles ou même prendre le contrôle de votre système.",
          "title": "Protocole de Bureau à distance (RDP) activé"
        }
      ],
      "dimension": "network",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "if((Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0) { 'Terminal Services connections allowed' } else { '' }"
      },
      "metrictype": "bool",
      "name": "remote desktop enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling Remote Desktop Protocol (RDP) is crucial for securing your system against unauthorized remote access. This ensures that no remote connections can be established, significantly reducing the risk of cyber attacks."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver le Protocole de Bureau à distance (RDP) est crucial pour sécuriser votre système contre l'accès à distance non autorisé. Cela garantit qu'aucune connexion à distance ne peut être établie, réduisant considérablement le risque d'attaques cybernétiques."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "If you need to enable Remote Desktop Protocol (RDP) for specific purposes, ensure your system is secured with strong passwords and access is restricted to trusted users only. Additionally, consider implementing network level authentication and firewall rules to safeguard your system."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Si vous devez activer le Protocole de Bureau à distance (RDP) pour des besoins spécifiques, assurez-vous que votre système est sécurisé avec des mots de passe forts et que l'accès est limité aux utilisateurs de confiance uniquement. De plus, envisagez de mettre en œuvre une authentification au niveau du réseau et des règles de pare-feu pour protéger votre système."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Ensure Remote Desktop Protocol is Configured"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Disabling Windows Update prevents critical security patches and updates from being installed on your system, leaving your system vulnerable to known exploits and threats. It is highly recommended that you enable Windows Update to ensure your system is up to date with the latest security patches.",
          "title": "Windows Update disabled"
        },
        {
          "locale": "FR",
          "summary": "La désactivation de la mise à jour de Windows empêche l'installation des correctifs et des mises à jour de sécurité critiques sur votre système, laissant votre système vulnérable aux exploits et menaces connus. Il est fortement recommandé d'activer la mise à jour de Windows pour garantir que votre système est à jour avec les derniers correctifs de sécurité.",
          "title": "Mise à jour Windows désactivée"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "$registryPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU'; $noAutoUpdate = (Get-ItemProperty -Path $registryPath -Name NoAutoUpdate -ErrorAction SilentlyContinue).NoAutoUpdate; $useWUServer = (Get-ItemProperty -Path $registryPath -Name UseWUServer -ErrorAction SilentlyContinue).UseWUServer; Write-Output ($(if ($noAutoUpdate -eq 0 -or $useWUServer -eq 1) { '' } else { $messages = @(); if ($noAutoUpdate -ne 0) {$messages += 'NoAutoUpdate is set.'}; if ($useWUServer -ne 1) {$messages += 'Updates are not managed through GPO.'}; $messages -join ' ' }))"
      },
      "metrictype": "bool",
      "name": "manual system updates",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Enabling automatic updates is crucial for maintaining system security. To ensure your system automatically downloads and installs updates, execute the provided command. This action helps protect your computer against vulnerabilities by keeping it updated with the latest security patches."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Activer les mises à jour automatiques est crucial pour maintenir la sécurité du système. Pour que votre système télécharge et installe automatiquement les mises à jour, exécutez la commande fournie. Cette action aide à protéger votre ordinateur contre les vulnérabilités en le gardant à jour avec les derniers correctifs de sécurité."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "If you need to disable automatic updates, be aware that this may expose your system to security risks. Manual updates require regular monitoring to ensure your system's security. Use the provided command to switch back to manual updates, but consider the potential vulnerabilities and ensure to manually check for updates regularly."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Si vous devez désactiver les mises à jour automatiques, sachez que cela peut exposer votre système à des risques de sécurité. Les mises à jour manuelles nécessitent une surveillance régulière pour garantir la sécurité de votre système. Utilisez la commande fournie pour revenir aux mises à jour manuelles, mais prenez en compte les vulnérabilités potentielles et assurez-vous de vérifier manuellement les mises à jour régulièrement."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f"
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 1,Configure Automatic Updates"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "The Guest account is a default account in Windows, which allows users to access the system with limited privileges. It's recommended to disable this account to prevent unauthorized access to your system and data.",
          "title": "Guest account enabled"
        },
        {
          "locale": "FR",
          "summary": "Le compte Invité est un compte par défaut dans Windows, qui permet aux utilisateurs d'accéder au système avec des privilèges limités. Il est recommandé de désactiver ce compte pour empêcher tout accès non autorisé à votre système et à vos données.",
          "title": "Compte Invité activé"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "$guestAccount = Get-LocalUser | Where-Object {$_.SID -like '*-501'}; if ($guestAccount.Enabled) {'Guest account is active'} else {''}"
      },
      "metrictype": "bool",
      "name": "guest account enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling the Guest account is a critical step towards securing your Windows system. The Guest account, by default, has limited access but can still be a potential entry point for unauthorized access. Use the provided CLI command to disable this account and protect your system from unnecessary exposure."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver le compte Invité est une étape cruciale pour sécuriser votre système Windows. Le compte Invité, par défaut, a un accès limité mais peut encore être un point d'entrée potentiel pour un accès non autorisé. Utilisez la commande CLI fournie pour désactiver ce compte et protéger votre système d'une exposition inutile."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "$guestAccount = Get-LocalUser | Where-Object {$_.SID -like '*-501'}; if ($guestAccount.Enabled) {Disable-LocalUser -Name $guestAccount.Name}"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "If there's a specific need to enable the Guest account, it should be done with caution. Ensure that the use of the Guest account is monitored and that its access is limited to only what is necessary. Use the provided CLI command to re-enable the Guest account as needed."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "S'il y a un besoin spécifique d'activer le compte Invité, cela devrait être fait avec prudence. Assurez-vous que l'utilisation du compte Invité est surveillée et que son accès est limité à ce qui est nécessaire. Utilisez la commande CLI fournie pour réactiver le compte Invité selon les besoins."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "$guestAccount = Get-LocalUser | Where-Object {$_.SID -like '*-501'}; if (-not $guestAccount.Enabled) {Enable-LocalUser -Name $guestAccount.Name}"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Ensure Guest account status is disabled"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "The Built-in Administrator account is a powerful account that has full access to the system. Having this account enabled is a security risk as it is a common target for attackers. It should be disabled unless it is absolutely necessary to enable it.",
          "title": "Built-in Administrator account enabled"
        },
        {
          "locale": "FR",
          "summary": "Le compte administrateur intégré est un compte puissant qui a un accès complet au système. Avoir ce compte activé représente un risque de sécurité car c'est une cible courante pour les attaquants. Il devrait être désactivé sauf s'il est absolument nécessaire de l'activer.",
          "title": "Compte administrateur intégré activé"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "$adminAccount = Get-LocalUser | Where-Object {$_.SID -like '*-500'}; if ($adminAccount.Enabled) {'Built-in Administrator account enabled'} else {''}"
      },
      "metrictype": "bool",
      "name": "root user enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling the built-in Administrator account reduces the risk of unauthorized system changes and potential security breaches. This account has full system access and should be disabled in a normal user environment. Use the provided CLI command for disabling the Administrator account to enhance your system's security posture."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver le compte administrateur intégré réduit le risque de modifications non autorisées du système et de violations potentielles de la sécurité. Ce compte a un accès complet au système et devrait être désactivé dans un environnement utilisateur normal. Utilisez la commande CLI fournie pour désactiver le compte administrateur afin d'améliorer la posture de sécurité de votre système."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "$adminAccount = Get-LocalUser | Where-Object {$_.SID -like '*-500'}; if ($adminAccount.Enabled) {Disable-LocalUser -Name $adminAccount.Name}"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Re-enabling the built-in Administrator account should be done with specific operational requirements in mind. Ensure that its use is strictly controlled and monitored. Use the provided CLI command to re-enable the Administrator account when necessary, but always prioritize security and minimize its use to when absolutely needed."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Réactiver le compte administrateur intégré doit être fait en tenant compte de besoins opérationnels spécifiques. Assurez-vous que son utilisation est strictement contrôlée et surveillée. Utilisez la commande CLI fournie pour réactiver le compte administrateur lorsque nécessaire, mais toujours prioriser la sécurité et minimiser son utilisation à quand absolument nécessaire."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "$adminAccount = Get-LocalUser | Where-Object {$_.SID -like '*-500'}; if (-not $adminAccount.Enabled) {Enable-LocalUser -Name $adminAccount.Name}"
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 1,Built-in Administrator account status"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Windows Firewall is a built-in feature of Windows that helps to protect your computer from unauthorized access. When it's disabled, your computer is vulnerable to attacks from the network. We recommend that you enable it.",
          "title": "Windows Firewall disabled"
        },
        {
          "locale": "FR",
          "summary": "Le pare-feu Windows est une fonctionnalité intégrée de Windows qui aide à protéger votre ordinateur contre les accès non autorisés. Lorsqu'il est désactivé, votre ordinateur est vulnérable aux attaques en provenance du réseau. Nous vous recommandons de l'activer.",
          "title": "Pare-feu Windows désactivé"
        }
      ],
      "dimension": "network",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "if((Get-NetFirewallProfile -All | Where-Object { $_.Enabled -eq 'False' })) { 'One or more firewall profiles are disabled' } else { '' }"
      },
      "metrictype": "bool",
      "name": "local firewall disabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Enabling Windows Firewall is crucial for defending your computer against unauthorized network access and potential cyber threats. The Windows Firewall provides a first line of defense by controlling incoming and outgoing network traffic based on security rules. By using the provided CLI command, you can ensure that your firewall is active and contributing to the overall security of your system."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Activer le pare-feu Windows est essentiel pour défendre votre ordinateur contre les accès réseau non autorisés et les menaces cybernétiques potentielles. Le pare-feu Windows offre une première ligne de défense en contrôlant le trafic réseau entrant et sortant en fonction des règles de sécurité. En utilisant la commande CLI fournie, vous pouvez vous assurer que votre pare-feu est actif et contribue à la sécurité globale de votre système."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling the Windows Firewall should be considered only under specific circumstances where it is necessary for certain applications or services to function correctly. However, this action increases your system's vulnerability to network-based attacks. Ensure alternative security measures are in place before proceeding with the provided CLI command to disable the firewall."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver le pare-feu Windows ne devrait être envisagé que dans des circonstances spécifiques où cela est nécessaire pour le bon fonctionnement de certaines applications ou services. Cependant, cette action augmente la vulnérabilité de votre système aux attaques basées sur le réseau. Assurez-vous que des mesures de sécurité alternatives sont en place avant de procéder avec la commande CLI fournie pour désactiver le pare-feu."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 1,Ensure Windows Firewall is Enabled"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "The Remote Registry Service allows remote access to the Windows Registry. This can be a security risk if not properly secured.",
          "title": "Remote Registry Service enabled"
        },
        {
          "locale": "FR",
          "summary": "Le Service Registre Distant permet l'accès distant au Registre de Windows. Cela peut être un risque de sécurité si cela n'est pas correctement sécurisé.",
          "title": "Service Registre Distant activé"
        }
      ],
      "dimension": "system services",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "if((Get-Service -Name RemoteRegistry).Status -eq 'Running') { 'RemoteRegistry service is running' } else { '' }"
      },
      "metrictype": "bool",
      "name": "Remote Registry Service enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling the Remote Registry Service is recommended to reduce the attack surface of your Windows system. This service, if left enabled, can provide a potential pathway for attackers to modify registry settings remotely, leading to unauthorized changes or malicious activities. Secure your system by using the provided CLI command to disable this service."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Il est recommandé de désactiver le Service Registre Distant pour réduire la surface d'attaque de votre système Windows. Ce service, s'il reste activé, peut fournir un chemin potentiel pour que les attaquants modifient à distance les paramètres du registre, conduisant à des changements non autorisés ou à des activités malveillantes. Sécurisez votre système en utilisant la commande CLI fournie pour désactiver ce service."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "(sc.exe config RemoteRegistry start= disabled) -and (sc.exe stop RemoteRegistry)"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Re-enabling the Remote Registry Service should be done with caution and only if it is strictly necessary for your operational needs. Keep in mind that this can expose your system to additional risks. Ensure that appropriate security controls and monitoring are in place before using the provided CLI command to re-enable this service."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Réactiver le Service Registre Distant doit être fait avec prudence et seulement si cela est strictement nécessaire pour vos besoins opérationnels. Gardez à l'esprit que cela peut exposer votre système à des risques supplémentaires. Assurez-vous que des contrôles de sécurité appropriés et une surveillance sont en place avant d'utiliser la commande CLI fournie pour réactiver ce service."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "(sc.exe config RemoteRegistry start= auto) -and (sc.exe start RemoteRegistry)"
      },
      "scope": "generic",
      "severity": 3,
      "tags": [
        "CIS Benchmark Level 1,Ensure Remote Registry Service is disabled"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "The LM and NTLMv1 protocols are outdated and insecure authentication protocols. They should be disabled to prevent potential security threats. Leaving these protocols enabled can allow attackers to potentially crack passwords and gain unauthorized access to sensitive information.",
          "title": "LM and NTLMv1 protocols enabled"
        },
        {
          "locale": "FR",
          "summary": "Les protocoles LM et NTLMv1 sont des protocoles d'authentification obsolètes et peu sûrs. Ils doivent être désactivés pour prévenir les menaces potentielles à la sécurité. Le fait de laisser ces protocoles activés peut permettre à des attaquants de déchiffrer des mots de passe et d'obtenir un accès non autorisé à des informations sensibles.",
          "title": "Protocoles LM et NTLMv1 activés"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 0,
        "system": "Windows",
        "target": "if(((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA' -ErrorAction SilentlyContinue).LMCompatibilityLevel -lt 5) -or ((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinClientSec -lt 537395200) -or ((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinServerSec -lt 537395200)) { 'Weak NTLM settings' } else { '' }"
      },
      "metrictype": "bool",
      "name": "LM and NTLMv1 enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling LM and NTLMv1 protocols enhances security by preventing the use of these older, less secure authentication methods. Modern authentication protocols offer stronger encryption and better protection against attacks. Follow the provided CLI command to update your system's settings to use more secure authentication methods."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver les protocoles LM et NTLMv1 améliore la sécurité en empêchant l'utilisation de ces méthodes d'authentification plus anciennes et moins sécurisées. Les protocoles d'authentification modernes offrent un cryptage plus fort et une meilleure protection contre les attaques. Suivez la commande CLI fournie pour mettre à jour les paramètres de votre système afin d'utiliser des méthodes d'authentification plus sécurisées."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 0,
        "system": "Windows",
        "target": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA' -Name 'LMCompatibilityLevel' -Value '5' -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0' -Name 'NtlmMinClientSec' -Value '537395200' -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0' -Name 'NtlmMinServerSec' -Value '537395200' -Type DWord"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Re-enabling LM and NTLMv1 should be done with caution and only if there is a specific requirement for these older protocols due to legacy systems or applications. Be aware that enabling these protocols can expose your system to increased security risks. Ensure that you have strong mitigations and monitoring in place."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Réactiver LM et NTLMv1 doit être fait avec prudence et seulement s'il existe une exigence spécifique pour ces protocoles plus anciens en raison de systèmes ou d'applications hérités. Soyez conscient que l'activation de ces protocoles peut exposer votre système à des risques de sécurité accrus. Assurez-vous que vous avez en place de fortes atténuations et une surveillance."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 0,
        "system": "Windows",
        "target": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA' -Name 'LmCompatibilityLevel' -Value '1' -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0' -Name 'NtlmMinClientSec' -Value '262144' -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0' -Name 'NtlmMinServerSec' -Value '537395200' -Type DWord"
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 1,Network security: LAN Manager authentication level"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Lsass.exe is a critical system process that handles user authentication. It contains sensitive information such as passwords and security tokens. If this process is compromised, it could lead to a security breach. Enabling Lsass.exe process protection helps prevent attacks against this process. This content will show you how to enable Lsass.exe process protection.",
          "title": "Lsass.exe process protection not enabled"
        },
        {
          "locale": "FR",
          "summary": "Lsass.exe est un processus système essentiel qui gère l'authentification de l'utilisateur. Il contient des informations sensibles telles que des mots de passe et des jetons de sécurité. Si ce processus est compromis, cela peut entraîner une violation de sécurité. L'activation de la protection du processus Lsass.exe aide à prévenir les attaques contre ce processus. Ce contenu vous montrera comment activer la protection du processus Lsass.exe.",
          "title": "Protection du processus Lsass.exe désactivée"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "if((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL -eq 0) { 'RunAsPPL is a REG_DWORD with value 0' } else { '' }"
      },
      "metrictype": "bool",
      "name": "Lsass process protection",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Enabling Lsass process protection is crucial for securing the system against attacks targeting the Local Security Authority Subsystem Service (LSASS), which handles user logins and password changes. This setting ensures that the LSASS process runs with additional protections, making it harder for attackers to exploit vulnerabilities. Implement the provided CLI command to enhance the security of your system."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Activer la protection du processus Lsass est crucial pour sécuriser le système contre les attaques ciblant le Service de sous-système d'autorité de sécurité locale (LSASS), qui gère les connexions des utilisateurs et les changements de mot de passe. Ce paramètre garantit que le processus LSASS fonctionne avec des protections supplémentaires, rendant plus difficile pour les attaquants d'exploiter les vulnérabilités. Implémentez la commande CLI fournie pour renforcer la sécurité de votre système."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Disabling Lsass process protection should be carefully considered as it removes additional security layers from the LSASS process. If you must disable this protection due to compatibility issues or other specific requirements, ensure you understand the risks and have alternative security measures in place."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Désactiver la protection du processus Lsass doit être soigneusement considéré car cela supprime des couches de sécurité supplémentaires du processus LSASS. Si vous devez désactiver cette protection en raison de problèmes de compatibilité ou d'autres exigences spécifiques, assurez-vous de comprendre les risques et d'avoir des mesures de sécurité alternatives en place."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Ensure LSASS is configured to run as a Protected Process"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "PowerShell is a powerful command-line tool that is built into Windows, and is often used by attackers to carry out malicious activities. The execution policy determines which scripts are allowed to run on a Windows system. If the execution policy is set to Unrestricted, it could allow an attacker to run malicious scripts on your system.",
          "title": "PowerShell execution policy not securely configured"
        },
        {
          "locale": "FR",
          "summary": "PowerShell est un outil en ligne de commande puissant intégré à Windows, souvent utilisé par des attaquants pour effectuer des activités malveillantes. La stratégie d'exécution détermine les scripts autorisés à s'exécuter sur un système Windows. Si la stratégie d'exécution est pas définie sur Unrestricted, cela pourrait permettre à un attaquant d'exécuter des scripts malveillants sur votre système.",
          "title": "La stratégie d'exécution de PowerShell n'est pas sécurisée"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "$currentUserPolicy= Get-ExecutionPolicy -Scope CurrentUser; if($currentUserPolicy -eq 'Unrestricted') { 'Execution Policy is unrestricted' } else { '' }"
      },
      "metrictype": "bool",
      "name": "PS execution policy unrestricted",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Setting PowerShell's execution policy to Default helps prevent the execution of malicious scripts by requiring that all scripts and configuration files downloaded from the Internet are signed by a trusted publisher. This setting is a balance between security and functionality, allowing locally created scripts to run while protecting against untrusted scripts. Apply the provided CLI command to adjust your PowerShell execution policy. Following the automatic changes, a system restart is required."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Définir la politique d'exécution de PowerShell sur Default aide à prévenir l'exécution de scripts malveillants en exigeant que tous les scripts et fichiers de configuration téléchargés depuis Internet soient signés par un éditeur de confiance. Ce paramètre est un équilibre entre sécurité et fonctionnalité, permettant l'exécution de scripts créés localement tout en protégeant contre les scripts non fiables. Appliquez la commande CLI fournie pour ajuster votre politique d'exécution PowerShell. Après les modifications automatiques, un redémarrage du système est requis."
          }
        ],
        "elevation": "restart",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "Set-ExecutionPolicy -ExecutionPolicy Default -Scope CurrentUser -Force"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Reverting PowerShell's execution policy to Unrestricted removes the requirement for scripts to be signed, significantly increasing the risk of executing malicious scripts. Only proceed with this action if there is a compelling need and you have adequate security measures to mitigate potential risks. Be sure to apply strict controls and monitoring to detect and respond to malicious activities. Following the automatic changes, a system restart is required."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Revenir à la politique d'exécution de PowerShell sur Non restreint supprime l'exigence pour les scripts d'être signés, augmentant considérablement le risque d'exécuter des scripts malveillants. Ne procédez à cette action que s'il y a un besoin impérieux et que vous disposez de mesures de sécurité adéquates pour atténuer les risques potentiels. Assurez-vous d'appliquer des contrôles stricts et une surveillance pour détecter et répondre aux activités malveillantes. Après les modifications automatiques, un redémarrage du système est requis."
          }
        ],
        "elevation": "restart",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Ensure PowerShell Execution Policy is set to RemoteSigned"
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
        "minversion": 10,
        "system": "Windows",
        "target": "$path = 'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome'; if (Test-Path $path) { $local_version = (Get-ItemProperty -Path $path).DisplayVersion; $web_content = Invoke-WebRequest -UseBasicParsing 'https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1'; $latest_version = ($web_content.Content | ConvertFrom-Json)[0].version; if ([version]$latest_version -le [version]$local_version) { Write-Output '' } else { Write-Output 'Chrome is not up to date (Installed: $local_version, Latest: $latest_version)'; } } else { Write-Output '' }"
      },
      "metrictype": "bool",
      "name": "Chrome not uptodate",
      "remediation": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/chrome/answer/95414?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/chrome/answer/95414?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": ""
      },
      "rollback": {
        "class": "",
        "education": [
          {
            "class": "link",
            "locale": "EN",
            "target": "https://support.google.com/chrome/a/answer/6350036?hl=en"
          },
          {
            "class": "link",
            "locale": "FR",
            "target": "https://support.google.com/chrome/a/answer/6350036?hl=fr"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
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
          "summary": "The SMBv1 protocol is enabled on your system. This protocol is outdated and has known vulnerabilities that can allow attackers to take over your system. It should be disabled to improve your system's security.",
          "title": "SMBv1 Protocol Enabled"
        },
        {
          "locale": "FR",
          "summary": "Le protocole SMBv1 est activé sur votre système. Ce protocole est obsolète et présente des vulnérabilités connues qui peuvent permettre aux attaquants de prendre le contrôle de votre système. Il devrait être désactivé pour améliorer la sécurité de votre système.",
          "title": "Protocole SMBv1 activé"
        }
      ],
      "dimension": "network",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "if((Get-SmbServerConfiguration).EnableSMB1Protocol -eq $true) { 'SMBv1 enabled' } else { '' }"
      },
      "metrictype": "bool",
      "name": "SMBv1 enabled",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Following the automatic changes, a system restart is required."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Après les modifications automatiques, un redémarrage du système est requis."
          }
        ],
        "elevation": "restart",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -norestart"
      },
      "rollback": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "Following the automatic changes, a system restart is required."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Après les modifications automatiques, un redémarrage du système est requis."
          }
        ],
        "elevation": "restart",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -norestart"
      },
      "scope": "generic",
      "severity": 5,
      "tags": [
        "CIS Benchmark Level 1,Ensure SMBv1 protocol is disabled"
      ]
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Your system currently does not have any sign-in options enabled. It is important to enable sign-in options like passwords, PIN, or Windows Hello to ensure your device is securely protected.",
          "title": "No sign-in options enabled"
        },
        {
          "locale": "FR",
          "summary": "Votre système n'a actuellement activé aucune option de connexion. Il est important d'activer des options de connexion telles que des mots de passe, un code PIN ou Windows Hello pour assurer la protection sécurisée de votre appareil.",
          "title": "Aucune option de connexion activée"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "$lastLoggedOnProvider = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI' -Name 'LastLoggedOnProvider' -ErrorAction SilentlyContinue).LastLoggedOnProvider; if ($null -eq $lastLoggedOnProvider) { 'Registry entry not present' } elseif ($lastLoggedOnProvider -like '*NgcPin*') { $pinLength = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\PassportForWork\\PINComplexity' -Name 'MinimumPINLength' -ErrorAction SilentlyContinue).MinimumPINLength; if ($pinLength -lt 6) { 'Windows Hello PIN does not meet the minimum length requirement.' } else { '' } } else { '' }"
      },
      "metrictype": "bool",
      "name": "no sign-in options protection",
      "remediation": {
        "class": "link",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "To enable sign-in options, go to Settings > Accounts > Sign-in options. Follow the guide to set up a password, PIN, or Windows Hello. <a href='https://support.microsoft.com/en-us/windows/windows-sign-in-options-and-account-protection-7b34d4cf-794f-f6bd-ddcc-e73cdf1a6fbf'>Learn more</a>"
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Pour activer les options de connexion, allez dans Paramètres > Comptes > Options de connexion. Suivez le guide pour configurer un mot de passe, un code PIN ou Windows Hello. <a href='https://support.microsoft.com/fr-fr/windows/options-de-connexion-de-windows-10-et-protection-des-comptes-7b34d4cf-794f-f6bd-ddcc-e73cdf1a6fbf'>En savoir plus</a>"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "ms-settings:signinoptions"
      },
      "rollback": {
        "class": "link",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "To enable sign-in options, go to Settings > Accounts > Sign-in options. Follow the guide to set up a password, PIN, or Windows Hello. <a href='https://support.microsoft.com/en-us/windows/windows-sign-in-options-and-account-protection-7b34d4cf-794f-f6bd-ddcc-e73cdf1a6fbf'>Learn more</a>"
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Pour activer les options de connexion, allez dans Paramètres > Comptes > Options de connexion. Suivez le guide pour configurer un mot de passe, un code PIN ou Windows Hello. <a href='https://support.microsoft.com/fr-fr/windows/options-de-connexion-de-windows-10-et-protection-des-comptes-7b34d4cf-794f-f6bd-ddcc-e73cdf1a6fbf'>En savoir plus</a>"
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "ms-settings:signinoptions"
      },
      "scope": "generic",
      "severity": 5,
      "tags": []
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "Windows Hello, a crucial security feature, is not available on your system. Enabling it provides advanced security mechanisms such as PIN and biometric authentication.",
          "title": "Windows Hello is not available"
        },
        {
          "locale": "FR",
          "summary": "Windows Hello, une fonctionnalité de sécurité essentielle, n'est pas disponible sur votre système. L'activer fournit des mécanismes de sécurité avancés tels que l'authentification par PIN et biométrique.",
          "title": "Windows Hello n'est pas disponible"
        }
      ],
      "dimension": "credentials",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Ngc\\Status') { '' } else { 'Windows Hello is not available.' }"
      },
      "metrictype": "bool",
      "name": "Windows Hello availability",
      "remediation": {
        "class": "link",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "To enable Windows Hello, go to <a href='ms-settings:signinoptions'>Settings > Accounts > Sign-in options</a>. Please note that your device needs to support Windows Hello. If it does not, you might need to upgrade your hardware or check for available updates from your device manufacturer. For more information, visit the <a href='https://support.microsoft.com/en-us/windows/configure-windows-hello-dae28983-8242-bb2a-d3d1-87c9d265a5f0'>support page</a>."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Pour activer Windows Hello, allez dans <a href='ms-settings:signinoptions'>Paramètres > Comptes > Options de connexion</a>. Veuillez noter que votre appareil doit prendre en charge Windows Hello. Si ce n'est pas le cas, vous devrez peut-être mettre à niveau votre matériel ou vérifier les mises à jour disponibles auprès du fabricant de votre appareil. Pour plus d'informations, visitez la <a href='https://support.microsoft.com/fr-fr/windows/configurer-windows-hello-dae28983-8242-bb2a-d3d1-87c9d265a5f0'>page de support</a>."
          }
        ],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "ms-settings:signinoptions"
      },
      "rollback": {
        "class": "link",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "To enable Windows Hello, go to <a href='ms-settings:signinoptions'>Settings > Accounts > Sign-in options</a>. Please note that your device needs to support Windows Hello. If it does not, you might need to upgrade your hardware or check for available updates from your device manufacturer. For more information, visit the <a href='https://support.microsoft.com/en-us/windows/configure-windows-hello-dae28983-8242-bb2a-d3d1-87c9d265a5f0'>support page</a>."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Pour activer Windows Hello, allez dans <a href='ms-settings:signinoptions'>Paramètres > Comptes > Options de connexion</a>. Veuillez noter que votre appareil doit prendre en charge Windows Hello. Si ce n'est pas le cas, vous devrez peut-être mettre à niveau votre matériel ou vérifier les mises à jour disponibles auprès du fabricant de votre appareil. Pour plus d'informations, visitez la <a href='https://support.microsoft.com/fr-fr/windows/configurer-windows-hello-dae28983-8242-bb2a-d3d1-87c9d265a5f0'>page de support</a>."
          }
        ],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "ms-settings:signinoptions"
      },
      "scope": "generic",
      "severity": 5,
      "tags": []
    },
    {
      "description": [
        {
          "locale": "EN",
          "summary": "The screensaver lock settings are not properly configured. Ensuring a secure and active screensaver with a reasonable timeout enhances the physical security of your system.",
          "title": "Screensaver lock is not properly configured"
        },
        {
          "locale": "FR",
          "summary": "Les paramètres de verrouillage de l'économiseur d'écran ne sont pas correctement configurés. Assurer un économiseur d'écran sécurisé et actif avec un délai raisonnable améliore la sécurité physique de votre système.",
          "title": "Le verrouillage de l'économiseur d'écran n'est pas correctement configuré"
        }
      ],
      "dimension": "system integrity",
      "implementation": {
        "class": "cli",
        "education": [],
        "elevation": "user",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "$screensaverTimeout = (Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaveTimeOut' -ErrorAction SilentlyContinue).ScreenSaveTimeOut; $screensaverActive = (Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaveActive' -ErrorAction SilentlyContinue).ScreenSaveActive; $secureScreensaver = (Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaverIsSecure' -ErrorAction SilentlyContinue).ScreenSaverIsSecure; if ($screensaverActive -eq '1' -and $secureScreensaver -eq '1' -and $screensaverTimeout -le 600) { '' } else { 'Screensaver lock is not properly configured.' }"
      },
      "metrictype": "bool",
      "name": "too slow or disabled screensaver lock",
      "remediation": {
        "class": "cli",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "This remediation configures your screensaver settings to ensure it is active and set to lock after 10 minutes of inactivity. For more detailed instructions, visit the <a href='https://support.microsoft.com/en-us/windows/change-your-screen-saver-settings-a9dc2a0c-dc8e-9161-d270-aaccc252082a'>support page</a>."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Cette remédiation configure les paramètres de votre économiseur d'écran pour qu'il soit actif et configuré pour se verrouiller après 10 minutes d'inactivité. Pour des instructions plus détaillées, visitez la <a href='https://support.microsoft.com/fr-fr/windows/modifier-vos-param%C3%A8tres-d-%C3%A9cran-de-veille-a9dc2a0c-dc8e-9161-d270-aaccc252082a'>page de support</a>."
          }
        ],
        "elevation": "system",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaveTimeOut' -Value 600; Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaveActive' -Value 1; Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaverIsSecure' -Value 1"
      },
      "rollback": {
        "class": "link",
        "education": [
          {
            "class": "html",
            "locale": "EN",
            "target": "If you need to revert the changes, go back to the lock screen settings and adjust the screensaver timeout and security settings accordingly. Ensure you understand the security implications of any changes you make. For more information, visit the <a href='https://support.microsoft.com/en-us/windows/change-your-screen-saver-settings-a9dc2a0c-dc8e-9161-d270-aaccc252082a'>support page</a>."
          },
          {
            "class": "html",
            "locale": "FR",
            "target": "Si vous devez annuler les modifications, retournez dans les paramètres de l'écran de verrouillage et ajustez les paramètres de délai d'attente et de sécurité de l'économiseur d'écran en conséquence. Assurez-vous de comprendre les implications de sécurité des modifications apportées. Pour plus d'informations, visitez la <a href='https://support.microsoft.com/fr-fr/windows/modifier-vos-param%C3%A8tres-d-%C3%A9cran-de-veille-a9dc2a0c-dc8e-9161-d270-aaccc252082a'>page de support</a>."
          }
        ],
        "elevation": "",
        "maxversion": 0,
        "minversion": 10,
        "system": "Windows",
        "target": "ms-settings:lockscreen"
      },
      "scope": "generic",
      "severity": 4,
      "tags": [
        "CIS Benchmark Level 1,Machine inactivity limit",
        "ISO 27001/2,A.11.2.8-Unattended User Equipment",
        "SOC 2,CC6.1-Logical Access"
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
        "minversion": 10,
        "system": "Windows",
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
        "minversion": 10,
        "system": "Windows",
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
        "minversion": 10,
        "system": "Windows",
        "target": ""
      },
      "scope": "generic",
      "severity": 1,
      "tags": []
    }
  ],
  "name": "threat model Windows",
  "signature": "7a67457fd74d69ecaf5abb7268e47185861a343f5d9f95ad52b15a8df49c679a"
}"#;
