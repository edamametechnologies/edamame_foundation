Linux Politique de Confidentialité du Score Détaillé avec Détails IA (FR)
=========================================================================

En rapportant un score détaillé, vous acceptez de partager les informations suivantes avec EDAMAME :
* L'identifiant unique de votre machine
* Le nom et la version de votre système d'exploitation
* Votre adresse IPv4 et/ou IPv6 publique
* Votre adresse MAC si disponible
* Vos identifiants de pairs pour vos connexions VPN ou ZTNA si disponibles
* Le domaine auquel vous êtes connecté
* Votre nom d'utilisateur dans ce domaine
* Votre score sous forme d'une valeur numérique
* Votre score sous forme d'un vecteur de valeurs booléennes résultant des tests de sécurité suivants :
  * EDAMAME Helper inactif
  * Pas d'antivirus activé
  * Pas de gestionnaire de mots de passe installé
  * Cryptage du disque désactivé
  * Adresse e-mail potentiellement compromise
  * Environement réseau non vérifié ou non sécurisé
  * Services non vérifiés ou non sécurisés exposés sur le réseau local
  * Trafic sortant non vérifié ou non sécurisé
  * Vulnerabilites non examinees
  * Divergence comportementale detectee
  * Actions escaladees en attente d'examen
  * Permissions du fichier /etc/passwd
  * Permissions du fichier /etc/shadow
  * Permissions du fichier /etc/fstab
  * Permissions du fichier /etc/group
  * Appartenance au groupe de /etc/group
  * Appartenance au groupe de /etc/shadow
  * Votre OS n'est pas à jour
  * Pare-feu local désactivé
  * Accès à distance activé
  * Bureau à distance activé
  * Partage de fichiers activé
  * Économiseur d'écran nécessite un mot de passe désactivé
  * Secure Boot désactivé
  * Politique de mot de passe faible
  * Règle métier non respectée
  * Agent Cursor non sécurisé (observateur en pause)
  * Agent Claude Code non sécurisé (observateur en pause)
  * Agent Claude Desktop non sécurisé (observateur en pause)
  * Agent OpenClaw non sécurisé (observateur en pause)
  * Agent IA avec un rayon d'impact eleve sur l'hote
  * Agents IA sans harnais de gouvernance
  * L'agent echappe a la frontiere de son harnais de gouvernance
  * Un agent IA expose un serveur MCP non protege
  * Agent Codex CLI non sécurisé (observateur en pause)
  * Agent Hermes non sécurisé (observateur en pause)

* Le détail de chaque test de sécurité IA en échec parmi ceux listés ci-dessus :
  * Pour chaque agent de codage IA pris en charge par EDAMAME, s'il est installé sur cette machine et si son observateur de transcriptions est actif
  * Le nom de l'agent concerné par l'échec, par exemple `cursor` ou `claude_code`
  * Le nom du harnais de gouvernance déclaré par cet agent, par exemple `nono` ou `srt`
  * Le nom de l'amplificateur de risque déclenché, par exemple `passwordless_root`, `critical_subprocess` ou `secret_exposure`
  * Le nom de fichier, sans son chemin ni ses arguments, d'un programme sensible lancé par l'agent, par exemple `ssh`
  * Le nom configuré d'un serveur MCP détecté comme exposé, par exemple `gojiberry`, accompagné de la règle d'exposition déclenchée, par exemple `mcp_public_no_strong_auth`. Les serveurs MCP non exposés ne sont jamais nommés
  * La catégorie d'un secret détecté dans la transcription de l'agent, par exemple `aws_credentials`, jamais le secret lui-même

Les transcriptions d'agents, les invites, les réponses des modèles, le contenu des fichiers, les arguments de commande, les valeurs des variables d'environnement et les valeurs des secrets ne sont jamais rapportés.

Ces informations sont utilisées uniquement par EDAMAME et ne sont pas partagées avec des tiers.

Ces informations sont collectées à l'aide d'un "modèle de menace" public qui garantit de ne pas violer votre vie privée.

Le modèle de menace peut être consulté à l'adresse [https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-Linux.json](https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-Linux.json).

Le wiki du modèle de menace peut être consulté à l'adresse [https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-Linux-FR](https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-Linux-FR).

Si vous n'êtes pas d'accord avec cette politique, veuillez ne pas rapporter votre score.
