Linux Politique de Confidentialité du Score Détaillé (FR)
=========================================================

En rapportant un score détaillé, vous acceptez de partager les informations suivantes avec EDAMAME :
* L'identifiant unique de votre machine
* Le nom de votre machine (nom d'hôte), sans son suffixe de domaine réseau
* Le nom et la version de votre système d'exploitation
* Votre adresse IPv4 et/ou IPv6 publique
* Votre localisation approximative déduite de votre adresse IPv4 publique : ville, région, pays, fuseau horaire, latitude et longitude. Pour la déterminer, EDAMAME envoie votre adresse IPv4 publique au service de géolocalisation ip-api.com
* Votre adresse MAC si disponible
* Vos identifiants de pairs pour vos connexions VPN ou ZTNA si disponibles
* Le domaine auquel vous êtes connecté, votre nom d'utilisateur dans ce domaine et le code d'accès utilisé pour vous connecter
* La langue de l'interface d'EDAMAME
* La version d'EDAMAME, si cette machine est un exécuteur CI/CD, et l'état de l'EDAMAME Helper
* La date et l'heure du rapport
* Votre score sous forme d'une valeur numérique
* Votre score pour chaque catégorie (réseau, intégrité du système, services système, applications, identifiants), votre nombre d'étoiles, et votre pourcentage de conformité pour chaque référentiel de conformité
* L'historique des remédiations et des retours en arrière que vous avez effectués : le test concerné, l'action, sa date, et si elle a réussi et a été validée
* Le nom, la date et la signature du modèle de menace utilisé, et pour chacun des tests de sécurité suivants : sa définition telle que publiée dans ce modèle, son statut (en échec, réussi ou inconnu) et la date de sa dernière évaluation :
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

Ces informations sont utilisées uniquement par EDAMAME et ne sont pas partagées avec des tiers, à l'exception de votre adresse IPv4 publique envoyée à ip-api.com pour la localisation ci-dessus.

Ces informations sont collectées à l'aide d'un "modèle de menace" public qui garantit de ne pas violer votre vie privée.

Le modèle de menace peut être consulté à l'adresse [https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-Linux.json](https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-Linux.json).

Le wiki du modèle de menace peut être consulté à l'adresse [https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-Linux-FR](https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-Linux-FR).

Si vous n'êtes pas d'accord avec cette politique, veuillez ne pas rapporter votre score.
