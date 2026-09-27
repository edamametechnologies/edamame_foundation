macOS Politique de Confidentialité du Score Détaillé avec Détails IA (FR)
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
  * Réponse au ping activée
  * Profils MDM installés
  * Administration à distance JAMF installée
  * Wake On LAN activé
  * Mises à jour Appstore manuelles
  * Pare-feu local désactivé
  * Login automatique activé
  * Accès à distance activé
  * Bureau à distance activé
  * Partage de fichiers activé
  * Événements à distance activés
  * Clé d'entreprise de récupération de disque
  * Encryption du disque désactivée
  * Applications non signées autorisées
  * Mises à jour système manuelles
  * Ecran protégé désactivé
  * Pas d'antivirus activé
  * Pas de gestionnaire de mots de passe installé
  * Protection d'intégrité système désactivée
  * Compte invité activé
  * Utilisateur root activé
  * Changement de paramètres système non protégés
  * Adresse e-mail potentiellement compromise
  * Environement réseau non vérifié ou non sécurisé
  * Services non vérifiés ou non sécurisés exposés sur le réseau local
  * Trafic sortant non vérifié ou non sécurisé
  * Vulnerabilites non examinees
  * Divergence comportementale detectee
  * Actions escaladees en attente d'examen
  * Votre OS n'est pas à jour
  * Navigateur Chrome non à jour
  * Règle métier non respectée
  * CLI non restreint pour les utilisateurs standard
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

* Les détails IA de cette machine :
  * Configuration IA de cette machine, envoyée dans chaque rapport, même quand aucun test IA n'est en échec
    * Le nom du compte utilisateur évalué par EDAMAME (déduit du dossier personnel), la famille du système d'exploitation, et si ce compte est administrateur, s'exécute avec des droits élevés ou peut devenir root sans mot de passe
    * Les harnais de gouvernance connus d'EDAMAME, par exemple `nono` ou `srt`, et si chacun est installé
    * Pour chaque agent de codage IA pris en charge par EDAMAME, par exemple `cursor` ou `claude_code` :
      * S'il est installé et si son observateur de transcriptions est actif
      * S'il s'exécute dans un bac à sable, le mécanisme de ce bac à sable et son étendue d'accès aux fichiers
      * Les amplificateurs de risque qui s'appliquent, par exemple `passwordless_root`, `critical_subprocess` ou `secret_exposure`
      * Les noms de fichier, sans chemin ni arguments, des programmes sensibles qu'il a lancés, par exemple `ssh`
      * Les catégories de secrets détectés dans ses transcriptions, par exemple `aws_credentials`, jamais les secrets eux-mêmes
      * Chaque serveur MCP qu'il déclare, exposé ou non : le nom configuré du serveur, le transport, l'étendue d'exposition, le niveau d'authentification, s'il s'agit du serveur d'EDAMAME, ainsi que la sévérité et le nom des règles de tout risque détecté sur ce serveur
  * Pour chaque test de sécurité IA en échec
    * Le nom du test, l'agent concerné, et les conditions qui l'ont fait échouer : un amplificateur de risque, un nom de programme sensible, un nom de serveur MCP et sa règle d'exposition, une catégorie de secret, un harnais de gouvernance absent ou contourné, ou un observateur de transcriptions en pause
    * Pour chaque constat de schéma d'attaque : le détecteur qui l'a levé, son identifiant (une empreinte), sa sévérité, la description du détecteur, le nom du processus et de son processus parent, le nom de domaine de destination (ou, à défaut, l'adresse IP de destination) et le port, la base de détection, la référence de cadre, si vous l'avez écarté sur cet appareil, et si un modèle d'IA l'a examiné. La description peut contenir des chemins complets de fichiers et de programmes, qui contiennent souvent le nom de votre compte utilisateur, et, lorsqu'un agent IA a relancé une commande interdite sous une autre forme, les deux commandes
    * Pour chaque constat de divergence comportementale : sa catégorie, son identifiant, sa sévérité, sa description, le nom du processus, l'agent concerné, ce qui l'a déclenché, et le nombre de fichiers sensibles inattendus (pas leurs chemins)
    * Pour chaque action de l'Assistant en attente de votre validation : son identifiant, son type et sa priorité
    * Si le détecteur de schémas d'attaque, le moteur de divergence ou l'Assistant est désactivé

Les transcriptions d'agents, les invites, les réponses des modèles, le contenu des fichiers, les valeurs des variables d'environnement et les valeurs des secrets ne sont jamais rapportés.

Ces informations sont utilisées uniquement par EDAMAME et ne sont pas partagées avec des tiers.

Ces informations sont collectées à l'aide d'un "modèle de menace" public qui garantit de ne pas violer votre vie privée.

Le modèle de menace peut être consulté à l'adresse [https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-macOS.json](https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-macOS.json).

Le wiki du modèle de menace peut être consulté à l'adresse [https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-macOS-FR](https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-macOS-FR).

Si vous n'êtes pas d'accord avec cette politique, veuillez ne pas rapporter votre score.
