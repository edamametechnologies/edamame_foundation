Windows Politique de Confidentialité du Score Détaillé avec Détails IA (FR)
===========================================================================

En rapportant un score détaillé, vous acceptez de partager les informations suivantes avec EDAMAME :
* L'identifiant unique de votre machine
* Le nom de votre machine (nom d'hôte), sans son suffixe de domaine réseau
* Le nom et la version de votre système d'exploitation
* Votre adresse IPv4 et/ou IPv6 publique
* Votre localisation approximative déduite de votre adresse IPv4 publique : ville, région, pays, fuseau horaire, latitude et longitude. Pour la déterminer, EDAMAME envoie votre adresse IPv4 publique au service de géolocalisation ip-api.com
* Votre adresse MAC si disponible
* Vos identifiants de pairs pour vos connexions VPN ou ZTNA si disponibles
* Le domaine auquel vous êtes connecté, votre nom d'utilisateur dans ce domaine et le code d'accès utilisé pour vous connecter ou, lorsque vous certifiez votre score, l'adresse email que vous saisissez
* La langue de l'interface d'EDAMAME
* La version d'EDAMAME, si cette machine est un exécuteur CI/CD, et l'état de l'EDAMAME Helper
* La date et l'heure du rapport
* Votre score sous forme d'une valeur numérique
* Votre score pour chaque catégorie (réseau, intégrité du système, services système, applications, identifiants), votre nombre d'étoiles, et votre pourcentage de conformité pour chaque référentiel de conformité
* L'historique des remédiations et des retours en arrière que vous avez effectués : le test concerné, l'action, sa date, et si elle a réussi et a été validée
* Si le partage des détails IA est activé pour cet appareil. Les détails IA eux-mêmes ne sont envoyés que lorsqu'il l'est
* Le nom, la date et la signature du modèle de menace utilisé, et pour chacun des tests de sécurité suivants : sa définition telle que publiée dans ce modèle, son statut (en échec, réussi ou inconnu) et la date de sa dernière évaluation :
  * EDAMAME Helper inactif
  * Activation de la mise en cache des identifiants de connexion
  * Pas d'antivirus activé
  * Pas de gestionnaire de mots de passe installé
  * Encryption du disque désactivée
  * Contrôle de compte d'utilisateur désactivé
  * Connexion automatique activée
  * Adresse e-mail potentiellement compromise
  * Environement réseau non vérifié ou non sécurisé
  * Services non vérifiés ou non sécurisés exposés sur le réseau local
  * Trafic sortant non vérifié ou non sécurisé
  * Vulnerabilites non examinees
  * Divergence comportementale detectee
  * Actions escaladees en attente d'examen
  * Windows Script Host activé
  * Protocole de Bureau à distance (RDP) activé
  * Mise à jour Windows désactivée
  * Compte Invité activé
  * Compte administrateur intégré activé
  * Pare-feu Windows désactivé
  * Service Registre Distant activé
  * Protocoles LM et NTLMv1 activés
  * Protection du processus Lsass.exe désactivée
  * La stratégie d'exécution de PowerShell n'est pas sécurisée
  * Navigateur Chrome non à jour
  * Protocole SMBv1 activé
  * Aucune option de connexion activée
  * Windows Hello n'est pas disponible
  * Le verrouillage de l'économiseur d'écran n'est pas correctement configuré
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

* Les détails IA de cette machine :
  * Configuration IA de cette machine, envoyée dans chaque rapport tant que les détails IA sont partagés, même quand aucun test IA n'est en échec
    * La famille du système d'exploitation, et si le compte utilisateur évalué est administrateur, s'exécute avec des droits élevés ou peut devenir root sans mot de passe. Le nom du compte lui-même n'est pas envoyé
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
    * Pour chaque constat de schéma d'attaque : le détecteur qui l'a levé, son identifiant (une empreinte), sa sévérité, les noms de fichier, sans chemin, du processus et de son processus parent, la destination et le port, la base de détection, la référence de cadre, si vous l'avez écarté sur cet appareil, et si un modèle d'IA l'a examiné
      * La destination est le nom de domaine ou, à défaut, l'adresse IP. Une destination privée, du réseau local ou de bouclage n'est envoyée que sous cette catégorie, par exemple `private network`, jamais sous son adresse ni son nom
      * Pour les fichiers concernés par le constat : la catégorie et le nom de fichier, sans son dossier, de chaque fichier reconnu par la liste de fichiers sensibles d'EDAMAME, par exemple `ssh:id_ed25519`, et seulement le nombre des autres fichiers. Un fichier de votre dossier personnel dont le nom contient le nom de votre compte n'est envoyé que sous sa catégorie
      * Lorsqu'un agent IA a relancé une commande interdite sous une autre forme : les noms des programmes concernés, par exemple `curl`, sans leurs arguments
    * Pour chaque constat de divergence comportementale : sa catégorie, son identifiant, sa sévérité, le nom de fichier du processus, l'agent concerné, la formule du moteur pour ce qui l'a déclenché, par exemple `unexpected sensitive file access with unexplained external egress`, et le nombre de fichiers sensibles inattendus (pas leurs chemins)
    * Pour chaque action de l'Assistant en attente de votre validation : son identifiant, son type et sa priorité
    * Si le détecteur de schémas d'attaque, le moteur de divergence ou l'Assistant est désactivé
    * Les descriptions qu'EDAMAME affiche pour ces constats sur cet appareil ne sont pas envoyées : EDAMAME Hub affiche un résumé construit à partir des éléments ci-dessus

Les transcriptions d'agents, les invites, les réponses des modèles, le contenu des fichiers, les chemins complets des fichiers, les arguments des commandes, les valeurs des variables d'environnement et les valeurs des secrets ne sont jamais rapportés.

**Qui voit ces informations et combien de temps EDAMAME Hub les conserve**
* Les administrateurs du domaine auquel vous êtes connecté voient ces informations dans EDAMAME Hub, et le personnel d'EDAMAME peut les consulter depuis la console d'administration d'EDAMAME
* Si les administrateurs du domaine connectent EDAMAME Hub à d'autres services, comme une plateforme de conformité (Vanta), un fournisseur de contrôle d'accès (par exemple Netskope) ou une organisation GitHub, EDAMAME Hub leur envoie l'état de cet appareil et les informations dont ils ont besoin pour le reconnaître, comme ses adresses IP ou ses identifiants de pairs VPN ou ZTNA
* EDAMAME Hub conserve le dernier rapport de cet appareil sans date d'expiration. Chaque nouveau rapport le remplace, et il est supprimé lorsqu'un administrateur retire l'appareil, lorsque le domaine est supprimé, ou 7 jours après le dernier rapport d'un appareil que le domaine a désactivé
* EDAMAME Hub conserve aussi les rapports précédents pendant 7 jours avec une offre de domaine gratuite et pendant 365 jours avec une offre payante, y compris après la suppression de l'appareil ou du domaine. Ils contiennent l'identifiant de l'appareil, votre nom d'utilisateur, le type de système d'exploitation, le score global et la conformité, le statut de chaque test, les adresses IP publiques et la localisation approximative
* Les journaux du service d'EDAMAME enregistrent les rapports que reçoit EDAMAME Hub. Aucune expiration n'est configurée pour ces journaux
* Lorsque vous certifiez votre score, EDAMAME envoie le rapport par email à l'adresse que vous saisissez et conserve cette adresse. Sauf s'il s'agit d'une adresse edamame.tech, EDAMAME la transmet aussi à son prestataire de prospection par email, Apollo.io, qui peut vous envoyer des emails de suivi. L'équipe d'EDAMAME est avertie de chaque certification dans son espace de travail Slack, avec l'identifiant de l'appareil, le nom d'utilisateur, le système d'exploitation, le score, la ville et le pays, et l'adresse email

En dehors des services nommés dans cette politique, EDAMAME ne partage pas ces informations avec des tiers.

Ces informations sont collectées à l'aide d'un "modèle de menace" public : les tests qu'il exécute, avec leurs scripts, sont publiés aux adresses ci-dessous.

Le modèle de menace peut être consulté à l'adresse [https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-Windows.json](https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-Windows.json).

Le wiki du modèle de menace peut être consulté à l'adresse [https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-Windows-FR](https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-Windows-FR).

Si vous n'êtes pas d'accord avec cette politique, veuillez ne pas rapporter votre score.
