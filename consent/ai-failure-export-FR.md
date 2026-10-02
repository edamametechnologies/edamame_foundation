Politique de partage des détails d'échec IA (FR)
================================================

Lorsque cet appareil est connecté à un domaine, il envoie des rapports de score à EDAMAME Hub. Ce réglage ajoute des détails IA à ces rapports. Il est désactivé tant que vous ne l'activez pas, et vos rapports de score fonctionnent sans lui.

En l'activant, vous acceptez de partager les informations suivantes avec EDAMAME dans chaque rapport de score.

**Configuration IA de cette machine, envoyée dans chaque rapport tant que les détails IA sont partagés, même quand aucun test IA n'est en échec**
* La famille du système d'exploitation, et si le compte utilisateur évalué est administrateur, s'exécute avec des droits élevés ou peut devenir root sans mot de passe. Le nom du compte lui-même n'est pas envoyé
* Les harnais de gouvernance connus d'EDAMAME, par exemple `nono` ou `srt`, et si chacun est installé
* Pour chaque agent de codage IA pris en charge par EDAMAME, par exemple `cursor` ou `claude_code` :
  * S'il est installé et si son observateur de transcriptions est actif
  * S'il s'exécute dans un bac à sable, le mécanisme de ce bac à sable et son étendue d'accès aux fichiers
  * Les amplificateurs de risque qui s'appliquent, par exemple `passwordless_root`, `critical_subprocess` ou `secret_exposure`
  * Les noms de fichier, sans chemin ni arguments, des programmes sensibles qu'il a lancés, par exemple `ssh`
  * Les catégories de secrets détectés dans ses transcriptions, par exemple `aws_credentials`, jamais les secrets eux-mêmes
  * Chaque serveur MCP qu'il déclare, exposé ou non : le nom configuré du serveur, le transport, l'étendue d'exposition, le niveau d'authentification, s'il s'agit du serveur d'EDAMAME, ainsi que la sévérité et le nom des règles de tout risque détecté sur ce serveur

**Pour chaque test de sécurité IA en échec**
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

Les administrateurs du domaine auquel vous êtes connecté voient ces détails à côté de votre score dans EDAMAME Hub. Ces informations sont utilisées uniquement par EDAMAME et ne sont pas partagées avec des tiers.

Vous pouvez désactiver ce réglage à tout moment dans Config > Confidentialité ou dans Confiance > Connecter : le rapport de score suivant ne contient plus ces détails. Une organisation qui gère cet appareil peut aussi activer ce partage pour lui.

Si vous n'êtes pas d'accord avec cette politique, laissez ce réglage désactivé.
