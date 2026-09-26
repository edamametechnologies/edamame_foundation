Politique de partage des détails d'échec IA (FR)
================================================

Ce réglage ajoute le détail des tests de sécurité des agents IA en échec aux rapports de score que cet appareil envoie au domaine auquel il est connecté. Il est désactivé tant que vous ne l'activez pas, et vos rapports de score fonctionnent sans lui.

En l'activant, vous acceptez de partager les informations suivantes avec EDAMAME dans chaque rapport de score :
* Pour chaque agent de codage IA pris en charge par EDAMAME, s'il est installé sur cette machine et si son observateur de transcriptions est actif
* Pour chaque test de sécurité IA en échec :
  * Le nom de l'agent concerné par l'échec, par exemple `cursor` ou `claude_code`
  * Le nom du harnais de gouvernance déclaré par cet agent, par exemple `nono` ou `srt`
  * Le nom de l'amplificateur de risque déclenché, par exemple `passwordless_root`, `critical_subprocess` ou `secret_exposure`
  * Le nom de fichier, sans son chemin ni ses arguments, d'un programme sensible lancé par l'agent, par exemple `ssh`
  * Le nom configuré d'un serveur MCP détecté comme exposé, par exemple `gojiberry`, accompagné de la règle d'exposition déclenchée, par exemple `mcp_public_no_strong_auth`. Les serveurs MCP non exposés ne sont jamais nommés
  * La catégorie d'un secret détecté dans la transcription de l'agent, par exemple `aws_credentials`, jamais le secret lui-même

Les transcriptions d'agents, les invites, les réponses des modèles, le contenu des fichiers, les arguments de commande, les valeurs des variables d'environnement et les valeurs des secrets ne sont jamais rapportés.

Les administrateurs du domaine auquel vous êtes connecté voient ces détails à côté de votre score dans EDAMAME Hub. Ces informations sont utilisées uniquement par EDAMAME et ne sont pas partagées avec des tiers.

Vous pouvez désactiver ce réglage à tout moment dans Config > Confidentialité ou dans Confiance > Connecter : le rapport de score suivant ne contient plus ces détails. Une organisation qui gère cet appareil peut aussi activer ce partage pour lui.

Si vous n'êtes pas d'accord avec cette politique, laissez ce réglage désactivé.
