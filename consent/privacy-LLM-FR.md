Politique de confidentialité du service IA EDAMAME Portal (FR)
==============================================================

En vous connectant au service IA EDAMAME Portal, vous acceptez le traitement décrit ci-dessous.

**La connexion active la protection**

Accepter active la protection agentique d'EDAMAME. Elle reste active jusqu'à ce que vous la désactiviez avec le bouton de protection de l'écran Sécurité.
* Sur un ordinateur, la protection fait fonctionner l'Assistant, la détection de schémas d'attaque et la détection de divergence comportementale, et démarre les deux surveillances qu'ils utilisent :
  * La capture des sessions, qui enregistre les métadonnées des connexions réseau de cet ordinateur : adresses IP et ports source et destination, noms de domaine, nombres d'octets et de paquets, horaires, et le programme qui a ouvert chaque connexion (son nom, son chemin, sa ligne de commande, son répertoire de travail, son compte utilisateur et ses fichiers ouverts). Le contenu des paquets n'est pas enregistré.
  * La surveillance des fichiers, qui enregistre les créations, modifications et suppressions de fichiers, avec leurs chemins.
* Sur un téléphone ou une tablette, la protection fait fonctionner uniquement l'Assistant.

Tout ce que ces surveillances enregistrent reste sur cet appareil. Seules les informations listées ci-dessous sont envoyées au service IA EDAMAME Portal.

**Ce qui est envoyé au service IA d'EDAMAME**

Tant que vous êtes connecté, EDAMAME envoie des requêtes textuelles construites à partir de ses constats sur cet appareil. Selon ce que trouve la protection, une requête peut contenir :
* Pour les constats de schémas d'attaque : la description du constat par le détecteur (qui peut contenir des chemins de fichiers complets et, lorsqu'un agent IA a relancé une commande interdite sous une autre forme, les deux commandes), le nom et le chemin complet du processus, le nom et le chemin du processus parent et le chemin du script parent, le nom de domaine, l'adresse IP et le port de destination, les chemins complets des fichiers ouverts par le processus, et les éléments de preuve utilisés par le détecteur (vérifications déclenchées, noms des listes de blocage, identifiants de signature de code, cadres de gouvernance d'agents IA détectés)
* Pour les constats de divergence comportementale : les mêmes informations de processus et de chemins de fichiers, la destination (nom de domaine ou adresse IP, et port), ainsi que le nom et l'identifiant d'instance de l'agent IA concerné. L'identifiant d'instance contient le nom d'hôte de cet ordinateur
* Pour construire le modèle comportemental d'un agent de programmation IA (Cursor, Claude Code, Codex et autres) : des extraits des transcriptions récentes de cet agent, jusqu'à 3 000 caractères chacun pour vos demandes et pour les réponses de l'agent, les commandes exécutées par l'agent, les fichiers et URL utilisés par ses outils, et le chemin du fichier de transcription. Le texte des transcriptions est envoyé tel quel et peut contenir tout ce que vous ou l'agent avez écrit, y compris des secrets
* Pour l'analyse de vos tâches de sécurité par l'Assistant :
  * Connexions réseau : adresses IP et ports source et destination, noms de domaine, opérateur réseau (ASN) et pays, et le programme à l'origine de la connexion (nom, chemin, ligne de commande, répertoire de travail, compte utilisateur, fichiers ouverts et programme parent)
  * Appareils de votre réseau local : nom d'hôte, type, fabricant, système d'exploitation, ports ouverts et bannières de service qu'ils renvoient. Lorsqu'un appareil n'a pas d'autre information d'identification, son adresse IP, son nom d'hôte ou son adresse MAC est envoyé à la place
  * Noms et descriptions des menaces et des politiques, et noms et descriptions des fuites de données. Dans certains cas, l'adresse email concernée par une fuite est incluse
  * Avec chaque analyse de tâche, un résumé de toutes vos tâches de sécurité en cours, qui peut reprendre les informations ci-dessus
* Lorsque vous demandez un conseil du coach : des scores et des compteurs décrivant votre usage des agents de programmation IA, et les noms de leurs compétences, hooks et espaces de travail

Les chemins de fichiers contiennent souvent le nom de votre compte utilisateur, par exemple `/Users/<nom>/...` ou `C:\Users\<nom>\...`. Ces valeurs sont envoyées telles qu'enregistrées, sans être raccourcies ni anonymisées.

EDAMAME envoie aussi un enregistrement de notification à votre compte EDAMAME Portal lorsque la protection lève une alerte ou que l'Assistant agit. Cet enregistrement contient le nom d'hôte de cet ordinateur, ses adresses IP publiques, son modèle et la version de son système d'exploitation, les informations de constat listées ci-dessus (y compris le raisonnement du modèle) et les actions effectuées. Les constats de schémas d'attaque et de divergence sont aussi ajoutés à l'historique des constats de votre Portal.

**Identifiants envoyés à EDAMAME**
* Avec chaque requête : l'identifiant d'appareil EDAMAME de cet appareil, et le jeton de connexion de votre compte EDAMAME (vous vous connectez avec votre adresse email, et le jeton identifie votre compte)
* Lorsque l'application vérifie votre offre Portal : le nom d'hôte de cet ordinateur, utilisé comme nom d'appareil dans votre compte Portal

**Comment EDAMAME traite et conserve ces données**
* Les requêtes sont analysées par Microsoft Azure OpenAI Service, pour le compte d'EDAMAME. Vos identifiants de compte et d'appareil ne lui sont pas transmis
* EDAMAME stocke chaque requête et sa réponse, avec vos identifiants de compte et d'appareil, afin qu'une requête répétée ne soit pas analysée deux fois. Ces entrées sont programmées pour expirer 12 heures après leur écriture
* Les enregistrements de notification sont programmés pour expirer 1 jour après leur envoi, et les entrées de l'historique des constats du Portal 90 jours après la dernière observation du constat
* EDAMAME enregistre la consommation de jetons par compte et par appareil pour appliquer les limites de votre offre. Les journaux du service d'EDAMAME enregistrent les identifiants de compte et d'appareil et le nombre de jetons ; le service n'écrit pas le texte des requêtes dans ses journaux

**Vos choix**
* Désactivez la protection à tout moment avec le bouton de protection de l'écran Sécurité. L'Assistant, les détecteurs, la capture des sessions et la surveillance des fichiers s'arrêtent tous, et EDAMAME n'envoie plus de requêtes de lui-même. Tant que vous restez connecté, une requête est encore envoyée lorsqu'une analyse est demandée explicitement, depuis l'application ou par un agent IA via le serveur MCP d'EDAMAME
* Déconnectez-vous d'EDAMAME Portal dans Config > IA pour cesser toute utilisation du service. Vos jetons de connexion sont stockés sur cet appareil et sont supprimés lors de la déconnexion
* À la place d'EDAMAME Portal, vous pouvez utiliser votre propre fournisseur de modèle dans Config > IA. Les requêtes sont alors envoyées directement à ce fournisseur

Pour plus d'informations sur les pratiques générales de confidentialité d'EDAMAME, consultez notre [Politique de confidentialité](https://www.edamame.tech/privacy).

Si vous n'êtes pas d'accord avec cette politique, ne vous connectez pas au service IA EDAMAME Portal.
