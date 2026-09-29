Politique de confidentialité du service IA EDAMAME Portal (FR)
==============================================================

En vous connectant au service IA EDAMAME Portal, vous acceptez le traitement décrit ci-dessous.

**La connexion active la protection**

Accepter active la protection agentique d'EDAMAME. Elle reste active jusqu'à ce que vous la désactiviez avec le bouton de protection de l'écran Sécurité.
* Sur un ordinateur, la protection fait fonctionner l'Assistant, la détection de schémas d'attaque et la détection de divergence comportementale, et démarre les deux surveillances qu'ils utilisent :
  * La capture des sessions, qui enregistre les métadonnées des connexions réseau de cet ordinateur : adresses IP et ports source et destination, noms de domaine, nombres d'octets et de paquets, horaires, et le programme qui a ouvert chaque connexion (son nom, son chemin, sa ligne de commande, son répertoire de travail, son compte utilisateur et ses fichiers ouverts). Le contenu des paquets n'est pas enregistré.
  * La surveillance des fichiers, qui enregistre les créations, modifications et suppressions de fichiers, avec leurs chemins.
* Sur un téléphone ou une tablette, la protection fait fonctionner uniquement l'Assistant.

Ces surveillances conservent leurs enregistrements sur cet appareil. De ce qu'elles enregistrent, seules les informations listées ci-dessous sont envoyées au service IA EDAMAME Portal. Les fonctions que vous activez séparément, comme les détails IA dans les rapports de score envoyés à EDAMAME Hub ou les canaux de notification, envoient des données selon leurs propres réglages et politiques.

**Ce qui est envoyé au service IA d'EDAMAME**

Tant que vous êtes connecté, EDAMAME envoie des requêtes textuelles construites à partir de ses constats sur cet appareil. Selon ce que trouve la protection, une requête peut contenir :
* Pour les constats de schémas d'attaque : la description du constat par le détecteur (qui peut contenir des chemins de fichiers et, lorsqu'un agent IA a relancé une commande interdite sous une autre forme, les deux commandes), le nom et le chemin du processus, le nom et le chemin du processus parent et le chemin du script parent, le nom de domaine, l'adresse IP et le port de destination, les chemins des fichiers ouverts par le processus, et les éléments de preuve utilisés par le détecteur (vérifications déclenchées, noms des listes de blocage, identifiants de signature de code, cadres de gouvernance d'agents IA détectés)
* Pour les constats de divergence comportementale : les mêmes informations de processus et de chemins de fichiers, la destination (nom de domaine ou adresse IP, et port), ainsi que le type de l'agent IA concerné avec un identifiant de son instance
* Pour construire le modèle comportemental d'un agent de programmation IA (Cursor, Claude Code, Codex et autres) : des extraits des transcriptions récentes de cet agent, jusqu'à 3 000 caractères chacun pour vos demandes et pour les réponses de l'agent, les titres des sessions, les commandes exécutées par l'agent, les fichiers et URL utilisés par ses outils, le chemin du fichier de transcription, ainsi que le type et l'identifiant d'instance de l'agent
* Pour l'analyse de vos tâches de sécurité par l'Assistant :
  * Connexions réseau : adresses IP et ports source et destination, noms de domaine, opérateur réseau (ASN) et pays, et le programme à l'origine de la connexion (nom, chemin, ligne de commande, répertoire de travail, compte utilisateur, fichiers ouverts et programme parent)
  * Appareils de votre réseau local : nom d'hôte, type, fabricant, système d'exploitation, services qu'ils annoncent, ports ouverts et bannières de service qu'ils renvoient. Lorsqu'un appareil n'a pas d'autre information d'identification, son adresse IP, son nom d'hôte ou son adresse MAC est envoyé à la place
  * Noms et descriptions des menaces et des politiques, et noms et descriptions des fuites de données. Dans certains cas, l'adresse email concernée par une fuite est incluse
  * Avec chaque analyse de tâche, un résumé de toutes vos tâches de sécurité en cours, qui peut reprendre les informations ci-dessus
* Lorsque vous demandez un conseil du coach : des scores et des compteurs décrivant votre usage des agents de programmation IA et leur sécurité (par exemple le nombre d'agents non surveillés et de constats actifs), et les noms de leurs compétences, hooks et espaces de travail. Le nom d'un espace de travail est dérivé du chemin de son dossier et peut contenir le nom de votre compte

Les chemins de fichiers contiennent souvent le nom de votre compte, par exemple `/Users/<nom>/...` ou `C:\Users\<nom>\...`. Ce qu'EDAMAME retire des requêtes dépend de sa version :
* Jusqu'à EDAMAME 2.0.2, les chemins de fichiers sont envoyés tels qu'enregistrés, l'identifiant d'instance de l'agent contient le nom d'hôte de cet ordinateur, le compte utilisateur d'une connexion réseau est envoyé sous son nom, et le texte des transcriptions est envoyé tel quel. Il peut contenir tout ce que vous ou l'agent avez écrit, y compris des secrets
* À partir d'EDAMAME 2.0.3, toutes les requêtes listées ci-dessus, sauf les conseils du coach, écrivent la partie d'un chemin qui correspond au dossier personnel sous la forme `~`, par exemple `~/.ssh/id_ed25519` ; le reste du chemin est envoyé tel qu'enregistré, et le nom de votre compte peut encore apparaître en partie dans un nom de dossier de projet qu'un agent IA a dérivé d'un dossier personnel dont le nom contient un tiret ou un point. L'identifiant d'instance de l'agent est remplacé par un pseudonyme qui ne contient pas de nom d'hôte et change à chaque redémarrage d'EDAMAME. Le compte utilisateur d'une connexion réseau n'est envoyé sous son nom que pour les comptes système et de service, comme `root` ou `SYSTEM` ; tout autre compte est envoyé sous la forme `user`. Dans le texte des transcriptions, les commandes et les cibles des appels d'outils, EDAMAME masque avant l'envoi les secrets qu'il reconnaît : clés privées, jetons d'accès et clés d'API dans les formats qu'il connaît, mots de passe inclus dans des adresses web, et valeurs écrites après un nom comme `password`, `token` ou `api_key`. Le reste est envoyé tel quel et peut encore contenir des informations personnelles, ou un secret sous une forme qu'EDAMAME ne reconnaît pas

EDAMAME envoie aussi un enregistrement de notification à votre compte EDAMAME Portal lorsque la protection lève une alerte ou que l'Assistant agit. Cet enregistrement contient le nom d'hôte de cet ordinateur, ses adresses IP publiques, son modèle et la version de son système d'exploitation, les informations de constat listées ci-dessus avec les chemins de fichiers tels qu'enregistrés (ils ne sont pas raccourcis en `~`) et, pour les constats de divergence, l'identifiant d'instance de l'agent, qui contient le nom d'hôte de cet ordinateur, le raisonnement du modèle, les actions effectuées et, pour les rapports de l'Assistant, votre score de sécurité. Les constats de schémas d'attaque et de divergence sont aussi ajoutés à l'historique des constats de votre Portal, avec les mêmes informations.

**Identifiants envoyés à EDAMAME**
* Avec chaque requête : l'identifiant d'appareil EDAMAME de cet appareil, et soit le jeton de connexion de votre compte EDAMAME (vous vous connectez avec votre adresse email, et le jeton identifie votre compte), soit votre clé API EDAMAME
* Lorsque l'application vérifie votre offre Portal : le nom d'hôte de cet ordinateur et le type de son système d'exploitation. Sauf si vous avez renommé l'appareil dans le Portal, le nom d'hôte devient son nom dans votre compte Portal

**Comment EDAMAME traite et conserve ces données**
* Les requêtes sont analysées par Microsoft Azure OpenAI Service, pour le compte d'EDAMAME. Vos identifiants de compte et d'appareil ne lui sont pas transmis
* EDAMAME stocke chaque requête et sa réponse, avec vos identifiants de compte et d'appareil, afin qu'une requête répétée de votre compte ne soit pas analysée deux fois. Ces entrées sont programmées pour expirer 12 heures après leur écriture
* Les enregistrements de notification sont programmés pour expirer 1 jour après leur envoi. Une entrée de l'historique des constats du Portal est programmée pour expirer 90 jours après que cet appareil a signalé les mêmes constats pour la dernière fois
* EDAMAME enregistre la consommation de jetons par compte et par appareil pour appliquer les limites de votre offre. Il examine aussi cette consommation dans des rapports internes qui nomment les comptes par leur adresse email. Avec l'offre gratuite, lorsque votre compte a utilisé 80 % de ses jetons du mois, EDAMAME transmet votre adresse email à son prestataire de prospection par email, Apollo.io, pour vous envoyer des offres de réduction
* Les journaux du service d'EDAMAME enregistrent vos identifiants de compte et d'appareil et le nombre de jetons, ainsi que le texte complet de chaque requête envoyée pour analyse (une requête à laquelle les entrées stockées ci-dessus répondent n'est pas journalisée de nouveau). Aucune expiration n'est configurée pour ces journaux

**Vos choix**
* Désactivez la protection à tout moment avec le bouton de protection de l'écran Sécurité. L'Assistant, les détecteurs, la capture des sessions et la surveillance des fichiers s'arrêtent tous, et EDAMAME n'envoie plus de requêtes de lui-même. Tant que vous restez connecté, une requête est encore envoyée lorsqu'une analyse est demandée explicitement, depuis l'application ou par un agent IA via le serveur MCP d'EDAMAME
* Déconnectez-vous d'EDAMAME Portal dans Config > IA pour cesser toute utilisation du service. Vos jetons de connexion sont stockés sur cet appareil et sont supprimés lors de la déconnexion
* À la place d'EDAMAME Portal, vous pouvez utiliser votre propre fournisseur de modèle dans Config > IA. Les requêtes sont alors envoyées directement à ce fournisseur

Pour plus d'informations sur les pratiques générales de confidentialité d'EDAMAME, consultez notre [Politique de confidentialité](https://www.edamame.tech/privacy).

Si vous n'êtes pas d'accord avec cette politique, ne vous connectez pas au service IA EDAMAME Portal.
