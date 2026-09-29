iOS Politique de Confidentialité du Score Détaillé (FR)
=======================================================

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
  * Profils MDM installés
  * Ecran protégé désactivé
  * Votre appareil est jailbreaké
  * Adresse e-mail potentiellement compromise
  * Environement réseau non vérifié ou non sécurisé
  * Application pas à jour
  * Votre OS n'est pas à jour

**Qui voit ces informations et combien de temps EDAMAME Hub les conserve**
* Les administrateurs du domaine auquel vous êtes connecté voient ces informations dans EDAMAME Hub, et le personnel d'EDAMAME peut les consulter depuis la console d'administration d'EDAMAME
* Si les administrateurs du domaine connectent EDAMAME Hub à d'autres services, comme une plateforme de conformité (Vanta), un fournisseur de contrôle d'accès (par exemple Netskope) ou une organisation GitHub, EDAMAME Hub leur envoie l'état de cet appareil et les informations dont ils ont besoin pour le reconnaître, comme ses adresses IP ou ses identifiants de pairs VPN ou ZTNA
* EDAMAME Hub conserve le dernier rapport de cet appareil sans date d'expiration. Chaque nouveau rapport le remplace, et il est supprimé lorsqu'un administrateur retire l'appareil, lorsque le domaine est supprimé, ou 7 jours après le dernier rapport d'un appareil que le domaine a désactivé
* EDAMAME Hub conserve aussi les rapports précédents pendant 7 jours avec une offre de domaine gratuite et pendant 365 jours avec une offre payante, y compris après la suppression de l'appareil ou du domaine. Ils contiennent l'identifiant de l'appareil, votre nom d'utilisateur, le type de système d'exploitation, le score global et la conformité, le statut de chaque test, les adresses IP publiques et la localisation approximative
* Les journaux du service d'EDAMAME enregistrent les rapports que reçoit EDAMAME Hub. Aucune expiration n'est configurée pour ces journaux
* Lorsque vous certifiez votre score, EDAMAME envoie le rapport par email à l'adresse que vous saisissez et conserve cette adresse. Sauf s'il s'agit d'une adresse edamame.tech, EDAMAME la transmet aussi à son prestataire de prospection par email, Apollo.io, qui peut vous envoyer des emails de suivi. L'équipe d'EDAMAME est avertie de chaque certification dans son espace de travail Slack, avec l'identifiant de l'appareil, le nom d'utilisateur, le système d'exploitation, le score, la ville et le pays, et l'adresse email

En dehors des services nommés dans cette politique, EDAMAME ne partage pas ces informations avec des tiers.

Ces informations sont collectées à l'aide d'un "modèle de menace" public : les tests qu'il exécute, avec leurs scripts, sont publiés aux adresses ci-dessous.

Le modèle de menace peut être consulté à l'adresse [https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-iOS.json](https://github.com/edamametechnologies/threatmodels/blob/main/threatmodel-iOS.json).

Le wiki du modèle de menace peut être consulté à l'adresse [https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-iOS-FR](https://github.com/edamametechnologies/threatmodels/wiki/threatmodel-iOS-FR).

Si vous n'êtes pas d'accord avec cette politique, veuillez ne pas rapporter votre score.
