# Protocole BOOTP (Bootstrap Protocol) - Guide Avancé

**Auteur : Hackers_tchad**  
**Version : 1.0 - Avancé**  
**Date : 2024**

---

## Table des matières

1. [Introduction](#1-introduction)
2. [Définition et concepts fondamentaux](#2-définition-et-concepts-fondamentaux)
3. [Historique et créateurs](#3-historique-et-créateurs)
4. [Importance et rôle de BOOTP](#4-importance-et-rôle-de-bootp)
5. [Architecture et fonctionnement](#5-architecture-et-fonctionnement)
6. [Format du message BOOTP](#6-format-du-message-bootp)
7. [Processus de bootstrap complet](#7-processus-de-bootstrap-complet)
8. [Différences BOOTP vs DHCP](#8-différences-bootp-vs-dhcp)
9. [Configuration détaillée](#9-configuration-détaillée)
10. [Commandes et vérifications](#10-commandes-et-vérifications)
11. [Sécurité et vulnérabilités](#11-sécurité-et-vulnérabilités)
12. [Dépannage avancé](#12-dépannage-avancé)
13. [Implémentations et cas d'usage](#13-implémentations-et-cas-dusage)
14. [Outils d'analyse de paquets](#14-outils-danalyse-de-paquets)
15. [Ressources et livres](#15-ressources-et-livres)
16. [Annexes techniques](#16-annexes-techniques)
17. [Glossaire](#17-glossaire)
18. [Conclusion](#18-conclusion)

---

## 1. Introduction

Le protocole **BOOTP** (Bootstrap Protocol) est un protocole de réseau informatique historique qui a révolutionné la manière dont les stations de travail sans disque (diskless workstations) et les terminaux légers obtiennent leur configuration réseau initiale. Conçu à une époque où les disques durs étaient coûteux et peu fiables, BOOTP a permis à des machines de démarrer directement depuis le réseau, sans nécessiter de stockage local préconfiguré.

Ce guide avancé, rédigé par **Hackers_tchad**, a pour objectif de fournir une compréhension complète, technique et pratique du protocole BOOTP. Que vous soyez administrateur réseau, étudiant en cybersécurité, ingénieur système ou passionné de protocoles réseau, ce document couvre tous les aspects fondamentaux et avancés de BOOTP.

BOOTP est souvent considéré comme l'ancêtre direct du **DHCP** (Dynamic Host Configuration Protocol), qui a hérité de nombreux mécanismes, champs de message et concepts de son prédécesseur. Comprendre BOOTP en profondeur est donc essentiel pour maîtriser DHCP, la configuration automatique des réseaux modernes, et l'histoire des protocoles Internet.

Dans ce README, nous explorerons :
- Les fondements théoriques de BOOTP.
- La structure détaillée de ses messages.
- Son architecture client/serveur.
- Sa configuration sur différentes plateformes.
- Les commandes de vérification et de débogage.
- Les vulnérabilités et contre-mesures.
- Les ressources complémentaires pour approfondir.

Nous fournirons également des exemples concrets, des captures de paquets analysées, des configurations de serveurs, et des scripts de vérification.

---

## 2. Définition et concepts fondamentaux

### 2.1 Qu'est-ce que BOOTP ?

**BOOTP** (Bootstrap Protocol) est un protocole de la couche application du modèle TCP/IP, défini dans la RFC 951 (publiée en septembre 1985) et complété par les RFC 1048, 1084, 1395, 1497, 1532 et 1542. Il utilise les protocoles de transport **UDP** (User Datagram Protocol) avec les ports suivants :
- Port **67/UDP** côté serveur.
- Port **68/UDP** côté client.

BOOTP permet à un client, lors de son démarrage initial (boot), d'obtenir automatiquement :
- Une adresse **IP**.
- Le masque de sous-réseau (**subnet mask**).
- L'adresse de la passerelle par défaut (**default gateway**).
- L'adresse d'un serveur de noms (**DNS** ou anciennement serveur IEN-116).
- Le nom et le chemin d'un fichier de démarrage (**boot file**).
- L'adresse d'un serveur à partir duquel télécharger ce fichier de démarrage (**TFTP server**).

Contrairement à DHCP, BOOTP attribue des adresses **statiques** basées sur l'adresse **MAC** du client. Chaque client doit être préconfiguré manuellement dans la base de données du serveur BOOTP.

### 2.2 Pourquoi utiliser BOOTP ?

À l'origine, BOOTP a été développé pour résoudre plusieurs problèmes :
1. **Postes de travail sans disque** : les stations sans disque dur nécessitent un mécanisme pour découvrir leur identité réseau et télécharger leur système d'exploitation via le réseau.
2. **Déploiement centralisé** : les administrateurs peuvent gérer les configurations réseau et les images de démarrage depuis un serveur central.
3. **Réduction des coûts** : élimine le besoin de disques locaux coûteux sur chaque poste.
4. **Fiabilité** : simplifie la maintenance en centralisant les fichiers système.

### 2.3 Terminologie essentielle

- **BOOTREQUEST** : message envoyé par un client pour demander sa configuration.
- **BOOTREPLY** : message envoyé par un serveur en réponse à une demande.
- **Ciaddr** : client IP address, l'adresse IP du client si elle est connue.
- **Yiaddr** : your IP address, l'adresse IP proposée au client.
- **Siaddr** : server IP address, l'adresse du serveur de boot.
- **Giaddr** : gateway IP address, l'adresse de l'agent relais (relay agent).
- **Chaddr** : client hardware address, l'adresse MAC du client.
- **Sname** : nom du serveur de boot (optionnel).
- **File** : nom du fichier de boot à télécharger (optionnel).
- **Vend** : champ vendor-specific, ancêtre des options DHCP.

### 2.4 Modèle OSI et TCP/IP de BOOTP

Dans le modèle **OSI**, BOOTP opère principalement aux couches 3 (Réseau) et 7 (Application). Dans le modèle **TCP/IP**, il est classé à la couche Application, bien qu'il interagisse étroitement avec IP et UDP.

```
Modèle TCP/IP :
+------------------+
|   Application    |  <-- BOOTP
+------------------+
|     Transport    |  <-- UDP (ports 67/68)
+------------------+
|      Internet    |  <-- IP
+------------------+
|   Accès réseau   |  <-- Ethernet, Wi-Fi
+------------------+
```

### 2.5 Composants d'un environnement BOOTP

Un déploiement BOOTP typique comprend :
1. **Client BOOTP** : machine sans disque ou nécessitant une configuration initiale.
2. **Serveur BOOTP** : héberge la base de données d'adresses MAC et de configurations.
3. **Serveur TFTP** : fournit le fichier de boot (souvent le même serveur que BOOTP).
4. **Agent relais BOOTP** : transmet les requêtes BOOTP entre sous-réseaux.

---

## 3. Historique et créateurs

### 3.1 Contexte historique

Dans les années 1980, les réseaux informatiques commençaient à se démocratiser dans les universités, les centres de recherche et les entreprises. Cependant, la configuration manuelle de chaque poste de travail était fastidieuse et source d'erreurs. De plus, les disques durs étaient chers, bruyants, gourmands en énergie et sujets aux pannes mécaniques.

L'idée de stations de travail sans disque dur (diskless workstations) est apparue comme une solution économique et fiable. Ces machines devaient pouvoir démarrer depuis le réseau, mais pour cela, elles avaient besoin d'un mécanisme standardisé pour obtenir leur configuration IP et localiser leur image système.

### 3.2 Créateurs et auteurs de la RFC 951

Le protocole BOOTP a été formalisé dans la **RFC 951**, publiée en septembre 1985, par :
- **Bill Croft** (Stanford University)
- **John Gilmore** (Sun Microsystems)
- **Rajiv D. Satija** (contribuant également à l'époque)

Ces auteurs ont conçu BOOTP comme un successeur amélioré du protocole **RARP** (Reverse Address Resolution Protocol, RFC 903). RARP permettait déjà à une machine de découvrir son adresse IP à partir de son adresse MAC, mais il était limité :
- Il ne fournissait que l'adresse IP.
- Il nécessitait une diffusion au niveau de la couche liaison de données (broadcast Ethernet).
- Il ne pouvait pas traverser les routeurs.
- Il ne fournissait aucune information sur le serveur de boot ou le fichier de boot.

BOOTP a résolu ces limitations en utilisant IP/UDP et en fournissant des informations de configuration complètes.

### 3.3 Évolution vers DHCP

En 1993, le **DHCP** (Dynamic Host Configuration Protocol) a été introduit dans la RFC 2131 (et RFC 2132 pour les options) comme une extension de BOOTP. DHCP a conservé :
- Le même format de message de base.
- Les mêmes ports UDP (67 et 68).
- La compatibilité descendante avec les clients BOOTP.
- Le mécanisme des options (anciennement champ vendor-specific).

Les principales améliorations apportées par DHCP :
- Attribution dynamique des adresses IP avec bail temporaire (lease).
- Renouvellement automatique des baux.
- Attribution d'adresses par pools, sans configuration manuelle par MAC.
- Options plus riches et extensibles.

Aujourd'hui, DHCP a largement remplacé BOOTP dans la plupart des réseaux, mais BOOTP reste pertinent pour comprendre les fondements du boot réseau et pour certains environnements legacy (hérités).

### 3.4 Frise chronologique

```
1984  : RFC 903 - RARP (prédécesseur de BOOTP)
1985  : RFC 951 - BOOTP (Bootstrap Protocol)
1988  : RFC 1048 - BOOTP vendor information extensions
1989  : RFC 1084 - Obsoletes RFC 1048
1992  : RFC 1395 - BOOTP vendor information extensions update
1993  : RFC 1497 - BOOTP vendor extensions and vendor-specific information
1993  : RFC 1532 / 1542 - Interoperation Between DHCP and BOOTP
1997  : RFC 2131 - DHCP (Dynamic Host Configuration Protocol)
1997  : RFC 2132 - DHCP Options and BOOTP Vendor Extensions
```

---

## 4. Importance et rôle de BOOTP

### 4.1 Importance historique

BOOTP représente une étape cruciale dans l'évolution des réseaux TCP/IP. Il a été le premier protocole largement adopté à permettre le démarrage automatique et centralisé des postes de travail. Son importance réside dans plusieurs aspects :

1. **Fondation de DHCP** : sans BOOTP, DHCP n'aurait probablement pas eu la même structure. Les options DHCP sont directement héritées du champ vendor-specific de BOOTP.
2. **Boot réseau** : BOOTP a rendu possible le démarrage réseau (Netboot/PXE), encore utilisé aujourd'hui dans les datacenters, les salles de classe et les entreprises.
3. **Standardisation** : il a établi un format standard de message pour l'attribution d'adresses et la configuration initiale.
4. **Interopérabilité** : BOOTP a permis à des équipements de différents fabricants de démarrer depuis le réseau de manière uniforme.

### 4.2 Rôle dans un réseau moderne

Bien que DHCP domine, BOOTP conserve un rôle dans certains scénarios :
- **Équipements embarqués** : imprimantes réseau, terminaux de point de vente, équipements industriels.
- **Systèmes legacy** : anciens Unix, stations de travail Sun Microsystems, terminaux X.
- **Environnements de test et de laboratoire** : pour étudier les protocoles réseau historiques.
- **PXE (Preboot Execution Environment)** : bien que PXE utilise DHCP, il hérite conceptuellement de BOOTP.
- **Routeurs et commutateurs** : certains équipements réseau utilisent encore BOOTP pour obtenir leur configuration initiale.

### 4.3 Avantages de BOOTP

- **Simplicité** : protocole simple, facile à comprendre et à implémenter.
- **Fiabilité** : attribution statique garantit que chaque client reçoit toujours la même adresse IP.
- **Prévisibilité** : idéal pour les environnements où les adresses IP doivent rester constantes.
- **Compatibilité** : les serveurs DHCP modernes peuvent généralement répondre aux clients BOOTP.
- **Légèreté** : faible charge réseau, car aucun renouvellement de bail n'est nécessaire.

### 4.4 Inconvénients de BOOTP

- **Configuration manuelle** : chaque client doit être enregistré manuellement dans la base de données du serveur.
- **Pas de bail temporaire** : les adresses sont attribuées de manière permanente, ce qui peut gaspiller des adresses IP.
- **Moins flexible que DHCP** : pas de pools dynamiques, pas de réservations temporaires.
- **Sécurité limitée** : aucune authentification des messages, vulnérable aux attaques par usurpation.
- **Maintenance lourde** : dans les grands réseaux, gérer manuellement les adresses MAC devient rapidement complexe.

### 4.5 Pertinence pour la cybersécurité

Comprendre BOOTP est essentiel pour la cybersécurité réseau :
- **Analyse de paquets** : identifier les requêtes BOOTP dans les captures réseau.
- **Attaques** : détecter les serveurs BOOTP/DHCP malveillants (rogue DHCP).
- **Forensique** : corréler les adresses MAC et IP attribuées.
- **Hardening** : sécuriser les segments réseau où le boot réseau est activé.

---

## 5. Architecture et fonctionnement

### 5.1 Architecture client/serveur

BOOTP utilise une architecture **client/serveur** simple. Le client initie le processus en envoyant une diffusion (broadcast) sur le réseau local. Le serveur BOOTP, en écoute sur le port UDP 67, reçoit la requête, consulte sa base de données, et répond au client sur le port UDP 68.

```
+-----------+         Broadcast UDP 67          +-----------+
|  Client   |  --------------------------------> |  Serveur  |
|   BOOTP   |                                      |   BOOTP   |
| (port 68) |  <--------------------------------  | (port 67) |
+-----------+         Unicast/Broadcast UDP 68    +-----------+
```

### 5.2 Rôle de l'agent relais (Relay Agent)

Comme les requêtes BOOTP initiales sont des broadcasts, elles ne traversent pas les routeurs par défaut. Pour permettre le boot réseau dans des sous-réseaux distants, on utilise un **agent relais BOOTP** (BOOTP relay agent).

L'agent relais :
- Écoute les broadcasts BOOTP sur son sous-réseau local.
- Encapsule la requête dans un paquet unicast vers le serveur BOOTP distant.
- Insère son propre adresse IP dans le champ **Giaddr**.
- Retransmet la réponse du serveur au client.

Cela permet de centraliser un seul serveur BOOTP pour plusieurs sous-réseaux.

### 5.3 Flux de communication typique

```
1. Client démarre sans adresse IP connue.
2. Client envoie BOOTREQUEST en broadcast (255.255.255.255) avec IP source 0.0.0.0.
3. Serveur BOOTP reçoit la requête, consulte sa base de données.
4. Serveur envoie BOOTREPLY contenant l'adresse IP, le masque, la gateway, etc.
5. Client reçoit la réponse et configure son interface réseau.
6. Client contacte le serveur TFTP indiqué pour télécharger le fichier de boot.
7. Client exécute le fichier de boot et charge son système d'exploitation.
```

### 5.4 Interactions avec d'autres protocoles

BOOTP ne fonctionne pas isolément. Il s'appuie sur plusieurs autres protocoles :
- **UDP** : transport des messages BOOTP.
- **IP** : adressage des paquets.
- **Ethernet** : diffusion au niveau de la couche liaison.
- **TFTP** : téléchargement du fichier de boot (RFC 1350).
- **ARP** : résolution d'adresses après attribution de l'IP.
- **DNS** : résolution de noms si configuré via BOOTP.

### 5.5 Topologies courantes

#### Topologie simple (un seul sous-réseau)

```
[Client BOOTP] ---- [Switch] ---- [Serveur BOOTP + TFTP]
```

#### Topologie avec agent relais

```
[Client BOOTP] ---- [Routeur/Relay Agent] ---- [Réseau backbone] ---- [Serveur BOOTP + TFTP]
```

#### Topologie multi-sous-réseaux

```
[Client A] -- [Switch A] -- [Routeur A avec relay agent] --+
                                                          |
[Client B] -- [Switch B] -- [Routeur B avec relay agent] --+-- [Serveur BOOTP central]
                                                          |
[Client C] -- [Switch C] -- [Routeur C avec relay agent] --+
```

---

## 6. Format du message BOOTP

### 6.1 Structure du paquet BOOTP

Le message BOOTP a une taille fixe de **300 octets** minimum, définie dans la RFC 951. La structure est la suivante :

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            xid (4)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          secs (2)             |           flags (2)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           ciaddr (4)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           yiaddr (4)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           siaddr (4)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           giaddr (4)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                           chaddr (16)                           |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                           sname (64)                            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                           file (128)                            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                           vend (64)                             |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 6.2 Description détaillée des champs

#### 6.2.1 op (1 octet) - Opcode

Indique le type de message BOOTP.
- **1** = BOOTREQUEST (requête du client).
- **2** = BOOTREPLY (réponse du serveur).

Ce champ est essentiel pour différencier une demande d'une réponse.

#### 6.2.2 htype (1 octet) - Hardware Type

Type de matériel réseau du client, utilisant les codes ARP.
- **1** = Ethernet (10 Mb).
- **6** = IEEE 802 Networks.
- **7** = ARCNET.
- **11** = LocalTalk.
- **15** = Frame Relay.
- **17** = HDLC.
- **18** = Fibre Channel.
- **20** = Serial Line.

Pour la grande majorité des réseaux modernes, **htype = 1** (Ethernet).

#### 6.2.3 hlen (1 octet) - Hardware Address Length

Longueur de l'adresse matérielle en octets.
- **6** pour les adresses MAC Ethernet.
- Autres valeurs selon le type de matériel.

#### 6.2.4 hops (1 octet)

Compteur de sauts utilisé par les agents relais. Le client le met à 0. Chaque agent relais qui traite le message peut l'incrémenter pour éviter les boucles.

#### 6.2.5 xid (4 octets) - Transaction ID

Identifiant de transaction généré aléatoirement par le client. Permet au client de reconnaître la réponse correspondant à sa requête, car plusieurs clients peuvent émettre simultanément.

#### 6.2.6 secs (2 octets) - Seconds Elapsed

Nombre de secondes écoulées depuis que le client a commencé son processus de boot. Utile pour les serveurs qui doivent prioriser les requêtes.

#### 6.2.7 flags (2 octets)

Champ de flags introduit par la compatibilité DHCP. Le bit de poids fort (0x8000) indique si le client accepte les réponses en broadcast (1) ou si le serveur peut répondre en unicast (0).

Dans BOOTP pur, ce champ est généralement à 0.

#### 6.2.8 ciaddr (4 octets) - Client IP Address

Adresse IP du client si elle est déjà connue. Dans la plupart des cas, lors d'une première requête, ce champ est **0.0.0.0** car le client n'a pas encore d'adresse IP.

#### 6.2.9 yiaddr (4 octets) - Your IP Address

Adresse IP que le serveur attribue au client. C'est le champ le plus important dans une réponse BOOTP.

#### 6.2.10 siaddr (4 octets) - Server IP Address

Adresse IP du serveur de boot (souvent le serveur TFTP) à contacter pour télécharger le fichier de boot.

#### 6.2.11 giaddr (4 octets) - Gateway IP Address

Adresse IP de l'agent relais BOOTP. Si ce champ est non nul, le serveur sait que la requête provient d'un autre sous-réseau et doit répondre via cet agent relais.

#### 6.2.12 chaddr (16 octets) - Client Hardware Address

Adresse matérielle du client (adresse MAC). Le serveur BOOTP utilise ce champ pour identifier le client dans sa base de données. Les octets non utilisés sont mis à zéro.

#### 6.2.13 sname (64 octets) - Server Name

Nom du serveur de boot (optionnel, terminé par un octet nul). Peut être utilisé à la place de siaddr si le client doit résoudre le nom.

#### 6.2.14 file (128 octets) - Boot File Name

Nom du fichier de boot à télécharger (terminé par un octet nul). Par exemple : `/tftpboot/pxelinux.0` ou `unix-kernel`. Ce fichier est généralement téléchargé via TFTP.

#### 6.2.15 vend (64 octets) - Vendor-Specific Area

Champ réservé aux extensions spécifiques au fabricant. Dans les versions ultérieures de BOOTP (RFC 1048, 1497), ce champ a été standardisé pour transporter des **options BOOTP**, qui sont les ancêtres directs des options DHCP.

La première implémentation de BOOTP (RFC 951) spécifiait ce champ comme une zone opaque. La RFC 1048 a défini un format structuré avec un "magic cookie" suivi d'options TLV (Type-Length-Value).

### 6.3 Extensions BOOTP / Vendor-Specific Area

Le champ vend de 64 octets contient :
- **Magic Cookie** (4 octets) : valeur `0x63 0x82 0x53 0x63` (soit 99.130.83.99 en décimal).
- **Options** : liste d'options au format TLV.
- **Option 255** : marqueur de fin.

Format TLV d'une option :
- **Type** (1 octet) : numéro de l'option.
- **Length** (1 octet) : longueur de la valeur.
- **Value** (variable) : données de l'option.

### 6.4 Options BOOTP courantes

| Code | Nom | Description |
|------|-----|-------------|
| 1 | Subnet Mask | Masque de sous-réseau |
| 3 | Router | Passerelle(s) par défaut |
| 6 | Domain Name Server | Serveurs DNS |
| 12 | Host Name | Nom d'hôte du client |
| 15 | Domain Name | Nom de domaine |
| 17 | Root Path | Chemin racine du système de fichiers réseau |
| 28 | Broadcast Address | Adresse de diffusion du sous-réseau |
| 40 | NIS Domain | Domaine NIS |
| 42 | NTP Servers | Serveurs de temps NTP |
| 50 | Requested IP Address | Adresse IP demandée (hérité par DHCP) |
| 53 | DHCP Message Type | Type de message DHCP (non utilisé en BOOTP pur) |
| 55 | Parameter Request List | Liste des options demandées |
| 255 | End | Fin des options |

### 6.5 Exemple de paquet BOOTP capturé (représentation textuelle)

```
Bootstrap Protocol (Request)
    Message type: Boot Request (1)
    Hardware type: Ethernet (0x01)
    Hardware address length: 6
    Hops: 0
    Transaction ID: 0x3d1d0000
    Seconds elapsed: 0
    Bootp flags: 0x0000 (Unicast)
    Client IP address: 0.0.0.0
    Your (client) IP address: 0.0.0.0
    Next server IP address: 0.0.0.0
    Relay agent IP address: 0.0.0.0
    Client MAC address: 00:11:22:33:44:55
    Client hardware address padding: 00000000000000000000
    Server host name not given
    Boot file name not given
    Magic cookie: DHCP
    Option: (53) DHCP Message Type: Discover
    Option: (55) Parameter Request List
```

Note : dans Wireshark, BOOTP et DHCP partagent souvent le même dissecteur car ils sont très similaires.

---

## 7. Processus de bootstrap complet

### 7.1 Étapes du démarrage d'un client BOOTP

#### Étape 1 : Initialisation du matériel

Lors de la mise sous tension, le client exécute son **firmware** (BIOS, UEFI, ROM réseau). Ce firmware initialise la carte réseau et charge un petit programme client BOOTP.

#### Étape 2 : Envoi de la requête BOOTREQUEST

Le client crée un message BOOTREQUEST avec :
- `op` = 1
- `htype` = 1 (Ethernet)
- `hlen` = 6
- `hops` = 0
- `xid` = valeur aléatoire
- `secs` = 0
- `ciaddr` = 0.0.0.0 (si l'adresse est inconnue)
- `chaddr` = adresse MAC du client
- `file` = nom du fichier de boot souhaité (optionnel)

Le paquet est encapsulé dans UDP avec :
- Port source = 68
- Port destination = 67
- Adresse IP source = 0.0.0.0
- Adresse IP destination = 255.255.255.255 (broadcast)

Il est ensuite envoyé sur le réseau local.

#### Étape 3 : Réception par le serveur BOOTP

Le serveur BOOTP écoute sur le port UDP 67. Lorsqu'il reçoit une requête :
1. Il extrait l'adresse MAC du client (`chaddr`).
2. Il consulte sa base de données (`/etc/bootptab` sur Unix, ou configuration du serveur).
3. Il trouve l'entrée correspondant à cette adresse MAC.
4. Il prépare un message BOOTREPLY avec les informations de configuration.

#### Étape 4 : Envoi de la réponse BOOTREPLY

Le serveur envoie une réponse avec :
- `op` = 2
- `xid` = identique à celui de la requête
- `yiaddr` = adresse IP attribuée au client
- `siaddr` = adresse du serveur de boot/TFTP
- `file` = chemin du fichier de boot
- Options : masque de sous-réseau, passerelle, DNS, etc.

La réponse peut être envoyée :
- En **broadcast** si le client ne peut pas encore recevoir d'unicast.
- En **unicast** si le matériel réseau du client le permet.

#### Étape 5 : Configuration du client

Le client reçoit la réponse, vérifie le `xid`, et extrait :
- Son adresse IP (`yiaddr`).
- Le masque de sous-réseau.
- La passerelle par défaut.
- Les serveurs DNS.
- L'adresse du serveur TFTP (`siaddr`).
- Le nom du fichier de boot (`file`).

Il configure alors son interface réseau avec ces paramètres.

#### Étape 6 : Téléchargement du fichier de boot

Le client contacte le serveur TFTP spécifié par `siaddr` et demande le fichier indiqué par `file`. Le téléchargement se fait généralement via le protocole **TFTP** (port UDP 69).

Exemple de fichier de boot :
- `pxelinux.0` pour les environnements PXE.
- `vmlinuz` pour un noyau Linux.
- Un système d'exploitation complet pour un terminal sans disque.

#### Étape 7 : Exécution du système d'exploitation

Une fois le fichier de boot téléchargé en mémoire, le client l'exécute. Cela peut charger un noyau, monter un système de fichiers réseau (NFS), ou lancer directement un environnement de travail.

### 7.2 Gestion des retransmissions

Si le client ne reçoit pas de réponse dans un délai donné, il renvoie la requête BOOTREQUEST. Le délai entre les retransmissions augmente généralement de manière exponentielle pour éviter la saturation du réseau.

Typiquement :
- 1ère retransmission après 4 secondes.
- 2ème après 8 secondes.
- 3ème après 16 secondes.
- Puis toutes les 20-30 secondes.

Le client peut également doubler le délai de manière exponentielle jusqu'à une limite maximale.

### 7.3 Scénario avec agent relais

Lorsqu'un client se trouve dans un sous-réseau différent de celui du serveur BOOTP :

1. Le client envoie un BOOTREQUEST en broadcast local.
2. L'agent relais sur le routeur local intercepte le broadcast.
3. L'agent relais met à jour le champ `giaddr` avec son adresse IP.
4. Il incrémente éventuellement le champ `hops`.
5. Il transmet la requête en unicast au serveur BOOTP.
6. Le serveur consulte sa base de données et envoie la réponse à l'agent relais (`giaddr`).
7. L'agent relais transmet la réponse au client sur son sous-réseau local.

### 7.4 Diagramme de séquence complet

```
Client          Réseau local          Agent relais        Serveur BOOTP      Serveur TFTP
  |                    |                    |                    |                |
  |---- BOOTREQUEST --->|                    |                    |                |
  |   (broadcast)       |                    |                    |                |
  |                    |---- BOOTREQUEST --->|                    |                |
  |                    |   (broadcast)       |---- BOOTREQUEST --->|                |
  |                    |                    |   (unicast, giaddr) |                |
  |                    |                    |<---- BOOTREPLY -----|                |
  |                    |<---- BOOTREPLY ----|                    |                |
  |<---- BOOTREPLY ----|                    |                    |                |
  |   (broadcast)       |                    |                    |                |
  |                                                                               |
  |--------------------------------- TFTP Read Request -------------------------->|
  |                                                                               |
  |<---------------------------------- Fichier de boot ---------------------------|
```

---

## 8. Différences BOOTP vs DHCP

### 8.1 Tableau comparatif détaillé

| Caractéristique | BOOTP | DHCP |
|-----------------|-------|------|
| RFC principale | RFC 951 | RFC 2131 |
| Ports UDP | 67 (serveur), 68 (client) | 67 (serveur), 68 (client) |
| Attribution d'adresses | Statique, par adresse MAC | Statique (reservations) ou dynamique (pools) |
| Bail (lease) | Non, attribution permanente | Oui, durée limitée avec renouvellement |
| Configuration manuelle | Oui, chaque client doit être enregistré | Optionnelle pour les attributions dynamiques |
| Options | 64 octets (vendor-specific) | Options très étendues |
| Renouvellement | Non | Oui, à 50% et 87.5% du bail |
| Compatibilité | Serveur DHCP peut répondre aux clients BOOTP | Clients DHCP ne peuvent pas utiliser un serveur BOOTP pur |
| Complexité | Simple | Plus complexe |
| Utilisation actuelle | Legacy, environnements spécifiques | Universelle |

### 8.2 Pourquoi DHCP a remplacé BOOTP

1. **Flexibilité** : DHCP permet d'attribuer des adresses dynamiquement à partir d'un pool, sans enregistrer chaque client.
2. **Gestion des baux** : les adresses peuvent être récupérées automatiquement lorsqu'elles ne sont plus utilisées.
3. **Mobilité** : les ordinateurs portables peuvent obtenir une adresse sur n'importe quel réseau.
4. **Options riches** : DHCP supporte des centaines d'options (PXE, NTP, WPAD, etc.).
5. **Interopérabilité** : DHCP intègre la compatibilité BOOTP, permettant une migration progressive.

### 8.3 Quand utiliser BOOTP aujourd'hui

Bien que DHCP soit dominant, BOOTP reste utile dans certains cas :
- Équipements nécessitant une adresse IP fixe et prévisible.
- Environnements sans lease (baux) où la durée de vie des adresses est infinie.
- Systèmes d'exploitation anciens ou firmware embarqué ne supportant que BOOTP.
- Formation académique et recherche sur les protocoles historiques.

---

## 9. Configuration détaillée

### 9.1 Configuration d'un serveur BOOTP sur Linux

Sur les systèmes Linux traditionnels, le serveur BOOTP peut être configuré via le fichier `/etc/bootptab`.

#### 9.1.1 Installation du serveur bootpd

Sur Debian/Ubuntu :
```bash
sudo apt-get update
sudo apt-get install bootp
```

Sur RHEL/CentOS/Fedora :
```bash
sudo yum install bootp
# ou
sudo dnf install bootp
```

#### 9.1.2 Structure du fichier /etc/bootptab

Le fichier `/etc/bootptab` contient :
- Des entrées globales (paramètres par défaut).
- Des entrées par client (identifiées par adresse MAC ou nom).

Syntaxe générale :
```
%%
# Entrées globales
:sm=255.255.255.0:\
:gw=192.168.1.1:\
:dns=192.168.1.2:\
:hn:\
:vm=rfc1048:\
:bf=/tftpboot/pxelinux.0:

# Entrées par client
client1:ha=000c29a1b2c3:ip=192.168.1.101:bf=/tftpboot/client1.img
client2:ha=000c29a1b2c4:ip=192.168.1.102:bf=/tftpboot/client2.img
```

#### 9.1.3 Explication des tags /etc/bootptab

| Tag | Signification | Exemple |
|-----|---------------|---------|
| `sm` | Subnet Mask | `:sm=255.255.255.0:` |
| `gw` | Default Gateway | `:gw=192.168.1.1:` |
| `dns` | DNS Server | `:dns=192.168.1.2:` |
| `hn` | Send Hostname | `:hn:` |
| `bf` | Boot File | `:bf=/tftpboot/pxelinux.0:` |
| `bs` | Boot File Size | `:bs=1024:` |
| `ds` | Domain Name Server (ancien) | `:ds=192.168.1.2:` |
| `hd` | Home Directory for boot files | `:hd=/tftpboot:` |
| `ha` | Hardware Address (MAC) | `:ha=000c29a1b2c3:` |
| `ip` | IP Address | `:ip=192.168.1.101:` |
| `vm` | Vendor Magic Cookie | `:vm=rfc1048:` |
| `ns` | Name Server | `:ns=192.168.1.2:` |
| `nt` | NTP Server | `:nt=192.168.1.3:` |
| `ra` | Relay Agent Address | `:ra=192.168.2.1:` |
| `rp` | Root Path | `:rp=/nfsroot/client1:` |
| `sa` | Server Address (TFTP) | `:sa=192.168.1.10:` |
| `td` | TFTP Directory | `:td=/tftpboot:` |
| `to` | Time Offset | `:to=3600:` |
| `ts` | Time Server | `:ts=192.168.1.3:` |

#### 9.1.4 Exemple complet de /etc/bootptab

```
# /etc/bootptab - Configuration BOOTP avancée
# Auteur: Hackers_tchad
# Date: 2024

%%
# Paramètres globaux par défaut
:sm=255.255.255.0:\
:gw=192.168.1.1:\
:dns=192.168.1.2,192.168.1.3:\
:ns=192.168.1.2:\
:nt=192.168.1.10:\
:ts=192.168.1.10:\
:domain=hackers-tchad.local:\
:hn:\
:vm=rfc1048:\
:hd=/tftpboot:\
:bf=pxelinux.0:\
:rp=/nfsroot:\
:to=0:

# Stations de travail sans disque
station01:ha=00:11:22:33:44:55:ip=192.168.1.101:bf=station01/pxelinux.0:rp=/nfsroot/station01
station02:ha=00:11:22:33:44:56:ip=192.168.1.102:bf=station02/pxelinux.0:rp=/nfsroot/station02
station03:ha=00:11:22:33:44:57:ip=192.168.1.103:bf=station03/pxelinux.0:rp=/nfsroot/station03

# Imprimantes réseau
printer01:ha=00:11:22:33:44:66:ip=192.168.1.201:bf=printer01/firmware.bin
printer02:ha=00:11:22:33:44:67:ip=192.168.1.202:bf=printer02/firmware.bin

# Routeurs/Équipements embarqués
router01:ha=00:11:22:33:44:77:ip=192.168.1.254:bf=router01/config.bin
```

#### 9.1.5 Démarrage du serveur bootpd

Mode standalone :
```bash
sudo bootpd -s
```

Mode inetd/xinetd (historique) :
```
# /etc/inetd.conf
bootps  dgram  udp  wait  root  /usr/sbin/bootpd  bootpd
```

Puis recharger inetd :
```bash
sudo systemctl reload inetd
```

### 9.2 Configuration avec DHCP en mode BOOTP compatible

La plupart des serveurs DHCP modernes (ISC DHCP, dnsmasq) peuvent répondre aux clients BOOTP.

#### 9.2.1 ISC DHCP Server

```dhcpd.conf
# /etc/dhcp/dhcpd.conf

option domain-name "hackers-tchad.local";
option domain-name-servers 192.168.1.2, 192.168.1.3;
option routers 192.168.1.1;
option subnet-mask 255.255.255.0;

subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.100 192.168.1.200;
    next-server 192.168.1.10;        # Serveur TFTP (siaddr)
    filename "pxelinux.0";            # Fichier de boot
}

# Réservation BOOTP par adresse MAC (équivalent BOOTP statique)
host station01 {
    hardware ethernet 00:11:22:33:44:55;
    fixed-address 192.168.1.101;
    filename "station01/pxelinux.0";
    option host-name "station01";
}

host station02 {
    hardware ethernet 00:11:22:33:44:56;
    fixed-address 192.168.1.102;
    filename "station02/pxelinux.0";
    option host-name "station02";
}
```

Démarrage :
```bash
sudo systemctl enable isc-dhcp-server
sudo systemctl start isc-dhcp-server
```

#### 9.2.2 dnsmasq

```
# /etc/dnsmasq.conf

interface=eth0
domain=hackers-tchad.local
dhcp-range=192.168.1.100,192.168.1.200,255.255.255.0,1h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.2,192.168.1.3
dhcp-boot=pxelinux.0,boothost,192.168.1.10

# Réservations BOOTP statiques
dhcp-host=00:11:22:33:44:55,station01,192.168.1.101,infinite
dhcp-host=00:11:22:33:44:56,station02,192.168.1.102,infinite
```

### 9.3 Configuration d'un agent relais BOOTP

#### 9.3.1 Sur un routeur Cisco

```cisco
! Configuration de l'agent relais DHCP/BOOTP sur une interface
interface GigabitEthernet0/1
 ip address 192.168.2.1 255.255.255.0
 ip helper-address 192.168.1.10
!
```

#### 9.3.2 Sur Linux avec dhcrelay

```bash
# Installation
sudo apt-get install isc-dhcp-relay

# Configuration
sudo dhcrelay -i eth1 192.168.1.10
```

Le fichier `/etc/default/isc-dhcp-relay` :
```
SERVERS="192.168.1.10"
INTERFACES="eth1"
OPTIONS=""
```

### 9.4 Configuration du serveur TFTP

BOOTP s'appuie souvent sur TFTP pour fournir le fichier de boot.

#### 9.4.1 Installation de tftpd-hpa

```bash
sudo apt-get install tftpd-hpa
```

#### 9.4.2 Configuration /etc/default/tftpd-hpa

```bash
TFTP_USERNAME="tftp"
TFTP_DIRECTORY="/tftpboot"
TFTP_ADDRESS="0.0.0.0:69"
TFTP_OPTIONS="--secure --create"
```

#### 9.4.3 Préparation du répertoire /tftpboot

```bash
sudo mkdir -p /tftpboot
sudo chown -R tftp:tftp /tftpboot
sudo chmod -R 755 /tftpboot

# Copie des fichiers de boot
sudo cp /usr/lib/PXELINUX/pxelinux.0 /tftpboot/
sudo mkdir -p /tftpboot/pxelinux.cfg
```

#### 9.4.4 Démarrage de TFTP

```bash
sudo systemctl enable tftpd-hpa
sudo systemctl start tftpd-hpa
```

### 9.5 Configuration client BOOTP

#### 9.5.1 Activation du boot réseau dans le BIOS/UEFI

1. Accéder au BIOS/UEFI (généralement F2, F10, F12, Del).
2. Activer **PXE Boot** ou **Network Boot**.
3. Définir le boot réseau comme priorité de démarrage.
4. Sauvegarder et redémarrer.

#### 9.5.2 Configuration sous Linux avec bootpc

```bash
# Installation
sudo apt-get install bootpc

# Demander une configuration BOOTP
sudo bootpc -h 00:11:22:33:44:55 -i eth0
```

---

## 10. Commandes et vérifications

### 10.1 Vérification du serveur BOOTP

#### 10.1.1 Vérifier que le processus écoute sur le port 67

```bash
sudo ss -ulnp | grep 67
# ou
sudo netstat -ulnp | grep 67
```

Sortie attendue :
```
UNCONN  0  0  0.0.0.0:bootps  0.0.0.0:*  users:(("bootpd",pid=1234,fd=3))
```

#### 10.1.2 Vérifier le fichier de configuration

```bash
sudo bootpd -d 5 -c /etc/bootptab
```

#### 10.1.3 Tester la réponse BOOTP avec un client

```bash
sudo bootptest -i eth0 00:11:22:33:44:55
```

### 10.2 Capture et analyse de paquets BOOTP

#### 10.2.1 Capture avec tcpdump

```bash
# Capture des paquets BOOTP/DHCP
sudo tcpdump -i eth0 -n -vvv port 67 or port 68

# Sauvegarde dans un fichier
sudo tcpdump -i eth0 -w bootp_capture.pcap port 67 or port 68
```

#### 10.2.2 Analyse avec Wireshark

Ouvrir le fichier `.pcap` dans Wireshark et appliquer le filtre :
```
bootp
```

ou
```
udp.port == 67 || udp.port == 68
```

### 10.3 Commandes de vérification côté client

#### 10.3.1 Vérifier l'adresse IP obtenue

```bash
ip addr show eth0
# ou
ifconfig eth0
```

#### 10.3.2 Vérifier la route par défaut

```bash
ip route show
# ou
route -n
```

#### 10.3.3 Tester la connectivité

```bash
ping 192.168.1.1
ping 8.8.8.8
```

### 10.4 Commandes avancées de débogage

#### 10.4.1 Activer le mode debug de bootpd

```bash
sudo bootpd -d 99 -s
```

#### 10.4.2 Surveiller les logs système

```bash
sudo journalctl -u bootpd -f
# ou
sudo tail -f /var/log/syslog | grep -i bootp
```

#### 10.4.3 Vérifier les réservations avec ISC DHCP

```bash
sudo dhcp-lease-list
# ou
sudo cat /var/lib/dhcp/dhcpd.leases
```

### 10.5 Scripts de vérification automatisés

#### 10.5.1 Script Bash de vérification du serveur BOOTP

```bash
#!/bin/bash
# check_bootp.sh - Vérification avancée du serveur BOOTP
# Auteur: Hackers_tchad

BOOTP_SERVER="192.168.1.10"
CLIENT_MAC="00:11:22:33:44:55"
INTERFACE="eth0"

echo "=== Vérification du serveur BOOTP ==="
echo "Date: $(date)"
echo ""

echo "[1] Processus écoutant sur le port 67:"
ss -ulnp | grep ':bootps' || echo "ERREUR: Aucun service sur le port 67"
echo ""

echo "[2] Fichier de configuration /etc/bootptab:"
if [ -f /etc/bootptab ]; then
    echo "OK: /etc/bootptab existe"
    grep -c "^[^#]" /etc/bootptab || true
else
    echo "ERREUR: /etc/bootptab introuvable"
fi
echo ""

echo "[3] Test de réponse BOOTP pour MAC $CLIENT_MAC:"
bootptest -i "$INTERFACE" "$CLIENT_MAC" 2>/dev/null || echo "ERREUR: Pas de réponse BOOTP"
echo ""

echo "[4] Vérification du serveur TFTP:"
ss -ulnp | grep ':tftp' || echo "ERREUR: Aucun service TFTP"
echo ""

echo "[5] Fichiers de boot disponibles dans /tftpboot:"
ls -la /tftpboot/ 2>/dev/null || echo "ERREUR: Répertoire /tftpboot inaccessible"
echo ""

echo "=== Fin de la vérification ==="
```

#### 10.5.2 Script Python d'analyse de capture BOOTP

```python
#!/usr/bin/env python3
"""
analyze_bootp.py - Analyse basique de captures BOOTP avec scapy
Auteur: Hackers_tchad
"""

from scapy.all import rdpcap, BOOTP, DHCP
import sys

def analyze_bootp(pcap_file):
    packets = rdpcap(pcap_file)
    print(f"Nombre total de paquets: {len(packets)}")
    
    bootp_count = 0
    for pkt in packets:
        if pkt.haslayer(BOOTP):
            bootp_count += 1
            bootp = pkt[BOOTP]
            print(f"\n--- Paquet BOOTP #{bootp_count} ---")
            print(f"  Opcode: {'REQUEST' if bootp.op == 1 else 'REPLY' if bootp.op == 2 else bootp.op}")
            print(f"  Hardware Type: {bootp.htype}")
            print(f"  Hardware Len: {bootp.hlen}")
            print(f"  Transaction ID: {hex(bootp.xid)}")
            print(f"  Client MAC: {bootp.chaddr[:6].hex(':')}")
            print(f"  Client IP (ciaddr): {bootp.ciaddr}")
            print(f"  Your IP (yiaddr): {bootp.yiaddr}")
            print(f"  Server IP (siaddr): {bootp.siaddr}")
            print(f"  Gateway IP (giaddr): {bootp.giaddr}")
            print(f"  Boot File: {bootp.file.decode().strip(chr(0)) if bootp.file else 'N/A'}")
            print(f"  Server Name: {bootp.sname.decode().strip(chr(0)) if bootp.sname else 'N/A'}")
    
    print(f"\nTotal de paquets BOOTP trouvés: {bootp_count}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <fichier.pcap>")
        sys.exit(1)
    analyze_bootp(sys.argv[1])
```

---

## 11. Sécurité et vulnérabilités

### 11.1 Vulnérabilités inhérentes à BOOTP

BOOTP a été conçu à une époque où la sécurité n'était pas la priorité absolue des réseaux locaux. Par conséquent, il présente plusieurs faiblesses :

1. **Aucune authentification** : n'importe quel client peut demander une configuration, et n'importe quel serveur peut répondre.
2. **Broadcasts non sécurisés** : les requêtes initiales sont diffusées sur le réseau local, exposant les informations.
3. **Usurpation d'adresse MAC** : un attaquant peut usurper l'adresse MAC d'un client légitime pour obtenir son adresse IP et son fichier de boot.
4. **Serveur BOOTP malveillant (rogue BOOTP/DHCP)** : un attaquant peut déployer un serveur BOOTP non autorisé pour rediriger les clients vers un serveur TFTP compromis.
5. **TFTP non sécurisé** : TFTP transmet les fichiers en clair, sans authentification ni chiffrement.
6. **Déni de service** : un serveur BOOTP saturé ou inaccessible empêche le démarrage des clients.

### 11.2 Attaques courantes

#### 11.2.1 Attaque par serveur BOOTP malveillant

Un attaquant installe un serveur BOOTP/DHCP sur le réseau et répond aux requêtes des clients avant le serveur légitime. Il peut ainsi :
- Rediriger le trafic via une fausse passerelle (MITM).
- Fournir un fichier de boot malveillant via TFTP.
- Collecter les adresses MAC et les requêtes des clients.

#### 11.2.2 Usurpation de MAC (MAC spoofing)

L'attaquant modifie son adresse MAC pour correspondre à celle d'un client autorisé. Le serveur BOOTP lui attribue alors l'adresse IP et le fichier de boot réservés à la victime.

#### 11.2.3 Starvation / Épuisement des adresses

Bien que BOOTP utilise des attributions statiques, un attaquant peut inonder le serveur de requêtes avec de fausses adresses MAC, provoquant une dégradation des performances.

### 11.3 Contre-mesures et hardening

#### 11.3.1 Sécurisation physique et logique du réseau

- **Segmentation VLAN** : isoler les clients BOOTP dans un VLAN dédié.
- **DHCP Snooping** : sur les commutateurs, activer DHCP Snooping pour filtrer les réponses non autorisées.
- **Dynamic ARP Inspection (DAI)** : empêcher l'usurpation ARP après attribution de l'IP.
- **Port Security** : limiter le nombre d'adresses MAC par port de commutateur.

#### 11.3.2 Authentification et contrôle d'accès

- Lister explicitement les adresses MAC autorisées dans `/etc/bootptab`.
- Utiliser des réservations DHCP avec authentification 802.1X.
- Déployer un serveur RADIUS pour l'authentification des équipements.

#### 11.3.3 Sécurisation de TFTP

- Remplacer TFTP par **SFTP**, **HTTPS**, ou **iPXE avec HTTP/HTTPS** lorsque possible.
- Restreindre l'accès au répertoire `/tftpboot`.
- Signer les fichiers de boot et vérifier leur intégrité avant exécution.

#### 11.3.4 Surveillance et détection

- Surveiller les annonces BOOTP/DHCP non autorisées.
- Utiliser des outils comme **Arpwatch**, **Snort**, **Suricata**.
- Auditer régulièrement les logs du serveur BOOTP.

### 11.4 Bonnes pratiques de sécurité BOOTP

1. **Limiter le broadcast** : utiliser des agents relais pour contrôler la propagation des requêtes.
2. **Fichier de boot signé** : utiliser des mécanismes de signature pour les images de boot.
3. **Réseau dédié au boot** : isoler physiquement ou logiquement les clients sans disque.
4. **Mise à jour régulière** : maintenir les serveurs BOOTP/DHCP et TFTP à jour.
5. **Principe du moindre privilège** : le serveur TFTP ne doit avoir accès qu'aux fichiers strictement nécessaires.

---

## 12. Dépannage avancé

### 12.1 Problèmes courants et solutions

#### 12.1.1 Le client n'obtient pas d'adresse IP

**Causes possibles :**
- Le serveur BOOTP n'est pas en cours d'exécution.
- Le client n'est pas enregistré dans `/etc/bootptab`.
- L'adresse MAC dans la configuration est incorrecte.
- Un pare-feu bloque les ports UDP 67/68.
- L'agent relais n'est pas configuré pour le sous-réseau du client.

**Solutions :**
```bash
# Vérifier le service
sudo systemctl status bootpd

# Vérifier la présence du client dans la configuration
grep "00:11:22:33:44:55" /etc/bootptab

# Vérifier les ports
sudo ss -ulnp | grep bootps

# Vérifier le pare-feu
sudo iptables -L -n -v | grep -E "67|68"
```

#### 12.1.2 Le client obtient l'IP mais ne télécharge pas le fichier de boot

**Causes possibles :**
- Le serveur TFTP n'est pas en cours d'exécution.
- Le fichier de boot n'existe pas dans `/tftpboot`.
- Les permissions du fichier sont incorrectes.
- Le champ `siaddr` ou `file` est mal configuré.
- Le client ne peut pas joindre le serveur TFTP (routage, pare-feu).

**Solutions :**
```bash
# Vérifier le service TFTP
sudo systemctl status tftpd-hpa

# Vérifier l'existence du fichier
ls -la /tftpboot/pxelinux.0

# Tester le téléchargement TFTP
tftp 192.168.1.10 -c get pxelinux.0

# Vérifier les permissions
sudo chmod 644 /tftpboot/pxelinux.0
sudo chown tftp:tftp /tftpboot/pxelinux.0
```

#### 12.1.3 Requêtes BOOTP traversant les routeurs

**Symptôme :** les clients d'un sous-réseau distant ne reçoivent pas de réponse.

**Solution :** configurer un agent relais (`ip helper-address` sur Cisco, `dhcrelay` sur Linux).

### 12.2 Checklist de dépannage BOOTP

1. [ ] Vérifier que le client est correctement configuré pour le boot réseau.
2. [ ] Vérifier que le câble réseau et la connectivité physique sont OK.
3. [ ] Vérifier que le serveur BOOTP écoute sur le port UDP 67.
4. [ ] Vérifier que l'adresse MAC du client est dans `/etc/bootptab`.
5. [ ] Vérifier la syntaxe de `/etc/bootptab`.
6. [ ] Vérifier les logs du serveur BOOTP.
7. [ ] Capturer les paquets avec tcpdump/Wireshark.
8. [ ] Vérifier la configuration de l'agent relais si nécessaire.
9. [ ] Vérifier le serveur TFTP et les fichiers de boot.
10. [ ] Vérifier les pare-feu et les ACL réseau.

### 12.3 Messages d'erreur courants

| Message | Signification | Solution |
|---------|---------------|----------|
| `No BOOTP server found` | Le client ne reçoit aucune réponse. | Vérifier le serveur, le réseau, l'agent relais. |
| `File not found` | Le fichier de boot est introuvable sur TFTP. | Vérifier le chemin et les permissions. |
| `Permission denied` | Le serveur TFTP refuse l'accès. | Vérifier les droits du répertoire TFTP. |
| `Timeout` | Le serveur ne répond pas dans le délai imparti. | Vérifier la connectivité réseau et les pare-feu. |
| `Invalid BOOTP reply` | La réponse reçue est mal formée. | Vérifier la configuration du serveur. |

---

## 13. Implémentations et cas d'usage

### 13.1 Implémentations serveur BOOTP

- **bootpd** : serveur BOOTP historique pour Unix/BSD.
- **ISC DHCP Server** : compatible BOOTP avec le paramètre `allow bootp`.
- **dnsmasq** : serveur DHCP/BOOTP léger.
- **Cobbler** : outil de déploiement Linux utilisant PXE/DHCP/TFTP.
- **Foreman** : gestion du cycle de vie des serveurs avec provisioning PXE.
- **Microsoft Windows Server** : services DHCP avec prise en charge BOOTP.
- **Cisco IOS** : serveur BOOTP intégré sur certains équipements.

### 13.2 Cas d'usage réels

#### 13.2.1 Stations de travail sans disque (Diskless Workstations)

Les laboratoires informatiques, les salles de classe et les cybercafés utilisent le boot réseau pour exécuter un système d'exploitation centralisé sans disque dur local.

#### 13.2.2 Déploiement de systèmes d'exploitation

Les outils comme **PXE**, **Cobbler**, **Foreman** et **Microsoft WDS** utilisent des concepts hérités de BOOTP pour déployer des OS en masse.

#### 13.2.3 Équipements embarqués

Les imprimantes, les terminaux de point de vente, les bornes d'accès et les équipements IoT utilisent souvent BOOTP ou DHCP pour obtenir leur configuration initiale.

#### 13.2.4 Télécommunications

Certains équipements réseau (routeurs, commutateurs) utilisent BOOTP pour charger leur configuration initiale ou leur firmware.

#### 13.2.5 Environnements legacy

Les anciens systèmes Unix (SunOS, HP-UX, AIX) et les terminaux X utilisent encore BOOTP dans certains environnements industriels ou de recherche.

### 13.3 Exemple de déploiement PXE avec BOOTP/DHCP

```
[Client PXE] --broadcast--> [Serveur DHCP/Bootp] --reponse--> [Client]
                                        |
                                        v
                              [Serveur TFTP: pxelinux.0]
                                        |
                                        v
                              [Menu PXE / Noyau Linux]
                                        |
                                        v
                              [Installation automatique OS]
```

---

## 14. Outils d'analyse de paquets

### 14.1 Wireshark

Wireshark est l'outil le plus puissant pour analyser les paquets BOOTP. Le dissecteur BOOTP/DHCP affiche :
- Le type de message (Request/Reply).
- Les adresses IP et MAC.
- Les options.
- Le fichier de boot.
- Le nom du serveur.

Filtres utiles :
```
bootp
bootp.op == 1
bootp.op == 2
bootp.hw.mac_addr == 00:11:22:33:44:55
```

### 14.2 tcpdump

tcpdump permet de capturer rapidement les paquets BOOTP en ligne de commande.

```bash
sudo tcpdump -i any -n -vvv 'port 67 or port 68'
```

### 14.3 Scapy

Scapy permet de construire, envoyer et analyser des paquets BOOTP/DHCP en Python.

Exemple d'envoi d'une requête BOOTP avec Scapy :
```python
from scapy.all import *

# Construction d'une requête BOOTP/DHCP Discover
eth = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
ip = IP(src="0.0.0.0", dst="255.255.255.255")
udp = UDP(sport=68, dport=67)
bootp = BOOTP(chaddr="00:11:22:33:44:55", xid=0x12345678)
dhcp = DHCP(options=[("message-type", "discover"), "end"])

pkt = eth / ip / udp / bootp / dhcp
sendp(pkt, iface="eth0")
```

### 14.4 bootptest

`bootptest` est un outil spécifique pour tester les serveurs BOOTP.

```bash
sudo bootptest -i eth0 -h 00:11:22:33:44:55 192.168.1.10
```

### 14.5 Nmap

Nmap peut détecter les serveurs BOOTP/DHCP actifs sur un réseau.

```bash
sudo nmap -sU -p 67 --script=dhcp-discover 192.168.1.0/24
```

---

## 15. Ressources et livres

### 15.1 RFCs officielles

| RFC | Titre | Description |
|-----|-------|-------------|
| RFC 951 | Bootstrap Protocol | Spécification originale de BOOTP |
| RFC 1048 | BOOTP Vendor Information Extensions | Introduction des extensions vendeur |
| RFC 1084 | BOOTP Vendor Information Extensions | Mise à jour de la RFC 1048 |
| RFC 1395 | BOOTP Vendor Information Extensions | Mise à jour des extensions |
| RFC 1497 | BOOTP Vendor Extensions | Extensions génériques |
| RFC 1532 | Clarifications and Extensions for the Bootstrap Protocol | Clarifications |
| RFC 1542 | Clarifications and Extensions for the Bootstrap Protocol | Interopérabilité BOOTP/DHCP |
| RFC 2131 | Dynamic Host Configuration Protocol | DHCP, successeur de BOOTP |
| RFC 2132 | DHCP Options and BOOTP Vendor Extensions | Options communes |
| RFC 1350 | The TFTP Protocol (Revision 2) | Protocole TFTP associé |

Sources officielles :
- https://www.rfc-editor.org/
- https://tools.ietf.org/

### 15.2 Livres recommandés

1. **"TCP/IP Illustrated, Volume 1: The Protocols"** par W. Richard Stevens  
   Le livre de référence pour comprendre TCP/IP, incluant BOOTP et DHCP.

2. **"The Protocols (TCP/IP Illustrated)"** par Kevin R. Fall et Richard Stevens  
   Mise à jour du classique de Stevens.

3. **"DHCP: A Guide to Dynamic TCP/IP Network Configuration"** par Angela Orebaugh et Gilbert Held  
   Couvre BOOTP et DHCP en détail.

4. **"Computer Networking: A Top-Down Approach"** par James F. Kurose et Keith W. Ross  
   Excellent pour les concepts généraux, incluant DHCP et son héritage BOOTP.

5. **"Network Warrior"** par Gary A. Donahue  
   Guide pratique pour les administrateurs réseau.

6. **"Cisco LAN Switching Configuration Handbook"** par Stephen McQuerry et David Hucaby  
   Utile pour la configuration des agents relais BOOTP/DHCP sur Cisco.

### 15.3 Ressources en ligne

- **Wireshark BOOTP/DHCP Wiki** : https://wiki.wireshark.org/DHCP
- **ISC DHCP Documentation** : https://www.isc.org/dhcp/
- **Dnsmasq Documentation** : http://www.thekelleys.org.uk/dnsmasq/doc.html
- **iPXE** : https://ipxe.org/ (successeur moderne du boot réseau)
- **Syslinux/PXELINUX** : https://wiki.syslinux.org/wiki/index.php?title=PXELINUX
- **Linux Documentation Project (LDP)** : https://tldp.org/

### 15.4 Communautés et forums

- Stack Overflow (tag bootp, dhcp)
- Server Fault
- Reddit r/networking
- Cisco Learning Network
- Communautés francophones de cybersécurité et réseau

---

## 16. Annexes techniques

### 16.1 Table des codes matériels ARP (htype)

| Valeur | Type de matériel |
|--------|------------------|
| 1 | Ethernet (10 Mb) |
| 2 | Experimental Ethernet (3 Mb) |
| 3 | Amateur Radio AX.25 |
| 4 | Proteon ProNET Token Ring |
| 5 | Chaos |
| 6 | IEEE 802 Networks |
| 7 | ARCNET |
| 8 | Hyperchannel |
| 9 | Lanstar |
| 10 | Autonet Short Address |
| 11 | LocalTalk |
| 12 | LocalNet (IBM PCNet or SYTEK LocalNET) |
| 13 | Ultra link |
| 14 | SMDS |
| 15 | Frame Relay |
| 16 | Asynchronous Transmission Mode (ATM) |
| 17 | HDLC |
| 18 | Fibre Channel |
| 19 | Asynchronous Transmission Mode (ATM) |
| 20 | Serial Line |
| 21 | Asynchronous Transmission Mode (ATM) |
| 22 | MIL-STD-188-220 |
| 23 | Metricom |
| 24 | IEEE 1394.1995 |
| 25 | MAPOS |
| 26 | Twinaxial |
| 27 | EUI-64 |
| 28 | HIPARP |
| 29 | IP and ARP over ISO 7816-3 |
| 30 | ARPSec |
| 31 | IPsec tunnel |
| 32 | InfiniBand (TM) |
| 33 | TIA-102 Project 25 Common Air Interface |
| 34 | Wiegand Interface |
| 35 | Pure IP |
| 36 | HW_EXP1 |
| 37 | HFI |

### 16.2 Table des options BOOTP/DHCP communes

| Code | Nom | Longueur | Description |
|------|-----|----------|-------------|
| 0 | Pad | - | Octet de remplissage |
| 1 | Subnet Mask | 4 | Masque de sous-réseau |
| 2 | Time Offset | 4 | Décalage horaire en secondes |
| 3 | Router | Variable | Liste des routeurs |
| 4 | Time Server | Variable | Serveurs de temps |
| 5 | Name Server | Variable | Serveurs IEN-116 |
| 6 | Domain Name Server | Variable | Serveurs DNS |
| 7 | Log Server | Variable | Serveurs de logs |
| 8 | Cookie Server | Variable | Serveurs de cookies |
| 9 | LPR Server | Variable | Serveurs d'impression LPR |
| 12 | Host Name | Variable | Nom d'hôte |
| 15 | Domain Name | Variable | Nom de domaine |
| 17 | Root Path | Variable | Chemin racine NFS |
| 28 | Broadcast Address | 4 | Adresse de broadcast |
| 42 | NTP Servers | Variable | Serveurs NTP |
| 50 | Requested IP Address | 4 | IP demandée |
| 51 | IP Address Lease Time | 4 | Durée du bail |
| 53 | DHCP Message Type | 1 | Type DHCP |
| 54 | Server Identifier | 4 | Identifiant du serveur |
| 55 | Parameter Request List | Variable | Options demandées |
| 56 | Message | Variable | Message d'erreur |
| 57 | Maximum DHCP Message Size | 2 | Taille max du message |
| 58 | Renewal Time Value | 4 | T1 |
| 59 | Rebinding Time Value | 4 | T2 |
| 60 | Vendor Class Identifier | Variable | Classe vendeur |
| 61 | Client Identifier | Variable | Identifiant client |
| 66 | TFTP Server Name | Variable | Nom serveur TFTP |
| 67 | Bootfile Name | Variable | Nom du fichier de boot |
| 97 | Client System Architecture Type | 2 | Architecture client (PXE) |
| 255 | End | - | Fin des options |

### 16.3 Exemple de capture Wireshark (texte)

```
Frame 1: 342 bytes on wire (2736 bits), 342 bytes captured (2736 bits)
Ethernet II, Src: 00:11:22:33:44:55, Dst: ff:ff:ff:ff:ff:ff
Internet Protocol Version 4, Src: 0.0.0.0, Dst: 255.255.255.255
User Datagram Protocol, Src Port: 68, Dst Port: 67
Bootstrap Protocol (Request)
    Message type: Boot Request (1)
    Hardware type: Ethernet (0x01)
    Hardware address length: 6
    Hops: 0
    Transaction ID: 0x12345678
    Seconds elapsed: 0
    Bootp flags: 0x0000 (Unicast)
    Client IP address: 0.0.0.0
    Your (client) IP address: 0.0.0.0
    Next server IP address: 0.0.0.0
    Relay agent IP address: 0.0.0.0
    Client MAC address: 00:11:22:33:44:55
    Client hardware address padding: 00000000000000000000
    Server host name not given
    Boot file name not given
    Magic cookie: DHCP
    Option: (53) DHCP Message Type
        Length: 1
        DHCP: Discover (1)
    Option: (55) Parameter Request List
        Length: 4
        Parameter Request List Item: (1) Subnet Mask
        Parameter Request List Item: (3) Router
        Parameter Request List Item: (6) Domain Name Server
        Parameter Request List Item: (15) Domain Name
    Option: (255) End
    Padding
```

### 16.4 Conversion décimale/hexadécimale des ports

| Protocole | Port décimal | Port hexadécimal |
|-----------|--------------|------------------|
| BOOTP/DHCP serveur | 67 | 0x0043 |
| BOOTP/DHCP client | 68 | 0x0044 |
| TFTP | 69 | 0x0045 |

### 16.5 Schéma récapitulatif du paquet BOOTP

```
+------------------+
| UDP Header       |  (8 octets)
|  Src: 68 / Dst: 67
+------------------+
| BOOTP Header     |  (300 octets min)
|  op, htype, hlen, hops
|  xid, secs, flags
|  ciaddr, yiaddr, siaddr, giaddr
|  chaddr (16 octets)
|  sname (64 octets)
|  file (128 octets)
|  vend (64 octets)
+------------------+
```

---

## 17. Glossaire

| Terme | Définition |
|-------|------------|
| **BOOTP** | Bootstrap Protocol, protocole de configuration initiale réseau. |
| **DHCP** | Dynamic Host Configuration Protocol, successeur de BOOTP. |
| **MAC** | Media Access Control, adresse physique d'une interface réseau. |
| **IP** | Internet Protocol, adresse logique d'un hôte. |
| **UDP** | User Datagram Protocol, protocole de transport non fiable. |
| **TFTP** | Trivial File Transfer Protocol, protocole simple de transfert de fichiers. |
| **PXE** | Preboot Execution Environment, environnement de démarrage réseau moderne. |
| **VLAN** | Virtual Local Area Network, segmentation logique d'un réseau. |
| **Relay Agent** | Agent relais, transmet les requêtes BOOTP entre sous-réseaux. |
| **Lease** | Bail, durée d'attribution d'une adresse IP en DHCP. |
| **Broadcast** | Diffusion, envoi d'un paquet à tous les hôtes du réseau local. |
| **Unicast** | Envoi d'un paquet à un seul destinataire. |
| **RARP** | Reverse Address Resolution Protocol, prédécesseur de BOOTP. |
| **NFS** | Network File System, système de fichiers en réseau. |
| **PXELINUX** | Chargeur de démarrage PXE du projet Syslinux. |
| **iPXE** | Implémentation avancée et open-source de PXE. |

---

## 18. Conclusion

Le protocole **BOOTP** est un pilier fondamental de l'histoire des réseaux TCP/IP. Bien qu'il ait été largement supplanté par **DHCP**, sa compréhension reste indispensable pour tout professionnel des réseaux et de la cybersécurité. BOOTP a posé les bases du boot réseau, de l'attribution automatique des configurations IP, et des options de configuration étendues que nous utilisons encore aujourd'hui.

Ce guide avancé, rédigé par **Hackers_tchad**, a couvert :
- Les définitions et concepts fondamentaux de BOOTP.
- Son histoire et ses créateurs.
- Son importance et son rôle dans les réseaux modernes.
- Son architecture client/serveur et le rôle des agents relais.
- Le format détaillé de ses messages.
- Le processus complet de bootstrap.
- Les différences avec DHCP.
- La configuration sur Linux, Cisco, et avec dnsmasq.
- Les commandes de vérification et de débogage.
- Les aspects sécurité et les vulnérabilités.
- Le dépannage avancé.
- Les implémentations et cas d'usage.
- Les outils d'analyse de paquets.
- Les ressources complémentaires (RFCs, livres, communautés).

Pour aller plus loin, il est recommandé d'expérimenter dans un laboratoire virtuel avec des outils comme **GNS3**, **EVE-NG**, **VirtualBox** ou **VMware**, et d'analyser des captures Wireshark de paquets BOOTP/DHCP. La maîtrise de BOOTP ouvre la voie à une compréhension plus profonde de DHCP, PXE, et des mécanismes de configuration automatique des réseaux.

**Hackers_tchad** vous remercie d'avoir lu ce guide. N'hésitez pas à consulter les RFCs officielles et à pratiquer régulièrement pour perfectionner vos compétences.

---

## Licence et utilisation

Ce document est fourni à des fins éducatives et professionnelles. Vous êtes libre de l'utiliser, le modifier et le partager en mentionnant l'auteur original **Hackers_tchad**.

**Avertissement** : les techniques et configurations présentées doivent être utilisées de manière responsable et légale. L'auteur ne saurait être tenu responsable d'une mauvaise utilisation.

---

*Fin du document - Version avancée BOOTP par Hackers_tchad*
