<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

[English](README.md) · **Français**

# Vanargand

**Une conception de registre tolérant aux partitions, pour réseaux à connectivité intermittente.**

> **État : phase de conception, l'implémentation du socle commence.**
> Ce dépôt contient des documents de conception, un modèle de menace, des
> journaux de révision, une spécification à l'état de brouillon, des vecteurs de
> conformité, et des caisses Rust implémentant l'encodage, l'interface des
> primitives, les objets canoniques et le registre. **Aucune chaîne n'a jamais
> tourné.** Rien ici n'a été audité ni relu par des pairs. Plusieurs problèmes
> centraux sont ouverts — voir [Problèmes ouverts](#problèmes-ouverts) — et le
> code n'a aucune bibliothèque post-quantique branchée, donc il ne sait pas
> vérifier une vraie signature aujourd'hui. Voir
> [Ce qui est implémenté](#ce-qui-est-implémenté) pour la frontière exacte.

---

## De quoi il s'agit

Vanargand est une conception de registre dans laquelle **la partition réseau est le
régime de fonctionnement normal, et non un mode de défaillance**. La plupart des
registres distribués supposent la connectivité et traitent la partition comme
une exception dont il faut se remettre. Vanargand inverse cette hypothèse et demande à
quoi ressemble un système de paiement et d'identité quand les nœuds sont
couramment hors ligne pendant des heures ou des jours.

La conception vise trois situations : les sites à connectivité volontairement
dégradée (grands événements), les zones à infrastructure intermittente, et — par
généralisation — les réseaux à forte latence où les allers-retours se comptent en
minutes.

## Contributions

Les parties de cette conception susceptibles d'avoir un intérêt indépendant, que
Vanargand soit construit un jour ou non :

1. **Fraude sur canal en régime de partition.** Fermeture unilatérale d'un canal
   avec un état périmé, exécutée dans des blocs provisoires (non finalisés)
   pendant que la contrepartie et son tour de garde se trouvent de l'autre côté
   d'une partition. La fenêtre de contestation s'écoule dans un monde où le
   contestant ne peut pas exister. La littérature sur les canaux de paiement
   suppose la vivacité ; celle sur les partitions ignore les canaux. Documenté
   sous l'identifiant **C9** dans le modèle de menace, avec une parade proposée :
   liste blanche grammaticale pour l'inclusion provisoire, et horloges de
   contestation comptées exclusivement en hauteur finalisée.

2. **Dépense hors ligne bornée à équivoque de compte auto-prouvante.** Une borne
   d'exposition hors ligne déclarée publiquement sur le registre, de sorte que le
   risque du commerçant soit connu *ex ante* plutôt que réparé *ex post*. Une
   double dépense à travers les partitions produit nécessairement deux signatures
   partageant un même triplet (sous-clé d'appareil, voie, séquence) : la fraude
   porte sa propre preuve. L'allocation de voies par appareil garantit que deux
   appareils honnêtes d'un même compte ne peuvent pas produire d'équivoque
   punissable.

3. **Une échelle de finalité où la partition est nominale.** États provisoires et
   finalisés comme objets de première classe, avec réconciliation déterministe :
   deux nœuds honnêtes détenant les mêmes blocs provisoires calculent le même
   état final, indépendamment de l'ordre d'arrivée.

4. **L'inversion monétaire comme patron réglementaire.** Le jeton du protocole ne
   sert qu'entre machines, pour le règlement de l'infrastructure ; les
   utilisateurs finaux transigent dans leur monnaie habituelle. Cela supprime la
   surface de jeton face au grand public tout en préservant l'économie de
   l'opérateur.

## Problèmes ouverts

Cette section existe parce que la conception n'est pas terminée, et que prétendre
le contraire vous ferait perdre votre temps.

| Id. | Problème | État |
|----|---------|------|
| C7 | Fuite de la pondération de provenance ; se réduit à la preuve de personne | Ouvert |
| B4 | Corrélation de trafic contre la couche de messagerie | Ouvert |
| D3 | Disponibilité des données pour l'état archivé | Ouvert |
| G7 | Qualification réglementaire | Ouvert |
| A4 | Balise d'aléa sur le chemin critique du lancement | En révision |
| A7 | État finalisé invalide et exposition des clients légers | Parade partielle |
| E1–E3 | Scellement du stockage (Proof of Replication) | À concevoir |

La thèse économique centrale — attaquer le réseau est structurellement non
rentable — **dépend actuellement de C7** et doit se lire comme une conjecture en
attente de mesure, non comme un résultat. Le journal de révision retrace
l'affaiblissement de cette thèse par rapport à sa formulation initiale.

## Ce qui est implémenté

| Domaine | État |
|---|---|
| Encodage canonique, avec rejet des encodages non canoniques | Implémenté, vecteurs |
| Séparation de domaine BLAKE3, chaînes de hachage (PayWord, engagements) | Implémenté, vecteurs |
| Hiérarchie de clés, identifiants de compte et d'appareil, Bech32m `van1…` | Implémenté, vecteurs |
| Nonce 2D, état des voies | Implémenté |
| Enveloppe de transaction, 21 types, grammaire du provisoire (C9) | Implémenté |
| Preuve d'équivoque de compte (R2) | Implémenté |
| En-tête de bloc, échelle de finalité, horloges de contestation | Implémenté |
| Arbre de Merkle épars, preuves d'inclusion **et de non-inclusion** | Implémenté |
| Registre : 6 types de transaction sur 21, plafond nomade appliqué | Partiel |
| Bibliothèques post-quantiques (signature, KEM) | **Interface seule** |
| Consensus, réseau, messagerie, bourses, stockage, ponts | Non commencé |

La couche signature mérite d'être isolée. `vanargand-crypto` contient le
registre des algorithmes, les traits, et une suite de conformité
comportementale qu'une bibliothèque candidate doit passer — mais **aucune
bibliothèque post-quantique n'est encore une dépendance**, et c'est un état
assumé, pas un oubli. Un adaptateur écrit contre une API que personne n'a
compilée a l'air fini et ne l'est pas. Voir
[`vanargand-crypto/BACKENDS.md`](vanargand-crypto/BACKENDS.md).

Deux trouvailles nées de l'écriture du code sont consignées dans le brouillon
de spécification plutôt que résolues discrètement : le plafond hors-ligne ne
couvre pas les monnaies locales, c'est-à-dire exactement le paiement autour
duquel le pilote du Cran 1 est construit
([`04-transactions.md`](spec/draft/04-transactions.md) §4.1) ; et le seuil des
noms premium de la R1.7 contredit son propre exemple `@marie` (§6.1).

## Organisation du dépôt

```
docs/               Documents de conception, modèle de menace, révisions (R1, R2)
spec/draft/         Spécification, brouillon de travail — non gelée
spec/vectors/       Vecteurs de test de conformité (CC0)
tools/vectorgen/    Une seconde implémentation, en Python, qui les engendre
vanargand-crypto/   Interface des primitives : hachage, chaînes, clés, traits
vanargand-types/    Encodage canonique, identifiants, adresses, transactions, blocs
vanargand-state/    Arbre de Merkle épars, modèle de compte, transitions d'état
vanargand-*/        Réservées, documentées, non implémentées
```

Les vecteurs sont engendrés par une implémentation Python écrite depuis la
prose de `spec/draft/`, délibérément pas depuis le Rust. Des vecteurs engendrés
par l'implémentation qu'ils testent ne prouvent qu'une chose : que
l'implémentation est d'accord avec elle-même. L'intégration continue pose les
deux questions séparément — le Rust correspond-il aux vecteurs, et les vecteurs
correspondent-ils encore à la spécification dont ils sont tirés.

## Journaux de révision

`docs/` contient les tours de revue (R1, R2) comme documents distincts, plutôt
que repliés silencieusement dans la conception. Ils consignent des décisions
prises, jugées fausses, puis remplacées — dont deux corrections portant sur les
revendications centrales. Ils sont publiés délibérément.

## Licences

| Contenu | Licence |
|---------|---------|
| Code | `MIT OR Apache-2.0` |
| Documents et spécifications | `CC-BY-4.0` |
| Vecteurs de test de conformité | `CC0-1.0` |

Périmètre lisible par machine : [`.reuse/dep5`](.reuse/dep5).

La double licence du code suit la convention de l'écosystème Rust. Les vecteurs
de test sont placés dans le domaine public afin que toute implémentation puisse
les utiliser sans avoir à se poser la moindre question de licence.

## Citation

Voir [`CITATION.cff`](CITATION.cff), ou le DOI de la version archivée.

## Contribuer

Voir [`CONTRIBUTING.fr.md`](CONTRIBUTING.fr.md). Les contributions sont acceptées
sous le Developer Certificate of Origin — une ligne `Signed-off-by` dans chaque
commit. Il n'y a pas de CLA.

À ce stade, la contribution la plus utile n'est toujours pas du code. C'est un
argument établissant qu'un des mécanismes décrits ici ne fonctionne pas. Si vous
en trouvez un, ouvrez une issue.

La deuxième plus utile est un désaccord entre les deux implémentations. Là où
`tools/vectorgen/generate.py` et les caisses Rust divergent, l'une des deux a
tort — ou la spécification est assez ambiguë pour que deux lecteurs en tirent
deux choses, ce qui est le plus précieux des trois cas.

Ensuite : une bibliothèque post-quantique qui passe
`vanargand_crypto::sign::conformance::check`, et les quinze types de transaction
que le registre n'applique pas encore.

## Sécurité

Voir [`SECURITY.fr.md`](SECURITY.fr.md).

## Langues

Les documents de conception sont actuellement en français ; les spécifications et
les articles sont rédigés en anglais. La traduction est en cours. En cas de
divergence entre les versions française et anglaise d'un document, **la version
anglaise fait référence** pour les spécifications, la française pour les
documents de conception d'origine.
