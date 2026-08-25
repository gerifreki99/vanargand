<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

[English](CONTRIBUTING.md) · **Français**

# Contribuer à Vanargand

Le projet est en phase de conception. La contribution la plus précieuse
aujourd'hui est **un argument correct établissant que quelque chose ici ne
fonctionne pas** : un mécanisme qui casse face à un adversaire que le modèle de
menace ne couvre pas, un invariant qui ne tient pas, une revendication plus forte
que sa justification.

## Avant d'ouvrir une pull request

Lisez [`README.fr.md`](README.fr.md), et en particulier le tableau des
*Problèmes ouverts*. Si votre trouvaille y figure déjà comme ouverte, elle est
connue ; une issue reste bienvenue si vous apportez une parade.

## Attestation d'origine (DCO)

Ce projet utilise le **Developer Certificate of Origin 1.1** — voir
[`DCO`](DCO). Il n'y a pas de Contributor License Agreement.

Chaque commit doit porter une ligne `Signed-off-by` correspondant à son auteur :

```
Signed-off-by: Jane Doe <jane@example.com>
```

`git commit -s` l'ajoute automatiquement. Pour corriger un oubli sur le dernier
commit :

```
git commit --amend -s --no-edit
```

En signant, vous certifiez les déclarations du fichier `DCO` et acceptez que
votre contribution soit placée sous les licences du projet.

> Le texte du DCO est en anglais et n'est pas traduit : c'est un document
> juridique dont la version anglaise est la seule qui fasse foi.

## Licence des contributions

| Vous contribuez à | Votre contribution est sous |
|---|---|
| Code | `MIT OR Apache-2.0` |
| Documents, spécifications | `CC-BY-4.0` |
| Vecteurs de test | `CC0-1.0` |

Cela découle de l'article 5 d'Apache-2.0 : une contribution intentionnellement
soumise pour inclusion l'est sous les mêmes termes, sauf mention explicite
contraire de votre part.

**Sur le changement de licence.** En l'absence de CLA, le projet ne pourra pas
être relicencié une fois des contributions externes fusionnées, sans l'accord de
chaque contributeur. C'est volontaire.

## Règles de code

Elles ne sont pas encore vérifiées par l'intégration continue, puisqu'il n'y a
pas de code. Elles sont consignées maintenant parce que les appliquer
rétroactivement coûte cher.

### Le déterminisme est obligatoire dans le code de transition d'état

Toute transition d'état doit être prouvable et reproductible. Une divergence
entre deux nœuds honnêtes est une défaillance de consensus.

- **Pas de `HashMap` ni de `HashSet` dans le code d'état.** Leur ordre
  d'itération est randomisé par défaut en Rust et fera diverger des nœuds
  honnêtes. Utilisez `BTreeMap` / `BTreeSet`, ou `IndexMap` lorsque l'ordre
  d'insertion porte la sémantique voulue.
- **Pas de flottants** (`f32`, `f64`) dans quoi que ce soit qui affecte l'état.
  À faire respecter par lint.
- **Pas d'horloge système.** La seule horloge est la hauteur de bloc.
- **Aucune dépendance** aux adresses d'allocation, à l'ordonnancement des fils
  d'exécution, ou à l'ordre d'itération sur une collection non ordonnée.
- Toute transition doit être rejouable : les mêmes blocs, dans n'importe quel
  ordre d'arrivée, donnent la même racine d'état.

### L'encodage canonique est gelé

Sérialisation, dérivation d'adresse, convention de hachage de l'arbre et
enveloppe de transaction ne peuvent plus changer après le bloc d'origine. Toute
modification exige une nouvelle version de la spécification et est traitée comme
une rupture de compatibilité.

### Cryptographie

Toutes les primitives passent par l'abstraction de `vanargand-crypto`. N'appelez
jamais une primitive directement depuis ailleurs. Chaque objet du protocole porte
un octet de version.

## Messages de commit

Rédigez-les **en anglais**, comme le code et les commentaires, pour que le projet
reste lisible par des contributeurs non francophones.

```
component: short imperative summary

Body explaining why, not what. Reference the specification section or
threat-model identifier where relevant (for example: "addresses C9").

Signed-off-by: Jane Doe <jane@example.com>
```

## Vérifier le texte du DCO

La copie du DCO présente dans ce dépôt doit être identique au texte canonique de
<https://developercertificate.org/>. Si ce n'est pas le cas, la version canonique
prévaut — merci d'ouvrir une issue.
