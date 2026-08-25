# Traductions : ce qui se traduit et ce qui ne se traduit pas

## Structure bilingue

Convention retenue : l'anglais est le fichier par défaut, le français porte le
suffixe `.fr`. Chaque page commence par un sélecteur de langue.

| Anglais (défaut) | Français |
|---|---|
| `README.md` | `README.fr.md` |
| `CONTRIBUTING.md` | `CONTRIBUTING.fr.md` |
| `SECURITY.md` | `SECURITY.fr.md` |
| `docs/README.md` | `docs/README.fr.md` |
| `spec/README.md` | `spec/README.fr.md` |

L'anglais reste le point d'entrée parce que c'est lui qui vous apporte des
lecteurs : GitHub affiche `README.md`, et c'est la langue de la communauté que
vous visez. Si vous préférez inverser, il suffit d'échanger les deux noms de
fichier — mais je vous le déconseille.

## À NE JAMAIS TRADUIRE

### `LICENSE-MIT` et `LICENSE-APACHE`

Ces textes n'ont de valeur juridique que dans leur version anglaise d'origine.
Des traductions françaises circulent ; **aucune n'a de valeur légale**, et en
substituer une créerait une licence non standard que les outils d'analyse de
conformité ne reconnaîtraient pas.

Si vous voulez rendre service à un lecteur francophone, ajoutez un renvoi — pas
une traduction :

    Traduction française non officielle, à titre indicatif uniquement :
    https://veni.com/mit.html  (MIT)
    Seule la version anglaise ci-dessus fait foi.

### `DCO`

Même raison. C'est un texte du Linux Foundation dont la version canonique est
à <https://developercertificate.org/>. Les contributeurs certifient le texte
anglais, pas une paraphrase.

### `NOTICE`

Ce fichier est explicitement désigné par l'article 4(d) d'Apache-2.0 et doit être
reproduit tel quel par tout redistributeur. Gardez-le en anglais.

### `.reuse/dep5` et `CITATION.cff`

Fichiers lisibles par machine, consommés par des outils (`reuse lint`, l'index de
citation de GitHub, Zenodo). Les clés et les identifiants de licence SPDX sont
normalisés. Ne touchez qu'aux valeurs, jamais aux clés.

## Cas particulier : `LICENSE-DOCS` (CC-BY-4.0)

Contrairement à MIT et Apache, **Creative Commons publie des traductions
officielles** de ses licences 4.0, y compris en français, avec la même valeur
juridique que l'anglais.

Vous pouvez donc légitimement pointer vers la version française :

- Résumé : <https://creativecommons.org/licenses/by/4.0/deed.fr>
- Code juridique officiel : <https://creativecommons.org/licenses/by/4.0/legalcode.fr>

L'identifiant SPDX reste `CC-BY-4.0` dans tous les cas.

## Et le corpus lui-même ?

Vos dix documents sont en français et peuvent le rester dans `docs/`. Ce sont vos
documents de conception d'origine ; les traduire intégralement représente
plusieurs semaines pour un bénéfice faible.

En revanche, `spec/` doit être en anglais dès le départ. La spécification est ce
que quelqu'un d'autre réimplémentera, et les vecteurs de test qui l'accompagnent
n'ont pas de langue. Un correctif utile en attendant : ajoutez au README anglais
un résumé de 300 mots de chaque document français, pour qu'un lecteur non
francophone sache ce qu'il y a dedans et puisse demander une traduction ciblée.

## Règle en cas de divergence

Écrivez-la explicitement, elle évite les litiges :

- **Spécifications** : la version anglaise fait référence.
- **Documents de conception** : la version française fait référence (ce sont les
  originaux).
- **Licences** : la version anglaise fait référence, sauf CC-BY-4.0 dont les
  traductions officielles sont équivalentes.

Cette règle figure déjà au bas de `README.fr.md`.
