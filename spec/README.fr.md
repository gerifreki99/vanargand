<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

[English](README.md) · **Français**

# Spécification

Versionnée et gelée. Le code référence des sections de spécification par version,
jamais un document mouvant.

- `draft/` — brouillon de travail, **rien n'y est gelé**
- `v3/` — version gelée courante (à découper depuis `draft/` quand une section
  sera jugée stable)
- `vectors/` — vecteurs de test de conformité (CC0-1.0)

Geler, c'est promettre qu'un encodage ne changera plus jamais ; `draft/` ne
promet rien. Une section n'entre dans un répertoire numéroté que lorsqu'elle est
jugée stable, et la règle du gel ne s'applique qu'à partir de là.

## Les vecteurs de test viennent d'abord

Les vecteurs sont écrits **avant** l'implémentation, directement depuis la
spécification. Les écrire est le moyen de découvrir les ambiguïtés de la
spécification, et il est bien moins coûteux de les découvrir ici que dans un
débogueur de consensus.

Les vecteurs sont aussi l'artefact qui survit si l'implémentation ne survit pas :
une spécification accompagnée de vecteurs de conformité est réimplémentable par
quelqu'un d'autre. Une spécification en prose ne l'est pas.

Couverture prévue : sérialisation canonique, dérivation d'adresse et Bech32m,
convention de hachage de l'arbre de Merkle épars, enveloppe de transaction,
disposition du nonce 2D (voie, séquence), transition d'état par type de
transaction.
