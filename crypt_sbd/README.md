# Chiffrement au repos – PostgreSQL + pgcrypto
## Groupe : ALI Alissou & BONGO Andy

---

## Description

Ce projet implémente le **chiffrement au repos** de la colonne `SAL` de la table `EMP`
via l'extension **pgcrypto** de PostgreSQL, avec le schéma **AES-256 mode CBC**.
Un benchmark Python mesure la surcharge induite par le chiffrement.

**(Bonus Q3)** Une attaque par analyse de fréquences sur le mode **ECB** est également
implémentée pour illustrer la faiblesse de ce mode face au mode CBC.

---

## Prérequis

- **PostgreSQL** ≥ 13
- **Python** ≥ 3.9
- Extension `pgcrypto` disponible dans PostgreSQL

---

## Installation

### 1. PostgreSQL

```bash
# Ubuntu/Debian
sudo apt install postgresql postgresql-contrib

# macOS (Homebrew)
brew install postgresql

# Windows
# Télécharger l'installateur sur https://www.postgresql.org/download/windows/
```

### 2. Activer pgcrypto

```sql
-- Dans psql, connecté à votre base :
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

### 3. Dépendances Python

```bash
pip install psycopg2-binary matplotlib numpy scipy
```

---

## Configuration

Éditez **chaque script Python** et renseignez vos paramètres de connexion dans le bloc `DB_CONFIG` :

```python
DB_CONFIG = {
    "host":     "localhost",
    "port":     5432,
    "dbname":   "your_database",   # nom de votre base PostgreSQL
    "user":     "your_user",       # votre utilisateur PostgreSQL
    "password": "your_password",   # votre mot de passe
}
```

> Cette configuration est à répéter dans `benchmark.py` et `ecb_attack.py`.

---

## Utilisation

### Étape 1 – Initialiser la base de données (CBC)

```bash
psql -U your_user -d your_database -f encryption_setup.sql
```

Ce script :
- Active `pgcrypto`
- Crée `EMP_INTERNAL` (données chiffrées sur disque en AES-256 CBC)
- Crée la vue `EMP_VIEW` (accès transparent en clair)
- Crée les triggers INSTEAD OF (INSERT / UPDATE / DELETE)
- Insère 10 000 enregistrements générés aléatoirement avec SAL ~ N(5000, 500²)

### Étape 2 – Lancer les benchmarks (Q2)

```bash
python benchmark.py
```

Les résultats sont affichés dans le terminal et deux graphiques sont générés :
- `benchmark_results.png` – temps absolu par opération (INSERT, SELECT, UPDATE)
- `benchmark_ratio.png`   – ratio de surcharge chiffré / plain

### Étape 3 – Initialiser le mode ECB (Bonus Q3)

```bash
psql -U your_user -d your_database -f ecb_setup.sql
```

Ce script :
- Crée `EMP_ECB` (données chiffrées en AES-256 **ECB**)
- Crée la vue `EMP_ECB_VIEW` (accès transparent en clair)
- Crée les fonctions `encrypt_sal_ecb()` / `decrypt_sal_ecb()`
- Copie les 10 000 enregistrements depuis `EMP_INTERNAL` en les rechiffrant en ECB

> ⚠️ L'étape 1 doit être exécutée avant l'étape 3 (ecb_setup.sql copie les données depuis EMP_INTERNAL).

### Étape 4 – Lancer l'attaque par fréquences (Bonus Q3)

```bash
python ecb_attack.py
```

Ce script simule un attaquant ayant accès aux données chiffrées sur disque (sans la clé).
Il produit un résumé terminal et un graphique :
- `ecb_attack_analysis.png` – 4 graphiques comparant ECB vs CBC et la reconstruction de la distribution

---

## Architecture

### Mode CBC (Q1)

```
EMP_VIEW  (vue PostgreSQL – accès application)
    │
    ├── INSTEAD OF INSERT  → trigger_view_insert()  → encrypt_sal()  → EMP_INTERNAL
    ├── INSTEAD OF UPDATE  → trigger_view_update()  → encrypt_sal()  → EMP_INTERNAL
    ├── INSTEAD OF DELETE  → trigger_view_delete()               → EMP_INTERNAL
    └── SELECT             → decrypt_sal(SAL)        ← EMP_INTERNAL
```

### Mode ECB (Bonus Q3)

```
EMP_ECB_VIEW  (vue PostgreSQL – accès application)
    │
    ├── INSTEAD OF INSERT  → trigger_ecb_insert()     → encrypt_sal_ecb()  → EMP_ECB
    ├── INSTEAD OF UPDATE  → trigger_ecb_update()     → encrypt_sal_ecb()  → EMP_ECB
    └── SELECT             → decrypt_sal_ecb(SAL_ECB) ← EMP_ECB
```

### Principe de l'attaque ECB

En mode ECB, le même bloc en clair produit **toujours** le même bloc chiffré :

```
encrypt_ecb(clé, 5200) == encrypt_ecb(clé, 5200)   ← toujours vrai
encrypt_cbc(clé, 5200) != encrypt_cbc(clé, 5200)   ← IV aléatoire → toujours différent
```

Un attaquant qui accède aux `BYTEA` sur disque peut donc :
1. Compter les occurrences de chaque valeur chiffrée
2. Reconstruire la distribution des salaires par analyse de fréquences
3. **Sans jamais connaître la clé**

### Choix techniques

| Aspect | Choix | Justification |
|---|---|---|
| Algorithme | AES-256 | Standard industriel, résistant aux attaques connues |
| Mode principal | CBC | Masque les répétitions grâce à l'IV aléatoire |
| Mode bonus | ECB | Illustre la vulnérabilité aux attaques par fréquences |
| API CBC | `pgp_sym_encrypt` | Haut niveau, IV géré automatiquement |
| API ECB | `encrypt()` | Bas niveau, bloc fixe de 16 octets |
| Stockage chiffré | `BYTEA` | Format binaire natif PostgreSQL |
| Interface | Vue + triggers INSTEAD OF | Transparent pour l'application |
| Clé | Variable de session | `SET myapp.encryption_key = '...'` |

---

## Structure des fichiers

```
.
├── encryption_setup.sql   # Script SQL : CBC – tables, fonctions, triggers, données
├── ecb_setup.sql          # Script SQL : ECB – table, fonctions, triggers (Bonus Q3)
├── benchmark.py           # Script Python : benchmarks CBC vs plain + graphiques (Q2)
├── ecb_attack.py          # Script Python : attaque par fréquences ECB (Bonus Q3)
└── README.md              # Ce fichier
```

---

## Résultats attendus

### Benchmarks (Q2)

| Opération | Surcharge attendue | Explication |
|---|---|---|
| INSERT | ×3 à ×10 | Chiffrement AES + overhead pgp |
| SELECT * | ×5 à ×20 | Déchiffrement de chaque ligne |
| SELECT filtré | ×5 à ×20 | Déchiffrement avant comparaison |
| UPDATE | ×5 à ×15 | Déchiffrement + rechiffrement |

### Attaque ECB (Q3)

| Métrique | ECB | CBC |
|---|---|---|
| Chiffrés uniques (n=10 000) | ~300–500 | ~10 000 (tous uniques) |
| Distribution reconstruite | ✅ Identique à la réelle | ❌ Impossible |
| Résistance à l'attaque | ❌ Vulnérable | ✅ Résistant |

---

## Notes de sécurité

> ⚠️ La clé de chiffrement est définie via une variable de session PostgreSQL.
> En production, utilisez un gestionnaire de secrets (Vault, AWS KMS, etc.)
> et ne codez jamais la clé en dur dans le code source.

> ⚠️ Le mode ECB ne doit **jamais** être utilisé en production pour des données
> présentant des répétitions (salaires, codes postaux, catégories...).
> Utilisez toujours CBC ou GCM avec un IV aléatoire.