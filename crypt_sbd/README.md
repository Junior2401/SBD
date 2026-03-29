# Chiffrement au repos – PostgreSQL + pgcrypto
## Groupe : [Noms des étudiants]

---

## Description

Ce projet implémente le **chiffrement au repos** de la colonne `SAL` de la table `EMP`
via l'extension **pgcrypto** de PostgreSQL, avec le schéma **AES-256 mode CBC**.
Un benchmark Python mesure la surcharge induite par le chiffrement.

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

Éditez le fichier `benchmark.py` et renseignez vos paramètres de connexion :

```python
DB_CONFIG = {
    "host":     "localhost",
    "port":     5432,
    "dbname":   "your_database",
    "user":     "your_user",
    "password": "your_password",
}
```

---

## Utilisation

### Étape 1 – Initialiser la base de données

```bash
psql -U your_user -d your_database -f encryption_setup.sql
```

Ce script :
- Active `pgcrypto`
- Crée `EMP_INTERNAL` (données chiffrées sur disque)
- Crée la vue `EMP_VIEW` (accès transparent en clair)
- Crée les triggers INSTEAD OF (INSERT / UPDATE / DELETE)
- Insère 10 000 enregistrements générés aléatoirement

### Étape 2 – Lancer les benchmarks

```bash
python benchmark.py
```

Les résultats sont affichés dans le terminal et deux graphiques sont générés :
- `benchmark_results.png` – temps absolu par opération
- `benchmark_ratio.png`   – ratio de surcharge chiffré/plain

---

## Architecture

```
EMP_VIEW  (vue PostgreSQL – accès application)
    │
    ├── INSTEAD OF INSERT  → trigger_view_insert()  → encrypt_sal() → EMP_INTERNAL
    ├── INSTEAD OF UPDATE  → trigger_view_update()  → encrypt_sal() → EMP_INTERNAL
    ├── INSTEAD OF DELETE  → trigger_view_delete()              → EMP_INTERNAL
    └── SELECT             → decrypt_sal(SAL)        ← EMP_INTERNAL
```

### Choix techniques

| Aspect | Choix | Justification |
|---|---|---|
| Algorithme | AES-256 | Standard industriel, résistant aux attaques connues |
| Mode | CBC | Masque les patterns (≠ ECB), fourni par pgcrypto |
| Stockage | `BYTEA` | Format binaire natif PostgreSQL |
| Interface | Vue + triggers | Transparent pour l'application |
| Clé | Variable de session | `SET myapp.encryption_key = '...'` |

---

## Structure des fichiers

```
.
├── encryption_setup.sql   # Script SQL : tables, fonctions, triggers, données
├── benchmark.py           # Script Python : benchmarks + graphiques
└── README.md              # Ce fichier
```

---

## Notes de sécurité

> ⚠️ La clé de chiffrement est définie via une variable de session PostgreSQL.
> En production, utilisez un gestionnaire de secrets (Vault, AWS KMS, etc.)
> et ne codez jamais la clé en dur.
