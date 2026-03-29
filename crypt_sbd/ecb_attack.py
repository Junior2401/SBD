"""
Bonus Q3 : Attaque par analyse de fréquences sur le mode ECB
=============================================================
Démonstration que le mode ECB est vulnérable à une attaque passive :
un attaquant qui accède aux données chiffrées sur disque peut reconstituer
la distribution des salaires SANS connaître la clé.

Dépendances :
    pip install psycopg2-binary matplotlib numpy scipy

Usage :
    1. Exécutez d'abord ecb_setup.sql dans PostgreSQL
    2. python ecb_attack.py
"""

import psycopg2
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from collections import Counter
from scipy import stats

# =============================================================
# Configuration  ← ADAPTEZ
# =============================================================
DB_CONFIG = {
    "host":     "localhost",
    "port":     5432,
    "dbname":   "demo",
    "user":     "postgres",
    "password": "260322",   # ← votre mot de passe
}
ENCRYPTION_KEY = "projet_sgbd_cle_secrete_2025!!"


# =============================================================
# Connexion
# =============================================================

def get_connection():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(f"SET myapp.encryption_key = '{ENCRYPTION_KEY}'")
    return conn


# =============================================================
# Étape 1 : Récupérer les données chiffrées (vue de l'attaquant)
#           L'attaquant voit les BYTEA sur disque, pas les clairs
# =============================================================

def get_encrypted_data(conn):
    """
    Simule un attaquant qui lit la table EMP_ECB directement sur disque.
    Il voit les colonnes chiffrées (BYTEA) mais PAS les salaires en clair.
    """
    with conn.cursor() as cur:
        # L'attaquant lit la table brute (pas la vue qui déchiffre)
        cur.execute("SELECT SAL_ECB FROM EMP_ECB")
        rows = cur.fetchall()
    # Chaque valeur est un bytes Python (le chiffré ECB)
    return [bytes(row[0]) for row in rows]


def get_plaintext_data(conn):
    """Récupère les salaires en clair (pour valider l'attaque)."""
    with conn.cursor() as cur:
        cur.execute("SELECT SAL FROM EMP_ECB_VIEW ORDER BY EMPNO")
        rows = cur.fetchall()
    return [row[0] for row in rows]


def get_cbc_encrypted_data(conn):
    """Récupère les chiffrés CBC pour comparaison."""
    with conn.cursor() as cur:
        cur.execute("SELECT SAL FROM EMP_INTERNAL")
        rows = cur.fetchall()
    return [bytes(row[0]) for row in rows]


# =============================================================
# Étape 2 : Attaque par analyse de fréquences
#           L'attaquant compte les occurrences de chaque chiffré
# =============================================================

def frequency_attack(encrypted_values):
    """
    Attaque par analyse de fréquences sur les chiffrés ECB.

    Principe :
    - En ECB, encrypt(k, m) = encrypt(k, m) toujours
    - Donc deux salaires identiques produisent le même BYTEA
    - L'attaquant peut compter les fréquences des chiffrés
    - Il obtient la distribution des salaires sans connaître la clé

    Retourne :
        - freq_cipher : Counter {chiffré → nombre d'occurrences}
        - ranked      : liste triée [(chiffré, count), ...] par fréquence
    """
    freq_cipher = Counter(encrypted_values)
    ranked = freq_cipher.most_common()
    return freq_cipher, ranked


def map_frequencies_to_values(ranked_cipher, plaintext_values):
    """
    Valide l'attaque : mappe chaque chiffré au salaire correspondant.
    En pratique, l'attaquant ne connaît pas les clairs — mais on peut
    vérifier que la distribution reconstruite correspond à la vraie.
    """
    freq_plain = Counter(plaintext_values)
    ranked_plain = freq_plain.most_common()

    # Tri des chiffrés par fréquence → tri des clairs par fréquence
    # Les rangs coïncident parfaitement en ECB
    mapping = {}
    for (cipher, c_count), (plain, p_count) in zip(ranked_cipher, ranked_plain):
        mapping[cipher] = plain  # c_count == p_count (même distribution !)

    return mapping


# =============================================================
# Étape 3 : Comparaison ECB vs CBC
# =============================================================

def compare_ecb_vs_cbc(ecb_values, cbc_values):
    """
    Montre que CBC produit des chiffrés quasi-uniques (résistant),
    alors qu'ECB expose les répétitions.
    """
    ecb_unique = len(set(ecb_values))
    cbc_unique = len(set(cbc_values))
    total      = len(ecb_values)

    print(f"\n{'='*55}")
    print(f"  Comparaison ECB vs CBC ({total} enregistrements)")
    print(f"{'='*55}")
    print(f"  Mode ECB : {ecb_unique:>6} chiffrés uniques / {total}  "
          f"({ecb_unique/total*100:.1f}% uniques)")
    print(f"  Mode CBC : {cbc_unique:>6} chiffrés uniques / {total}  "
          f"({cbc_unique/total*100:.1f}% uniques)")
    print(f"{'='*55}")
    print(f"  → ECB expose {total - ecb_unique} répétitions exploitables !")
    print(f"  → CBC masque totalement les répétitions.\n")

    return ecb_unique, cbc_unique


# =============================================================
# Étape 4 : Visualisations
# =============================================================

def plot_full_analysis(ecb_encrypted, cbc_encrypted, plaintext_values, ranked_cipher):
    """
    4 graphiques :
    1. Distribution réelle des salaires (clair)
    2. Distribution des fréquences des chiffrés ECB (vue attaquant)
    3. Distribution des fréquences des chiffrés CBC (vue attaquant)
    4. Superposition : distribution reconstruite vs réelle
    """
    fig = plt.figure(figsize=(14, 10))
    fig.suptitle("Bonus Q3 : Attaque par analyse de fréquences — ECB vs CBC",
                 fontsize=14, fontweight="bold")
    gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.4, wspace=0.35)

    # ── Graphique 1 : Distribution réelle des salaires ──────────
    ax1 = fig.add_subplot(gs[0, 0])
    ax1.hist(plaintext_values, bins=50, color="#2196F3", edgecolor="white", linewidth=0.5)
    ax1.set_title("1. Distribution réelle des SAL (en clair)", fontweight="bold")
    ax1.set_xlabel("Salaire (€)")
    ax1.set_ylabel("Fréquence")

    mu, sigma = np.mean(plaintext_values), np.std(plaintext_values)
    ax1.axvline(mu, color="red", linestyle="--", linewidth=1.5, label=f"μ={mu:.0f}")
    ax1.legend(fontsize=9)
    ax1.grid(True, linestyle="--", alpha=0.4)

    # ── Graphique 2 : Fréquences ECB (vue attaquant) ────────────
    ax2 = fig.add_subplot(gs[0, 1])
    ecb_counts = sorted([v for v in Counter(ecb_encrypted).values()], reverse=True)
    ax2.bar(range(len(ecb_counts)), ecb_counts, color="#F44336", width=1.0)
    ax2.set_title("2. Fréquences des chiffrés ECB\n(vue attaquant — sans la clé !)",
                  fontweight="bold")
    ax2.set_xlabel("Rang du chiffré (par fréquence)")
    ax2.set_ylabel("Nombre d'occurrences")
    ax2.grid(True, linestyle="--", alpha=0.4)

    # Annotation : le chiffré le plus fréquent
    ax2.annotate(f"Top chiffré\n({ecb_counts[0]} fois)",
                 xy=(0, ecb_counts[0]),
                 xytext=(len(ecb_counts)*0.2, ecb_counts[0]*0.8),
                 arrowprops=dict(arrowstyle="->", color="black"),
                 fontsize=8)

    # ── Graphique 3 : Fréquences CBC (vue attaquant) ────────────
    ax3 = fig.add_subplot(gs[1, 0])
    cbc_counts = sorted([v for v in Counter(cbc_encrypted).values()], reverse=True)
    ax3.bar(range(len(cbc_counts)), cbc_counts, color="#4CAF50", width=1.0)
    ax3.set_title("3. Fréquences des chiffrés CBC\n(vue attaquant — sans la clé !)",
                  fontweight="bold")
    ax3.set_xlabel("Rang du chiffré (par fréquence)")
    ax3.set_ylabel("Nombre d'occurrences")
    ax3.set_ylim(0, max(ecb_counts) * 1.1)  # même échelle qu'ECB
    ax3.grid(True, linestyle="--", alpha=0.4)
    ax3.text(len(cbc_counts)*0.4, max(ecb_counts)*0.7,
             "Tous les chiffrés\nsont uniques →\naucune info fuie",
             fontsize=8, color="#2E7D32",
             bbox=dict(boxstyle="round", facecolor="lightgreen", alpha=0.5))

    # ── Graphique 4 : Distribution reconstruite vs réelle ───────
    ax4 = fig.add_subplot(gs[1, 1])

    # L'attaquant reconstruit la distribution depuis les fréquences ECB
    # en supposant que les valeurs les plus fréquentes correspondent
    # aux salaires les plus fréquents (ce qui est vrai !)
    freq_plain  = Counter(plaintext_values)
    freq_cipher = Counter(ecb_encrypted)

    # Trier les deux par fréquence décroissante
    plain_ranked  = [v for v, _ in freq_plain.most_common()]
    cipher_ranked = [c for c, _ in freq_cipher.most_common()]

    # Reconstruction : l'attaquant assigne les valeurs par rang
    reconstructed = []
    cipher_to_plain = {c: p for c, p in zip(cipher_ranked, plain_ranked)}
    for cipher in ecb_encrypted:
        reconstructed.append(cipher_to_plain.get(cipher, 0))

    ax4.hist(plaintext_values,  bins=50, alpha=0.5, color="#2196F3",
             label="Distribution réelle", edgecolor="white")
    ax4.hist(reconstructed,     bins=50, alpha=0.5, color="#FF5722",
             label="Distribution reconstruite (attaquant)", edgecolor="white")
    ax4.set_title("4. Reconstruction de la distribution\npar l'attaquant (sans la clé !)",
                  fontweight="bold")
    ax4.set_xlabel("Salaire (€)")
    ax4.set_ylabel("Fréquence")
    ax4.legend(fontsize=8)
    ax4.grid(True, linestyle="--", alpha=0.4)

    plt.savefig("ecb_attack_analysis.png", dpi=150, bbox_inches="tight")
    plt.show()
    print("✓ Graphique sauvegardé : ecb_attack_analysis.png")

    return reconstructed


def print_attack_results(ranked_cipher, plaintext_values, ecb_encrypted):
    """Affiche un résumé chiffré de l'attaque."""
    freq_plain  = Counter(plaintext_values)
    freq_cipher = Counter(ecb_encrypted)

    plain_ranked  = [(v, c) for v, c in freq_plain.most_common(10)]
    cipher_ranked = list(freq_cipher.most_common(10))

    print("\n" + "="*65)
    print("  Résultat de l'attaque par fréquences (top 10)")
    print("="*65)
    print(f"  {'Rang':<5} {'Chiffré (16 premiers octets)':<30} {'Fréq.':>6} {'SAL réel':>10} {'Fréq.':>6}")
    print("-"*65)
    for i, ((cipher, c_count), (plain, p_count)) in enumerate(
            zip(cipher_ranked, plain_ranked), 1):
        hex_preview = cipher.hex()[:30] + "..."
        print(f"  #{i:<4} {hex_preview:<30} {c_count:>6}   {plain:>8} €  {p_count:>6}")
    print("="*65)
    print("  → Les rangs de fréquence coïncident parfaitement !")
    print("  → L'attaquant reconnaît les valeurs les plus communes")
    print("    sans jamais déchiffrer (sans connaître la clé).\n")


# =============================================================
# Point d'entrée
# =============================================================

if __name__ == "__main__":
    print("="*55)
    print("  Bonus Q3 : Attaque par analyse de fréquences (ECB)")
    print("="*55)

    conn = get_connection()

    print("\n[1/4] Récupération des données chiffrées...")
    ecb_encrypted  = get_encrypted_data(conn)
    plaintext      = get_plaintext_data(conn)
    cbc_encrypted  = get_cbc_encrypted_data(conn)
    print(f"      {len(ecb_encrypted)} enregistrements récupérés.")

    print("\n[2/4] Analyse de fréquences (attaque ECB)...")
    freq_cipher, ranked_cipher = frequency_attack(ecb_encrypted)
    print_attack_results(ranked_cipher, plaintext, ecb_encrypted)

    print("[3/4] Comparaison ECB vs CBC...")
    compare_ecb_vs_cbc(ecb_encrypted, cbc_encrypted)

    print("[4/4] Génération des graphiques...")
    reconstructed = plot_full_analysis(ecb_encrypted, cbc_encrypted, plaintext, ranked_cipher)

    # Statistique finale : précision de la reconstruction
    correct = sum(1 for r, p in zip(reconstructed, plaintext) if r == p)
    print(f"\n✓ Précision de la reconstruction : {correct}/{len(plaintext)} "
          f"({correct/len(plaintext)*100:.1f}% des salaires retrouvés par rang de fréquence)")
    print("\nAttaque terminée.")

    conn.close()
