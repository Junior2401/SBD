"""
Projet : Évaluation expérimentale du chiffrement au repos (PostgreSQL + pgcrypto)
Q2 : Mesure de la surcharge due au chiffrement AES-256 CBC

Dépendances :
    pip install psycopg2-binary matplotlib numpy scipy

Usage :
    python benchmark.py
"""

import time
import statistics
import numpy as np
import matplotlib.pyplot as plt
import psycopg2
from psycopg2.extras import execute_batch

# =============================================================
# Configuration de la connexion PostgreSQL
# =============================================================
DB_CONFIG = {
    "host":     "localhost",
    "port":     5432,
    "dbname":   "demo",
    "user":     "postgres",
    "password": "260322",
}

ENCRYPTION_KEY = "projet_sgbd_cle_secrete_2025!!"
N_VALUES       = [100, 500, 1000, 5000, 10000]
N_REPEATS      = 5


# =============================================================
# Utilitaires
# =============================================================

def get_connection():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False
    return conn


def set_key(cur):
    """Définit la clé de chiffrement pour la session."""
    cur.execute(f"SET myapp.encryption_key = '{ENCRYPTION_KEY}'")


def generate_employees(n, start_id=1):
    """Génère n enregistrements aléatoires (SAL ~ N(5000, 500²))."""
    jobs = ["ANALYST", "CLERK", "MANAGER", "SALESMAN", "PRESIDENT"]
    records = []
    for i in range(n):
        sal = int(np.clip(np.random.normal(5000, 500), 1000, 9000))
        records.append((
            start_id + i,
            f"EMP_{start_id + i}",
            np.random.choice(jobs),
            "2020-01-01",
            sal,
        ))
    return records


def reset_tables(cur):
    """Vide les tables avant chaque run."""
    cur.execute("DELETE FROM EMP_INTERNAL")
    cur.execute("DELETE FROM emp_plain")


# =============================================================
# Création de la table non chiffrée (référence)
# =============================================================
SETUP_PLAIN = """
DROP TABLE IF EXISTS emp_plain;
CREATE TABLE emp_plain (
    EMPNO    INT PRIMARY KEY,
    ENAME    VARCHAR(256),
    JOB      VARCHAR(256),
    HIREDATE DATE,
    SAL      INT
);
"""


# =============================================================
# Fonctions de mesure
# =============================================================

def measure_insert(cur, table, records, encrypted=False):
    """Mesure le temps d'INSERT de `records` dans `table`."""
    if encrypted:
        sql = "INSERT INTO EMP_VIEW (EMPNO, ENAME, JOB, HIREDATE, SAL) VALUES (%s,%s,%s,%s,%s)"
    else:
        sql = "INSERT INTO emp_plain (EMPNO, ENAME, JOB, HIREDATE, SAL) VALUES (%s,%s,%s,%s,%s)"

    t0 = time.perf_counter()
    execute_batch(cur, sql, records, page_size=500)
    t1 = time.perf_counter()
    return t1 - t0


def measure_select_all(cur, encrypted=False):
    """Mesure le temps de SELECT * (scan complet)."""
    if encrypted:
        sql = "SELECT * FROM EMP_VIEW"
    else:
        sql = "SELECT * FROM emp_plain"

    t0 = time.perf_counter()
    cur.execute(sql)
    cur.fetchall()
    t1 = time.perf_counter()
    return t1 - t0


def measure_select_filter(cur, encrypted=False):
    """Mesure le temps de SELECT avec filtre SAL > 5000."""
    if encrypted:
        sql = "SELECT * FROM EMP_VIEW WHERE SAL > 5000"
    else:
        sql = "SELECT * FROM emp_plain WHERE SAL > 5000"

    t0 = time.perf_counter()
    cur.execute(sql)
    cur.fetchall()
    t1 = time.perf_counter()
    return t1 - t0


def measure_update(cur, encrypted=False):
    """Mesure le temps d'UPDATE de tous les salaires (+10%)."""
    if encrypted:
        sql = "UPDATE EMP_VIEW SET SAL = (SAL * 1.1)::INT"
    else:
        sql = "UPDATE emp_plain SET SAL = (SAL * 1.1)::INT"

    t0 = time.perf_counter()
    cur.execute(sql)
    t1 = time.perf_counter()
    return t1 - t0


# =============================================================
# Boucle principale de benchmarking
# =============================================================

def run_benchmarks():
    results = {
        "n": N_VALUES,
        "insert":         {"plain": [], "encrypted": []},
        "select_all":     {"plain": [], "encrypted": []},
        "select_filter":  {"plain": [], "encrypted": []},
        "update":         {"plain": [], "encrypted": []},
    }

    conn = get_connection()

    with conn.cursor() as cur:
        set_key(cur)
        cur.execute(SETUP_PLAIN)
        conn.commit()

    for n in N_VALUES:
        print(f"\n=== n = {n} ===")
        records = generate_employees(n)

        for mode in ("plain", "encrypted"):
            enc = (mode == "encrypted")
            times_insert        = []
            times_select_all    = []
            times_select_filter = []
            times_update        = []

            for rep in range(N_REPEATS):
                with conn.cursor() as cur:
                    set_key(cur)
                    reset_tables(cur)
                    conn.commit()

                    # INSERT
                    t = measure_insert(cur, None, records, encrypted=enc)
                    conn.commit()
                    times_insert.append(t)

                    # SELECT *
                    t = measure_select_all(cur, encrypted=enc)
                    times_select_all.append(t)

                    # SELECT avec filtre
                    t = measure_select_filter(cur, encrypted=enc)
                    times_select_filter.append(t)

                    # UPDATE
                    t = measure_update(cur, encrypted=enc)
                    conn.commit()
                    times_update.append(t)

            results["insert"][mode].append(statistics.mean(times_insert))
            results["select_all"][mode].append(statistics.mean(times_select_all))
            results["select_filter"][mode].append(statistics.mean(times_select_filter))
            results["update"][mode].append(statistics.mean(times_update))

            print(f"  [{mode:>9}] INSERT={results['insert'][mode][-1]:.3f}s  "
                  f"SELECT_ALL={results['select_all'][mode][-1]:.3f}s  "
                  f"FILTER={results['select_filter'][mode][-1]:.3f}s  "
                  f"UPDATE={results['update'][mode][-1]:.3f}s")

    conn.close()
    return results


# =============================================================
# Visualisation
# =============================================================

def plot_results(results):
    ops   = ["insert", "select_all", "select_filter", "update"]
    titles = {
        "insert":        "INSERT (n enregistrements)",
        "select_all":    "SELECT * (scan complet)",
        "select_filter": "SELECT avec filtre SAL > 5000",
        "update":        "UPDATE (tous les salaires)",
    }
    n_vals = results["n"]

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    fig.suptitle("Surcharge du chiffrement AES-256 CBC (PostgreSQL + pgcrypto)",
                 fontsize=14, fontweight="bold")

    for ax, op in zip(axes.flat, ops):
        plain     = results[op]["plain"]
        encrypted = results[op]["encrypted"]
        overhead  = [((e - p) / p * 100) if p > 0 else 0
                     for p, e in zip(plain, encrypted)]

        ax.plot(n_vals, plain,     "o-",  label="Sans chiffrement", color="#2196F3")
        ax.plot(n_vals, encrypted, "s--", label="Avec chiffrement",  color="#F44336")

        # Annotation du overhead en %
        for x, y, ov in zip(n_vals, encrypted, overhead):
            ax.annotate(f"+{ov:.0f}%", xy=(x, y),
                        textcoords="offset points", xytext=(4, 4),
                        fontsize=7, color="#F44336")

        ax.set_title(titles[op])
        ax.set_xlabel("Nombre d'enregistrements (n)")
        ax.set_ylabel("Temps (secondes)")
        ax.legend(fontsize=8)
        ax.grid(True, linestyle="--", alpha=0.5)
        ax.set_xscale("log")

    plt.tight_layout()
    plt.savefig("benchmark_results.png", dpi=150, bbox_inches="tight")
    plt.show()
    print("\nGraphique sauvegardé : benchmark_results.png")


def plot_overhead_ratio(results):
    """Graphique du ratio de surcharge (temps_chiffré / temps_plain)."""
    ops    = ["insert", "select_all", "select_filter", "update"]
    labels = ["INSERT", "SELECT *", "SELECT filtre", "UPDATE"]
    n_vals = results["n"]
    colors = ["#E91E63", "#9C27B0", "#FF9800", "#4CAF50"]

    fig, ax = plt.subplots(figsize=(10, 5))
    for op, label, color in zip(ops, labels, colors):
        ratio = [e / p if p > 0 else 1
                 for p, e in zip(results[op]["plain"], results[op]["encrypted"])]
        ax.plot(n_vals, ratio, "o-", label=label, color=color, linewidth=2)

    ax.axhline(y=1, color="black", linestyle="--", linewidth=1, label="Référence (×1)")
    ax.set_title("Ratio de surcharge : temps_chiffré / temps_plain")
    ax.set_xlabel("Nombre d'enregistrements (n)")
    ax.set_ylabel("Ratio (×)")
    ax.legend()
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.set_xscale("log")

    plt.tight_layout()
    plt.savefig("benchmark_ratio.png", dpi=150, bbox_inches="tight")
    plt.show()
    print("Graphique sauvegardé : benchmark_ratio.png")


# =============================================================
# Point d'entrée
# =============================================================

if __name__ == "__main__":
    print("Démarrage des benchmarks...")
    results = run_benchmarks()

    print("\nGénération des graphiques...")
    plot_results(results)
    plot_overhead_ratio(results)

    print("\nBenchmarks terminés.")
