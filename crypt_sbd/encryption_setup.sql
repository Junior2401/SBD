-- =============================================================
-- Projet : Chiffrement au repos avec pgcrypto (AES-256 CBC)
-- Table  : EMP(EMPNO, ENAME, JOB, HIREDATE, SAL)
-- Colonne chiffrée : SAL (stockée en bytea)
-- =============================================================

-- 1. Activation de l'extension pgcrypto
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =============================================================
-- 2. Clé de chiffrement (à stocker de façon sécurisée en prod !)
--    On utilise ici une variable de session PostgreSQL.
-- =============================================================
-- Pour définir la clé en session :
--   SET myapp.encryption_key = 'ma_cle_secrete_32b';
-- On utilise une valeur par défaut ici pour les tests.

-- =============================================================
-- 3. Table EMP avec SAL chiffrée sur disque (bytea)
-- =============================================================
DROP TABLE IF EXISTS EMP;

CREATE TABLE EMP (
    EMPNO    INT PRIMARY KEY,
    ENAME    VARCHAR(256),
    JOB      VARCHAR(256),
    HIREDATE DATE,
    SAL      BYTEA        -- colonne chiffrée (AES-256 CBC)
);

-- =============================================================
-- 4. Fonctions utilitaires : chiffrement / déchiffrement
-- =============================================================

-- Clé de 32 octets (256 bits) pour AES-256
-- En production, récupérer depuis une variable de config sécurisée.
CREATE OR REPLACE FUNCTION get_encryption_key()
RETURNS BYTEA AS $$
BEGIN
    -- Dérive exactement 32 octets depuis la clé configurée
    RETURN substring(
        digest(
            current_setting('myapp.encryption_key', true),
            'sha256'
        ), 1, 32
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;


-- Chiffre un entier (SAL) → bytea (AES-256 CBC)
CREATE OR REPLACE FUNCTION encrypt_sal(p_sal INT)
RETURNS BYTEA AS $$
BEGIN
    RETURN pgp_sym_encrypt(
        p_sal::TEXT,                  -- texte clair
        encode(get_encryption_key(), 'hex'),  -- clé
        'cipher-algo=aes256'          -- mode AES-256 (CBC par défaut dans pgp_sym_encrypt)
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;


-- Déchiffre un bytea → entier (SAL)
CREATE OR REPLACE FUNCTION decrypt_sal(p_encrypted BYTEA)
RETURNS INT AS $$
BEGIN
    RETURN pgp_sym_decrypt(
        p_encrypted,
        encode(get_encryption_key(), 'hex')
    )::INT;
EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'Échec du déchiffrement : clé incorrecte ou données corrompues.';
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- =============================================================
-- 5. Trigger : chiffrement automatique à l'INSERT et à l'UPDATE
-- =============================================================

CREATE OR REPLACE FUNCTION trigger_encrypt_sal()
RETURNS TRIGGER AS $$
BEGIN
    -- NEW.SAL contient la valeur en clair envoyée par l'application.
    -- On la remplace par sa version chiffrée avant écriture sur disque.
    IF NEW.SAL IS NOT NULL THEN
        NEW.SAL := encrypt_sal(
            -- Le trigger reçoit SAL en bytea (type de la colonne) ;
            -- on passe par une colonne intermédiaire en clair (voir vue ci-dessous).
            -- Astuce : on stocke temporairement le clair dans un champ texte fictif.
            -- Solution propre : utiliser une table shadow + vue (voir section 6).
            NULL  -- placeholder, remplacé par l'approche vue ci-dessous
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- =============================================================
-- 6. Approche recommandée : table interne + vue publique
--    L'application interagit uniquement avec la vue EMP_VIEW.
--    Le chiffrement/déchiffrement est transparent.
-- =============================================================

-- 6a. Table interne (données chiffrées)
DROP TABLE IF EXISTS EMP_INTERNAL CASCADE;

CREATE TABLE EMP_INTERNAL (
    EMPNO    INT PRIMARY KEY,
    ENAME    VARCHAR(256),
    JOB      VARCHAR(256),
    HIREDATE DATE,
    SAL      BYTEA   -- SAL chiffrée sur disque
);

-- 6b. Vue qui déchiffre SAL à la volée (lecture)
DROP VIEW IF EXISTS EMP_VIEW;

CREATE VIEW EMP_VIEW AS
SELECT
    EMPNO,
    ENAME,
    JOB,
    HIREDATE,
    decrypt_sal(SAL) AS SAL   -- SAL en clair pour l'application
FROM EMP_INTERNAL;

-- 6c. Fonction trigger INSTEAD OF INSERT sur la vue
CREATE OR REPLACE FUNCTION trigger_view_insert()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO EMP_INTERNAL (EMPNO, ENAME, JOB, HIREDATE, SAL)
    VALUES (
        NEW.EMPNO,
        NEW.ENAME,
        NEW.JOB,
        NEW.HIREDATE,
        encrypt_sal(NEW.SAL)   -- chiffrement transparent
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 6d. Fonction trigger INSTEAD OF UPDATE sur la vue
CREATE OR REPLACE FUNCTION trigger_view_update()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE EMP_INTERNAL
    SET ENAME    = NEW.ENAME,
        JOB      = NEW.JOB,
        HIREDATE = NEW.HIREDATE,
        SAL      = encrypt_sal(NEW.SAL)   -- rechiffrement transparent
    WHERE EMPNO = OLD.EMPNO;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 6e. Fonction trigger INSTEAD OF DELETE sur la vue
CREATE OR REPLACE FUNCTION trigger_view_delete()
RETURNS TRIGGER AS $$
BEGIN
    DELETE FROM EMP_INTERNAL WHERE EMPNO = OLD.EMPNO;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- 6f. Attachement des triggers à la vue
DROP TRIGGER IF EXISTS trg_emp_insert ON EMP_VIEW;
CREATE TRIGGER trg_emp_insert
    INSTEAD OF INSERT ON EMP_VIEW
    FOR EACH ROW EXECUTE FUNCTION trigger_view_insert();

DROP TRIGGER IF EXISTS trg_emp_update ON EMP_VIEW;
CREATE TRIGGER trg_emp_update
    INSTEAD OF UPDATE ON EMP_VIEW
    FOR EACH ROW EXECUTE FUNCTION trigger_view_update();

DROP TRIGGER IF EXISTS trg_emp_delete ON EMP_VIEW;
CREATE TRIGGER trg_emp_delete
    INSTEAD OF DELETE ON EMP_VIEW
    FOR EACH ROW EXECUTE FUNCTION trigger_view_delete();

-- =============================================================
-- 7. Génération de n enregistrements aléatoires (n = 10 000)
--    SAL ~ N(5000, 500²), tronqué à [1000, 9000]
-- =============================================================

SET myapp.encryption_key = 'projet_sgbd_cle_secrete_2025!!';  -- clé de test

DO $$
DECLARE
    n        INT := 10000;
    i        INT;
    sal_val  INT;
BEGIN
    FOR i IN 1..n LOOP
        -- Échantillonnage Box-Muller via random() (approximation normale)
        sal_val := GREATEST(1000, LEAST(9000,
            (5000 + 500 * sqrt(-2 * ln(random())) * cos(2 * pi() * random()))::INT
        ));

        INSERT INTO EMP_VIEW (EMPNO, ENAME, JOB, HIREDATE, SAL)
        VALUES (
            i,
            'EMP_' || i,
            (ARRAY['ANALYST','CLERK','MANAGER','SALESMAN','PRESIDENT'])[
                floor(random() * 5 + 1)::INT
            ],
            CURRENT_DATE - (random() * 3650)::INT,
            sal_val
        );
    END LOOP;
END;
$$;

-- =============================================================
-- 8. Vérifications
-- =============================================================

-- Voir les données en clair (via la vue)
-- SELECT * FROM EMP_VIEW LIMIT 5;

-- Voir les données chiffrées sur disque (bytea)
-- SELECT EMPNO, ENAME, SAL FROM EMP_INTERNAL LIMIT 5;

-- Vérifier la cohérence
-- SELECT v.EMPNO, v.SAL AS sal_clair, i.SAL AS sal_chiffre
-- FROM EMP_VIEW v JOIN EMP_INTERNAL i ON v.EMPNO = i.EMPNO
-- LIMIT 5;
