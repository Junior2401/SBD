-- =============================================================
-- Bonus Q3 : Chiffrement en mode ECB et attaque par fréquences
-- Comparaison ECB vs CBC pour illustrer la faiblesse d'ECB
-- =============================================================

-- 1. Table avec SAL chiffrée en ECB
DROP TABLE IF EXISTS EMP_ECB CASCADE;

CREATE TABLE EMP_ECB (
    EMPNO    INT PRIMARY KEY,
    ENAME    VARCHAR(256),
    JOB      VARCHAR(256),
    HIREDATE DATE,
    SAL_ECB  BYTEA   -- SAL chiffrée en AES-256 ECB
);

-- 2. Fonction de chiffrement ECB
--    pgcrypto expose AES-ECB via encrypt() (bas niveau, sans padding OpenPGP)
--    On chiffre le texte de SAL sur exactement 16 octets (bloc AES)
CREATE OR REPLACE FUNCTION encrypt_sal_ecb(p_sal INT)
RETURNS BYTEA AS $$
DECLARE
    plaintext BYTEA;
BEGIN
    -- Représentation fixe sur 16 octets (padding avec des espaces)
    plaintext := rpad(p_sal::TEXT, 16)::BYTEA;
    RETURN encrypt(plaintext, get_encryption_key(), 'aes-ecb');
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- 3. Fonction de déchiffrement ECB
CREATE OR REPLACE FUNCTION decrypt_sal_ecb(p_encrypted BYTEA)
RETURNS INT AS $$
BEGIN
    RETURN trim(convert_from(
        decrypt(p_encrypted, get_encryption_key(), 'aes-ecb'),
        'UTF8'
    ))::INT;
EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'Déchiffrement ECB échoué : %', SQLERRM;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- 4. Vue ECB (déchiffrement transparent)
DROP VIEW IF EXISTS EMP_ECB_VIEW;

CREATE VIEW EMP_ECB_VIEW AS
SELECT
    EMPNO,
    ENAME,
    JOB,
    HIREDATE,
    decrypt_sal_ecb(SAL_ECB) AS SAL
FROM EMP_ECB;

-- 5. Triggers INSTEAD OF pour EMP_ECB_VIEW
CREATE OR REPLACE FUNCTION trigger_ecb_insert()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO EMP_ECB (EMPNO, ENAME, JOB, HIREDATE, SAL_ECB)
    VALUES (NEW.EMPNO, NEW.ENAME, NEW.JOB, NEW.HIREDATE, encrypt_sal_ecb(NEW.SAL));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION trigger_ecb_update()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE EMP_ECB
    SET ENAME   = NEW.ENAME,
        JOB     = NEW.JOB,
        HIREDATE= NEW.HIREDATE,
        SAL_ECB = encrypt_sal_ecb(NEW.SAL)
    WHERE EMPNO = OLD.EMPNO;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ecb_insert ON EMP_ECB_VIEW;
CREATE TRIGGER trg_ecb_insert
    INSTEAD OF INSERT ON EMP_ECB_VIEW
    FOR EACH ROW EXECUTE FUNCTION trigger_ecb_insert();

DROP TRIGGER IF EXISTS trg_ecb_update ON EMP_ECB_VIEW;
CREATE TRIGGER trg_ecb_update
    INSTEAD OF UPDATE ON EMP_ECB_VIEW
    FOR EACH ROW EXECUTE FUNCTION trigger_ecb_update();

-- 6. Copier les données de EMP_INTERNAL → EMP_ECB (mêmes salaires, mode ECB)
SET myapp.encryption_key = 'projet_sgbd_cle_secrete_2025!!';

INSERT INTO EMP_ECB (EMPNO, ENAME, JOB, HIREDATE, SAL_ECB)
SELECT
    EMPNO,
    ENAME,
    JOB,
    HIREDATE,
    encrypt_sal_ecb(decrypt_sal(SAL))  -- déchiffre CBC → rechiffre ECB
FROM EMP_INTERNAL;

-- 7. Vérification : même valeur de SAL → même chiffré en ECB ?
-- SELECT
--     decrypt_sal_ecb(SAL_ECB) AS sal_clair,
--     encode(SAL_ECB, 'hex')   AS sal_ecb_hex,
--     COUNT(*)                 AS occurrences
-- FROM EMP_ECB
-- GROUP BY SAL_ECB, decrypt_sal_ecb(SAL_ECB)
-- ORDER BY occurrences DESC
-- LIMIT 20;
