import sys
import logging
from db_connection import get_db_connection
from sqlite3 import IntegrityError, Error
from bcrypt import hashpw, gensalt


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


logging.info("Inizio l'inizializzazione del database...")

conn = get_db_connection()

try:
    with open('schema.sql') as f:
        conn.executescript(f.read())
    logging.info("Schema SQL ('schema.sql') eseguito con successo.")
except FileNotFoundError:
    logging.critical("Impossibile trovare il file 'schema.sql'. Verifica il percorso.", exc_info=True)
    sys.exit(1)
except Error as e:
    logging.critical(f"Errore del database durante la creazione dello schema: {e}", exc_info=True)
    sys.exit(1)

try:

    #inserisco un utente Admin di default
    logging.info("Creazione dell'utente Admin di default in corso...")
    username = "Admin"
    password = "admin".encode("utf-8")
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, hashpw(password, gensalt()).decode("utf-8")),
    )

    #creo il ruolo Admin
    conn.execute(
    "INSERT INTO roles (role) VALUES (?)",
    ("Admin",)
    )

    # Fornisco all'utente Admin il ruolo Admin
    conn.execute(
        """
        INSERT INTO user_role (user_id, role_id)
        SELECT u.id, r.id
        FROM users u, roles r
        WHERE u.username = ? AND r.role = ?
        """,
        ("Admin", "Admin")
    )
    conn.commit()

    logging.info("Utente Admin base e ruoli configurati con successo.")

except IntegrityError as e:
    logging.critical(f"L'utente Admin esiste già o c'è un conflitto di integrità: {e}")
    conn.rollback()
except Error as e:
    logging.critical(f"Errore del database durante l'inserimento dell'utente Admin: {e}", exc_info=True)
    conn.rollback()
finally:
    conn.close()
    logging.info("Connessione al database chiusa correttamente. Script terminato.")