import sys
import logging
import os
from db_connections import get_db_connection
from mysql.connector import Error
from bcrypt import hashpw, gensalt
from dotenv import load_dotenv

load_dotenv() 

logging.basicConfig(
    level=getattr(logging, os.getenv("LOGGING_LEVEL", "INFO")),
    format='%(asctime)s | %(levelname)-8s | [%(filename)s:%(lineno)d - %(funcName)s()] | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logging.info("Inizio l'inizializzazione del database...")

conn = get_db_connection()

if conn is None:
    logging.critical("Impossibile connettersi al database. Uscita.")
    sys.exit(1)

cursor = conn.cursor()

try:
    with open('schema.sql') as f:
        sql_script = f.read()
        sql_commands = sql_script.split(';')
        
        for command in sql_commands:
            if command.strip():
                cursor.execute(command)
                
    logging.info("Schema SQL controllato/eseguito con successo.")
except FileNotFoundError:
    logging.critical("Impossibile trovare il file 'schema.sql'. Verifica il percorso.")
    if cursor: cursor.close()
    if conn: conn.close()
    sys.exit(1)
except Error as e:
    logging.critical(f"Errore del database durante la creazione dello schema: {e}")
    if cursor: cursor.close()
    if conn: conn.close()
    sys.exit(1)

try:
    cursor.execute("SELECT count(*) FROM roles WHERE role = 'Admin'")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO roles (role, level) VALUES (%s, %s)", ("Admin", 10))
        cursor.execute("INSERT INTO roles (role, level) VALUES (%s, %s)", ("Moderator", 5))
        logging.info("Ruoli di base creati.")

    username = "Admin"
    cursor.execute("SELECT count(*) FROM users WHERE username = %s", (username,))
    
    if cursor.fetchone()[0] == 0:
        logging.info("Creazione dell'utente Admin di default in corso...")
        password = "admin".encode("utf-8")
        
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, hashpw(password, gensalt()).decode("utf-8"))
        )

        cursor.execute(
            """
            INSERT INTO user_role (user_id, role_id)
            SELECT u.id, r.id
            FROM users u, roles r
            WHERE u.username = %s AND r.role = %s
            """,
            ("Admin", "Admin")
        )
        logging.info("Utente Admin base configurato con successo.")
    else:
        logging.info("Il database è già inizializzato (Admin e ruoli già presenti).")

    conn.commit()

except Error as e:
    logging.critical(f"Errore del database durante l'inserimento dei dati iniziali: {e}", exc_info=True)
    conn.rollback()
finally:
    if cursor:
        cursor.close()
    if conn:
        conn.close()
    logging.info("Connessione al database chiusa correttamente. Script terminato.")