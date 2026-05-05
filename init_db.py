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
    format='%(asctime)s | %(levelname)-8s | [%(filename)s:%(lineno)d] | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

logger.info("Starting database initialization...")

conn = get_db_connection()

if conn is None:
    logging.critical("Database connection failed. Exiting.")
    sys.exit(1)

cursor = conn.cursor()

try:
    with open('schema.sql') as f:
        sql_script = f.read()
        sql_commands = sql_script.split(';')
        
        for command in sql_commands:
            if command.strip():
                cursor.execute(command)
                
    logging.info("SQL schema verified and executed successfully.")
except FileNotFoundError:
    logging.critical("File 'schema.sql' not found. Please verify the path.")
    if cursor: cursor.close()
    if conn: conn.close()
    sys.exit(1)
except Error as e:
    logging.critical("Database error during schema creation: %s", e)
    if cursor: cursor.close()
    if conn: conn.close()
    sys.exit(1)

try:
    cursor.execute("SELECT count(*) FROM roles WHERE role = 'Admin'")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO roles (role, level) VALUES (%s, %s)", ("Admin", 10))
        cursor.execute("INSERT INTO roles (role, level) VALUES (%s, %s)", ("Moderator", 5))
        logging.info("Base roles created successfully.")

    username = "Admin"
    cursor.execute("SELECT count(*) FROM users WHERE username = %s", (username,))
    
    if cursor.fetchone()[0] == 0:
        logging.info("Creating default Admin user...")
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
        logging.info("Default Admin user configured successfully.")
    else:
        logging.info("Database is already initialized (Admin and roles present).")

    conn.commit()

except Error as e:
    logging.critical("Database error during initial data insertion: %s", e, exc_info=True)
    conn.rollback()
finally:
    if cursor:
        cursor.close()
    if conn:
        conn.close()
    logging.info("Database connection closed gracefully. Script terminated.")