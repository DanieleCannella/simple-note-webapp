import mysql.connector
from mysql.connector import Error, pooling
import logging
from flask import g
import os

logger = logging.getLogger(__name__)

try:
    db_pool = mysql.connector.pooling.MySQLConnectionPool(
        pool_name=os.getenv("DB_POOL_NAME"),
        pool_size=int(os.getenv("DB_POOL_SIZE")), #mantiene sempre un pool di DB_POOL_SIZE connesioni al db pronte
        pool_reset_session=True,
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME")
    )
    logger.info("Connection pool al database inizializzato con successo.")
except Error as e:
    logger.critical(f"Errore critico durante la creazione del connection pool: {e}")
    db_pool = None

def get_db_connection():
    """Connessione prelevata dal pool invece che creata da zero"""
    if db_pool is None:
        logger.error("Il pool di connessioni non è disponibile.")
        return None
        
    try:
        return db_pool.get_connection()
    except Error as e:
        logger.error(f"Errore durante il recupero della connessione dal pool: {e}")
        return None

def get_db():
    """Recupera o crea la connessione per la richiesta corrente in Flask 'g'"""
    if 'db' not in g:
        g.db = get_db_connection()
    return g.db

def close_db(e=None):
    """Restituisce la connessione al pool"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_app(app):
    """
    Registra la funzione di teardown (close_db) in Flask per garantire che la
    connessione al DB venga restituita al pool al termine di ogni richiesta.
    """
    app.teardown_appcontext(close_db)


def get_db_and_cursor(dictionary=True):
    conn = get_db()
    if conn is None:
        raise Error("Impossibile comunicare con il database: connessione assente.")
    return conn, conn.cursor(dictionary=dictionary)

def get_cursor(dictionary=True):
    conn = get_db()
    if conn is None:
        raise Error("Impossibile comunicare con il database: connessione assente.")
    return conn.cursor(dictionary=dictionary)