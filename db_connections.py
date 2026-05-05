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
    logger.info("Database connection pool initialized (Size: %s)", os.getenv("DB_POOL_SIZE"))
except Error as e:
    logger.critical("Database pool initialization failed: %s", e)
    db_pool = None

def get_db_connection():
    """Fetch connection from the pool instead of creating a new one"""
    if db_pool is None:
        logger.error("Connection request denied: database pool is unavailable")
        return None
        
    try:
        return db_pool.get_connection()
    except Error as e:
        logger.error("Pool connection retrieval failed: %s", e)
        return None

def get_db():
    """Retrieve or create the connection for the current Flask request in 'g'"""
    if 'db' not in g:
        g.db = get_db_connection()
    return g.db

def close_db(e=None):
    """Return the connection to the pool"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_app(app):
    """
    Register the teardown function (close_db) in Flask to ensure that the
    DB connection is returned to the pool at the end of each request.
    """
    app.teardown_appcontext(close_db)

class DatabaseUnavailableError(Exception):
    """Raised when the connection pool is empty or the database is down."""
    pass

def get_db_and_cursor(dictionary=True):
    """
    Retrieves the active database connection and initializes a cursor.
    Ideal for write operations (INSERT, UPDATE, DELETE) where 'conn.commit()' is required.
    """
    conn = get_db()
    if conn is None:
        raise DatabaseUnavailableError("Database communication failed: missing connection")
    return conn, conn.cursor(dictionary=dictionary)

def get_cursor(dictionary=True):
    """
    Retrieves only a cursor from the active database connection.
    Ideal for read-only operations (SELECT) where no commit is needed.
    """
    conn = get_db()
    if conn is None:
        raise DatabaseUnavailableError("Database communication failed: missing connection")
    return conn.cursor(dictionary=dictionary)