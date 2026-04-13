import sqlite3

def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    # Abilita le Foreign Keys e il Cascade in SQLite
    conn.execute('PRAGMA foreign_keys = ON;')
    return conn
