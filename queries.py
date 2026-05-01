import logging
from mysql.connector import Error, IntegrityError
from bcrypt import hashpw, gensalt, checkpw
import db_connections
from datetime import timedelta

logger = logging.getLogger(__name__)
DUMMY_PASSWORD = b"password_finta"
DUMMY_HASH = hashpw(DUMMY_PASSWORD, gensalt())


def user_login(username, password):
    try:
        cursor = db_connections.get_cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user is None:
            checkpw(password.encode("utf-8"), DUMMY_HASH)
            logger.warning(f"Tentativo di accesso per utente inesistente: '{username}'")
            return False, "user_not_found", None
            
        elif not checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            logger.warning(f"Password errata per l'utente: '{username}'")
            return False, "wrong_password", None
            
        logger.info(f"L'utente '{username}' ha effettuato l'accesso")
        return True, None, user

    except Error as e:
        logger.error(f"Errore DB durante l'accesso per l'utente '{username}': {e}", exc_info=True)
        return False, "DB_error", None
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()


def staff_login(username, password):
    try:
        cursor = db_connections.get_cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user is None:
            checkpw(password.encode("utf-8"), DUMMY_HASH)
            logger.warning(f"Tentativo di accesso per staff inesistente: '{username}'")
            return False, "staff_not_found", None, None
            
        elif not checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            logger.warning(f"Password errata per lo staff: '{username}'")
            return False, "wrong_password", None, None
        
        cursor.execute("""
            SELECT R.role, R.level FROM user_role U_R
            JOIN roles R ON U_R.role_id = R.id
            WHERE U_R.user_id = %s
            ORDER BY R.level DESC LIMIT 1
        """, (user["id"],))
        role_data = cursor.fetchone()

        if role_data is None or role_data["level"] < 5:
            logger.warning(f"Permesso negato: l'utente '{username}' ha provato ad accedere allo staff")
            return False, "Permission_denied", None, None

        logger.info(f"Lo staff '{username}' (Livello {role_data['level']}) ha effettuato l'accesso")
        return True, None, user, role_data

    except Error as e:
        logger.error(f"Errore DB durante l'accesso staff '{username}': {e}", exc_info=True)
        return False, "DB_error", None, None
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()


def get_users_and_roles():
    try:
        cursor = db_connections.get_cursor(dictionary=True)
        cursor.execute("""
            SELECT U.id, U.username, COALESCE(R.role, 'User') as role 
            FROM users U 
            LEFT JOIN user_role U_R ON U.id = U_R.user_id 
            LEFT JOIN roles R ON U_R.role_id = R.id
        """)
        users_and_roles = cursor.fetchall()
        return True, None, users_and_roles
    except Error as e:
        logger.error(f"Errore DB durante il recupero degli utenti e ruoli: {e}", exc_info=True)
        return False, "DB_error", None
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()


def add_user(username, password, role, staff_username, staff_level):
    password_bytes = password.encode("utf-8")
    try:
        conn, cursor = db_connections.get_db_and_cursor(dictionary=True)
    
        if role == "User":
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s)",
                (username, hashpw(password_bytes, gensalt()).decode("utf-8"))
            )
            conn.commit()
            logger.info(f"Lo staff {staff_username} ha creato l'utente base: {username}")
            return True, None
        
        cursor.execute("SELECT id, role, level FROM roles WHERE role = %s", (role,))
        role_info = cursor.fetchone()
        
        if role_info is None:
            logger.warning(f"Tentativo di assegnare ruolo inesistente: {role} a {username}")
            return False, "unknown_role"

        if staff_level <= role_info["level"]:
            logger.warning(f"Permessi insufficienti: {staff_username} (Lvl {staff_level}) ha provato a creare un {role} (Lvl {role_info['level']})")
            return False, "permission_denied"

        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, hashpw(password_bytes, gensalt()).decode("utf-8"))
        )
        
        cursor.execute(
            """
            INSERT INTO user_role (user_id, role_id)
            SELECT id, %s FROM users WHERE username = %s
            """,
            (role_info["id"], username)
        )
        conn.commit()
        logger.info(f"Lo staff {staff_username} ha creato l'utente: {username} con ruolo {role}")
        return True, None
        
    except IntegrityError:
        logger.warning(f"Lo staff {staff_username} ha provato a creare un utente già presente: {username}")
        return False, "integrity_error"
    except Error as e:
        logger.error(f"Errore DB creazione utente {username} da {staff_username}: {e}", exc_info=True)
        return False, "DB_error"
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()


def delete_user(user_id, staff_username, staff_level):
    try:
        conn, cursor = db_connections.get_db_and_cursor(dictionary=True)
        
        cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        if cursor.fetchone() is None:
            return False, "user_not_found"
            
        cursor.execute("""
            SELECT MAX(R.level) as max_level FROM users U
            LEFT JOIN user_role UR ON U.id = UR.user_id
            LEFT JOIN roles R ON UR.role_id = R.id
            WHERE U.id = %s
        """, (user_id,))
        user_info = cursor.fetchone()
 
        user_level = user_info["max_level"] if user_info and user_info["max_level"] is not None else 0
        
        if staff_level <= user_level:
            logger.warning(f"Permessi insufficienti: {staff_username} (Lvl {staff_level}) ha provato a eliminare ID {user_id} (Lvl {user_level})")
            return False, "permission_denied"
            
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        logger.info(f"L'utente ID {user_id} è stato eliminato da {staff_username}")
        return True, None

    except Error as e:
        logger.error(f"Errore DB durante l'eliminazione dell'utente {user_id}: {e}", exc_info=True)
        return False, "DB_error"
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()


def update_role(user_id, role, staff_username, staff_level):
    try:
        conn, cursor = db_connections.get_db_and_cursor(dictionary=True)

        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        user_exists = cursor.fetchone()
        if user_exists is None:
            return False, "user_not_found"
            
        username = user_exists["username"]

        cursor.execute("""
            SELECT MAX(R.level) as max_level FROM users U
            LEFT JOIN user_role UR ON U.id = UR.user_id
            LEFT JOIN roles R ON UR.role_id = R.id
            WHERE U.id = %s
        """, (user_id,))
        user_info = cursor.fetchone()

        user_level = user_info["max_level"] if user_info and user_info["max_level"] is not None else 0

        if staff_level <= user_level:
            logger.warning(f"Permessi insufficienti: {staff_username} (Lvl {staff_level}) ha provato a modificare {username} (Lvl {user_level})")
            return False, "permission_denied"

        if role == "User":
            role_id = None
            role_level = 0
        else:
            cursor.execute("SELECT id, level FROM roles WHERE role = %s", (role,))
            role_data = cursor.fetchone()
            if role_data is None:
                logger.info(f"Tentativo di assegnare ruolo inesistente: {role} a {username}")
                return False, "unknown_role"
            role_id = role_data["id"]
            role_level = role_data["level"]

        if staff_level <= role_level:
            logger.warning(f"Permessi insufficienti: {staff_username} (Lvl {staff_level}) ha provato a promuovere {username} a {role} (Lvl {role_level})")
            return False, "permission_denied"

        cursor.execute("DELETE FROM user_role WHERE user_id = %s", (user_id,))

        if role_id is not None:
            cursor.execute(
                "INSERT INTO user_role (user_id, role_id) VALUES (%s, %s)",
                (user_id, role_id)
            )

        conn.commit()
        logger.info(f"Lo staff {staff_username} ha aggiornato il ruolo di {username} a {role}")
        return True, None

    except Error as e:
        logger.error(f"Errore DB aggiornamento ruolo utente ID {user_id} da {staff_username}: {e}", exc_info=True)
        return False, "DB_error"
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()

def get_user_notes_by_modified(user_id, ascending, limit, offset):
    order_dir = "ASC" if ascending else "DESC"
    try:
        cursor = db_connections.get_cursor(dictionary=True)
        query = f"SELECT * FROM notes WHERE user_id = %s ORDER BY last_modified {order_dir} LIMIT %s OFFSET %s"
        cursor.execute(query, (user_id, limit, offset))
        user_notes = cursor.fetchall()
        return True, None, user_notes
    except Error as e:
        logger.error(f"Errore DB: {e}", exc_info=True)
        return False, "DB_error", []
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()

def get_user_notes_by_created(user_id, ascending, limit, offset):
    order_dir = "ASC" if ascending else "DESC"
    try:
        cursor = db_connections.get_cursor(dictionary=True)
        query = f"SELECT * FROM notes WHERE user_id = %s ORDER BY created {order_dir} LIMIT %s OFFSET %s"
        cursor.execute(query, (user_id, limit, offset))
        user_notes = cursor.fetchall()
        return True, None, user_notes
    except Error as e:
        logger.error(f"Errore DB: {e}", exc_info=True)
        return False, "DB_error", []
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()

def get_user_notes_ordered_by_title(user_id, ascending, limit, offset):
    order_dir = "ASC" if ascending else "DESC"
    try:
        cursor = db_connections.get_cursor(dictionary=True)
        query = f"SELECT * FROM notes WHERE user_id = %s ORDER BY title {order_dir} LIMIT %s OFFSET %s"
        cursor.execute(query, (user_id, limit, offset))
        user_notes = cursor.fetchall()
        return True, None, user_notes
    except Error as e:
        logger.error(f"Errore DB: {e}", exc_info=True)
        return False, "DB_error", []
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()


def get_user_notes_count(user_id):
    try:
        cursor = db_connections.get_cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) as total FROM notes WHERE user_id = %s", (user_id,))
        result = cursor.fetchone()
        return True, None, result['total']
    except Error as e:
        logger.error(f"Errore DB conteggio note: {e}", exc_info=True)
        return False, "DB_error", 0
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()




def add_note(title, body, user_id):
    try:
        conn, cursor = db_connections.get_db_and_cursor()
        cursor.execute(
            "INSERT INTO notes (title, body, user_id) VALUES (%s, %s, %s)",
            (title, body, user_id)
        )
        conn.commit()
        
        new_note_id = cursor.lastrowid
        logger.info(f"L'utente {user_id} ha aggiunto la nota {new_note_id}")
        return True, None
    except Error as e:
        logger.error(f"Errore DB inserimento nota per utente {user_id}: {e}", exc_info=True)
        return False, "DB_error"
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()


def delete_note(note_id, user_id):
    try:
        conn, cursor = db_connections.get_db_and_cursor(dictionary=True)
        
        cursor.execute("SELECT user_id FROM notes WHERE id = %s", (note_id,))
        note_to_delete = cursor.fetchone()

        if note_to_delete is None:
            return False, "note_not_found"

        if note_to_delete["user_id"] != user_id:
            logger.warning(f"Permessi negati: l'utente {user_id} ha provato a eliminare la nota {note_id} dell'utente {note_to_delete['user_id']}")
            return False, "permission_denied"

        cursor.execute("DELETE FROM notes WHERE id = %s", (note_id,))
        conn.commit()
        logger.info(f"Eliminata la nota {note_id} dall'utente {user_id}")
        return True, None
        
    except Error as e:
        logger.error(f"Errore DB eliminazione nota {note_id}: {e}", exc_info=True)
        return False, "DB_error"
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()


def update_note(note_id, user_id, title, body):
    try:
        conn, cursor = db_connections.get_db_and_cursor(dictionary=True)

        cursor.execute("SELECT user_id FROM notes WHERE id = %s", (note_id,))
        note_to_update = cursor.fetchone()

        if note_to_update is None:
            return False, "note_not_found"

        if note_to_update["user_id"] != user_id:
            logger.warning(f"Operazione non permessa: tentativo di modifica della nota {note_id} da parte di {user_id}")
            return False, "permission_denied"

        cursor.execute(
            "UPDATE notes SET title = %s, body = %s WHERE id = %s",
            (title, body, note_id)
        )
        conn.commit()
        logger.info(f"Nota {note_id} aggiornata con successo dall'utente {user_id}")
        return True, None

    except Error as e:
        logger.error(f"Errore DB durante la modifica della nota {note_id}: {e}", exc_info=True)
        return False, "DB_error"
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()


def register_user(username, password):
    password_bytes = password.encode("utf-8")
    try:
        conn, cursor = db_connections.get_db_and_cursor()
        
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, hashpw(password_bytes, gensalt()).decode("utf-8"))
        )
        conn.commit()
        
        logger.info(f"Nuovo utente registrato con successo: {username}")
        return True, None
        
    except IntegrityError:
        logger.warning(f"Tentativo di registrazione negato: username '{username}' già in uso.")
        return False, "integrity_error"
    except Error as e:
        logger.error(f"Errore DB durante la registrazione dell'utente '{username}': {e}", exc_info=True)
        return False, "DB_error"
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()