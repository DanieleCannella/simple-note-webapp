import logging
from mysql.connector import Error, IntegrityError
from bcrypt import hashpw, gensalt, checkpw
import db_connections
from db_connections import DatabaseUnavailableError

logger = logging.getLogger(__name__)
DUMMY_PASSWORD = b"dummy_password"
DUMMY_HASH = hashpw(DUMMY_PASSWORD, gensalt())


def user_login(username, password):
    try:
        cursor = db_connections.get_cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user is None:
            checkpw(password.encode("utf-8"), DUMMY_HASH)
            #no f-string in logger messager, for better performance due to lazy evaluation. 
            logger.warning("Login failed: user not found (Username: '%s')", username)
            return False, "user_not_found", None
            
        elif not checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            logger.warning("Login failed: incorrect password (Username: '%s')", username)
            return False, "wrong_password", None
            
        logger.info("Login successful (User ID: %s, Username: '%s')", user["id"], username)
        return True, None, user

    #at the moment we capture and treat both exception like they are the same. 
    except (Error, DatabaseUnavailableError) as e:
        logger.error("Query failed: user login '%s' - Error: %s", username, e, exc_info=True)
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
            logger.warning("Staff login failed: user not found (Attempted Username: '%s')", username)
            return False, "staff_not_found", None, None
            
        elif not checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            logger.warning("Staff login failed: incorrect password (Target ID: %s)", user["id"])
            return False, "wrong_password", None, None
        
        cursor.execute("""
            SELECT R.role, R.level FROM user_role U_R
            JOIN roles R ON U_R.role_id = R.id
            WHERE U_R.user_id = %s
            ORDER BY R.level DESC LIMIT 1
        """, (user["id"],))
        role_data = cursor.fetchone()

        if role_data is None or role_data["level"] < 5:
            logger.warning("Permission denied: staff access refused (User ID: %s)", user["id"])
            return False, "Permission_denied", None, None

        logger.info("Staff login successful (Staff ID: %s, Level: %s)", user["id"], role_data['level'])
        return True, None, user, role_data

    except (Error, DatabaseUnavailableError) as e:
        logger.error("Query failed: staff login '%s' - Error: %s", username, e, exc_info=True)
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
    except (Error, DatabaseUnavailableError) as e:
        logger.error("Query failed: fetch users and roles - Error: %s", e, exc_info=True)
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
            new_user_id = cursor.lastrowid
            conn.commit()
            logger.info("User created: ID %s (Action by Staff: '%s')", new_user_id, staff_username)
            return True, None
        
        cursor.execute("SELECT id, role, level FROM roles WHERE role = %s", (role,))
        role_info = cursor.fetchone()
        
        if role_info is None:
            logger.warning("User creation failed: unknown role '%s' requested", role)
            return False, "unknown_role"

        if staff_level <= role_info["level"]:
            logger.warning("Permission denied: insufficient privileges to create role (Staff Lvl %s -> Target Role Lvl %s)", staff_level, role_info['level'])
            return False, "permission_denied"

        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, hashpw(password_bytes, gensalt()).decode("utf-8"))
        )

        new_user_id = cursor.lastrowid
        
        cursor.execute(
            """
            INSERT INTO user_role (user_id, role_id)
            SELECT id, %s FROM users WHERE username = %s
            """,
            (role_info["id"], username)
        )
        conn.commit()
        logger.info("User created: ID %s with role ID %s (Action by Staff: '%s')", new_user_id, role_info["id"], staff_username)
        return True, None
        
    except IntegrityError:
        logger.warning("User creation failed: username already in use '%s'", username)
        return False, "integrity_error"
    except (Error, DatabaseUnavailableError) as e:
        logger.error("Query failed: user creation - Error: %s", e, exc_info=True)
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
            logger.warning("Permission denied: insufficient privileges for deletion (Staff Lvl %s -> Target ID %s Lvl %s)", staff_level, user_id, user_level)
            return False, "permission_denied"
            
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        logger.info("User deleted: Target ID %s (Action by Staff: '%s')", user_id, staff_username)
        return True, None

    except (Error, DatabaseUnavailableError) as e:
        logger.error("Query failed: user deletion Target ID %s - Error: %s", user_id, e, exc_info=True)
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
            logger.warning("Permission denied: insufficient privileges on target (Staff Lvl %s -> Target ID %s Lvl %s)", staff_level, user_id, user_level)
            return False, "permission_denied"

        if role == "User":
            role_id = None
            role_level = 0
        else:
            cursor.execute("SELECT id, level FROM roles WHERE role = %s", (role,))
            role_data = cursor.fetchone()
            if role_data is None:
                logger.warning("Role update failed: unknown role '%s'", role)
                return False, "unknown_role"
            role_id = role_data["id"]
            role_level = role_data["level"]

        if staff_level <= role_level:
            logger.warning("Permission denied: insufficient privileges for role assignment (Staff Lvl %s -> New Role ID %s Lvl %s)", 
                           staff_level, role_id, role_level)
            return False, "permission_denied"

        cursor.execute("DELETE FROM user_role WHERE user_id = %s", (user_id,))

        if role_id is not None:
            cursor.execute(
                "INSERT INTO user_role (user_id, role_id) VALUES (%s, %s)",
                (user_id, role_id)
            )

        conn.commit()
        logger.info("Role updated: Target ID %s changed to Role ID %s (Action by Staff: '%s')", user_id, role_id, staff_username)
        return True, None

    except (Error, DatabaseUnavailableError) as e:
        logger.error("Query failed: role update Target ID %s - Error: %s", user_id, e, exc_info=True)
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
    except (Error, DatabaseUnavailableError) as e:
        logger.error("Query failed: fetch notes by_modified (User ID: %s) - Error: %s", user_id, e, exc_info=True)
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
    except (Error, DatabaseUnavailableError) as e:
        logger.error("Query failed: fetch notes by_created (User ID: %s) - Error: %s", user_id, e, exc_info=True)
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
    except (Error, DatabaseUnavailableError) as e:
        logger.error("Query failed: fetch notes by_title (User ID: %s) - Error: %s", user_id, e, exc_info=True)
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
    except (Error, DatabaseUnavailableError) as e:
        logger.error("Query failed: fetch notes count (User ID: %s) - Error: %s", user_id, e, exc_info=True)
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
        logger.info("Note created: Note ID %s (Owner ID: %s)", new_note_id, user_id)
        return True, None
    except (Error, DatabaseUnavailableError) as e:
        logger.error("Query failed: insert note (User ID: %s) - Error: %s", user_id, e, exc_info=True)
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
            logger.warning("Permission denied: attempt to delete foreign note (Attempting User ID: %s -> Target Note ID: %s, Owner ID: %s)", user_id, note_id, note_to_delete['user_id'])
            return False, "permission_denied"

        cursor.execute("DELETE FROM notes WHERE id = %s", (note_id,))
        conn.commit()
        logger.info("Note deleted: Note ID %s (Owner ID: %s)", note_id, user_id)
        return True, None
        
    except (Error, DatabaseUnavailableError) as e:
        logger.error("Query failed: delete note ID %s - Error: %s", note_id, e, exc_info=True)
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
            logger.warning("Permission denied: attempt to modify foreign note (Attempting User ID: %s -> Target Note ID: %s)", user_id, note_id)
            return False, "permission_denied"

        cursor.execute(
            "UPDATE notes SET title = %s, body = %s WHERE id = %s",
            (title, body, note_id)
        )
        conn.commit()
        logger.info("Note updated: Note ID %s (Owner ID: %s)", note_id, user_id)
        return True, None

    except (Error, DatabaseUnavailableError) as e:
        logger.error("Query failed: modify note ID %s - Error: %s", note_id, e, exc_info=True)
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
        new_user_id = cursor.lastrowid
        conn.commit()
        
        logger.info("Registration successful: User ID %s (Username: '%s')", new_user_id, username)
        return True, None
        
    except IntegrityError:
        logger.warning("Registration failed: username already in use ('%s')", username)
        return False, "integrity_error"
    except (Error, DatabaseUnavailableError) as e:
        logger.error("Query failed: user registration - Error: %s", e, exc_info=True)
        return False, "DB_error"
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()