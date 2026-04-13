from flask import Flask, session, render_template, request, redirect, url_for, flash
from bcrypt import hashpw, gensalt, checkpw
from db_connection import get_db_connection
from sqlite3 import IntegrityError, Error
from functools import wraps
import logging

logger = logging.getLogger(__name__)


DUMMY_PASSWORD = b"password_finta"
DUMMY_HASH = hashpw(DUMMY_PASSWORD, gensalt())

app = Flask(__name__)

app.secret_key = b"Really_random_bytes"


def require_user_login(f):
    @wraps(f) #mantiene nome e docstring della funzione originale, cruciale perchè sennò flask vede le funzioni tutte come la funzione wrapper invece di vedere la funzione originale ma wrappata.
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def require_staff_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Controlla se è loggato e se ha un livello di ruolo >= 5 (Moderator o superiore)
        if "user_id" not in session or session.get("role_level", 0) < 5:
            flash("Accesso negato. Area riservata allo staff.", "danger")
            return redirect(url_for("staff_login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/", methods=["GET"])
def root():
    if "user_id" in session:
        return redirect(url_for("index"))
    return redirect(url_for("login"))



def db_user_login(username, password):
    try:
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user is None:
            checkpw(password.encode("utf-8"), DUMMY_HASH) # Controllo fittizio per evitare timing attack
            logger.warning(f"Tentativo di accesso per utente inesistente: '{username}'")
            return (False, "user_not_found", None)
            
        elif not checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            logger.warning(f"Password errata per l'utente: '{username}'")
            return (False, "wrong_password", None)
            
        # Login avvenuto con successo
        logger.info(f"L'utente '{username}' ha effettuato l'accesso")
        return (True, None, user)

    except Error as e:
        logger.error(f"Errore DB durante l'accesso per l'utente '{username}': {e}", exc_info=True)
        return (False, "DB_error", None)
    finally:
        if 'conn' in locals() and conn:
            conn.close()


@app.route("/login", methods=["GET", "POST"])
def user_login():
    if request.method == "GET":
        return render_template("auth/login.html")

    username = request.form.get("username")
    password = request.form.get("password")
    
    if not username or not password:
        flash("Username e password sono obbligatori", "danger")
        return render_template("auth/login.html")

    success, error_msg, user = db_user_login(username, password)

    if success:
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("index"))
    else:
        if error_msg in ["user_not_found", "wrong_password"]:
            flash("Username o password errati", "danger")
                
        else: # DB_error
            flash("Errore interno durante il login.", "danger")
            
        return render_template("auth/login.html")

def db_staff_login(username, password):
    try:
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user is None:
            checkpw(password.encode("utf-8"), DUMMY_HASH)
            logger.warning(f"Tentativo di accesso per staff inesistente: '{username}'")
            return (False, "staff_not_found", None, None)
            
        elif not checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            logger.warning(f"Password errata per lo staff: '{username}'")
            return (False, "wrong_password", None, None)
        
        # Recuperiamo il ruolo con il livello più alto associato all'utente
        role_data = conn.execute("""
            SELECT R.role, R.level FROM user_role U_R
            JOIN roles R ON U_R.role_id = R.id
            WHERE U_R.user_id = ?
            ORDER BY R.level DESC LIMIT 1
        """, (user["id"],)).fetchone()

        # Se non ha ruoli o il suo livello è inferiore a 5 (es. è solo un User normale)
        if role_data is None or role_data["level"] < 5:
            logger.info(f"Permesso negato: l'utente '{username}' ha provato ad accedere allo staff")
            return (False, "Permission_denied", None, None)

        logger.info(f"Lo staff '{username}' (Livello {role_data['level']}) ha effettuato l'accesso")
        return (True, None, user, role_data)

    except Error as e:
        logger.error(f"Errore DB durante l'accesso staff '{username}': {e}", exc_info=True)
        return (False, "DB_error", None, None)
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/staff/login", methods=["GET", "POST"])
def staff_login():
    if request.method == "GET":
        return render_template("auth/staff_login.html")

    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        flash("Username e password sono obbligatori", "danger")
        return render_template("auth/staff_login.html")

    success, error_msg, user, role_data = db_staff_login(username, password)

    if success:
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role_level"] = role_data["level"]
        session["role_name"] = role_data["role"]
        return redirect(url_for("staff_index"))
    else:
        if error_msg in ["staff_not_found", "wrong_password"]:
            flash("Username o password errati", "danger")
        elif error_msg == "Permission_denied":
            flash("Operazione negata, necessari permessi staff", "danger")
        else:
            flash("Errore interno durante il login.", "danger")
            
        return render_template("auth/staff_login.html")

def db_get_users_and_roles():
	try:
        conn = get_db_connection()
        users_and_roles = conn.execute("""
            SELECT U.id, U.username, COALESCE(R.role, 'User') as role 
            FROM users U 
            LEFT JOIN user_role U_R ON U.id = U_R.user_id 
            LEFT JOIN roles R ON U_R.role_id = R.id
        """).fetchall()
        return (True, None, users_and_roles)
    except Error as e:
        logger.error(f"Errore DB durante il recupero degli utenti e i rispettivi ruoli: {e}", exc_info=True)
	return (False, "DB_error", None)
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/staff/users", methods=["GET"])
@require_staff_login
def staff_index():
    success, error_msg, users_and_roles = db_get_users_and_roles()
    if success:
        return render_template("staff_index.html", users_and_roles=users_and_roles)
    else:#  DB_error
        flash("Si è verificato un errore durante il caricamento degli utenti", "danger")
        return render_template("staff_index.html", users_and_roles=[])

def db_add_user(username, password, role, staff_username, staff_level):
    password = password.encode("utf-8")
    try:
        conn = get_db_connection()
    
        if role == "User":
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashpw(password, gensalt()).decode("utf-8")),
            )
            conn.commit()
            logger.info(f"Lo staff {staff_username} ha creato l'utente base: {username}")
            return True, None
        
        # Verifica se il ruolo richiesto esiste E recupera il suo livello
        role_info = conn.execute("SELECT id, role, level FROM roles WHERE role = ?", (role,)).fetchone()
        
        if role_info is None:
            logger.info(f"Tentativo di assegnare ruolo inesistente: {role} a {username}")
            return False, "unknown_role"

        if staff_level <= role_info["level"]:
            logger.warning(f"Permessi insufficienti: {staff_username} (Lvl {staff_level}) ha provato a creare un {role} (Lvl {role_info['level']})")
            return False, "permission_denied"

        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashpw(password, gensalt()).decode("utf-8")),
        )
        
        conn.execute(
            """
            INSERT INTO user_role (user_id, role_id)
            SELECT id, ? FROM users WHERE username = ?
            """,
            (role_info["id"], username)
        )
        conn.commit()
        logger.info(f"Lo staff {staff_username} ha creato l'utente: {username} con ruolo {role}")
        return True, None
        
    except IntegrityError:
        logger.info(f"Lo staff {staff_username} ha provato a creare un utente già presente: {username}")
        return False, "integrity_error"
    except Error as e:
        logger.error(f"Errore DB creazione utente {username} da {staff_username}: {e}", exc_info = True)
        return False, "DB_error"
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/staff/add_user", methods=["POST"])
@require_staff_login
def staff_add_user():
    username = request.form.get("username")
    password = request.form.get("password")
    role = request.form.get("role")
    
    if not username or not password or not role:
        flash("Username, Password e Role sono obbligatori.", "danger")
        return redirect(url_for("staff_index"))

    success, error_msg = db_add_user(username, password, role, session["username"], session["role_level"])
    
    if success:
        flash(f"Creato l'utente {username} con successo!", "success")
    elif error_msg == "permission_denied":
        flash("Non hai i permessi sufficienti per assegnare questo ruolo.", "danger")
    elif error_msg == "integrity_error":
        flash(f"L'utente {username} è già registrato.", "danger")
    else:
        flash(f"Errore durante l'aggiunta dell'utente {username}", "danger")
        
    return redirect(url_for("staff_index"))

def db_delete_user(user_id, staff_username, staff_level):
    try:
        conn = get_db_connection()
        
        user_exists = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if user_exists is None:
            return False, "user_not_found"
            
        # 2. Trova il livello massimo dell'utente che stiamo per eliminare
        user_info = conn.execute("""
            SELECT MAX(R.level) as max_level FROM users U
            LEFT JOIN user_role UR ON U.id = UR.user_id
            LEFT JOIN roles R ON UR.role_id = R.id
            WHERE U.id = ?
        """, (user_id,)).fetchone()
 
        # Se non ha ruoli, è un "User" base di livello 0
        user_level = user_info["max_level"] if user_info["max_level"] is not None else 0
        
        if staff_level <= user_level:
            logger.warning(f"Permessi insufficienti: {staff_username} (Lvl {staff_level}) ha provato a eliminare ID {user_id} (Lvl {user_level})")
            return False, "permission_denied"
            
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        logger.info(f"L'utente ID {user_id} è stato eliminato da {staff_username}")
        return True, None

    except Error as e:
        logger.error(f"Errore DB durante l'eliminazione dell'utente {user_id}: {e}", exc_info=True)
        return False, "DB_error"
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/staff/delete_user/<int:user_id>", methods=["POST"])
@require_staff_login
def staff_delete_user(user_id):
    if user_id == session.get("user_id"):
        flash("Non puoi eliminare il tuo stesso account!", "danger")
        return redirect(url_for("staff_index"))
        
    success, error_msg = db_delete_user(user_id, session["username"], session["role_level"])
    
    if success:
        flash("Utente eliminato con successo.", "success")
    elif error_msg == "permission_denied":
        flash("Non hai i permessi per eliminare questo utente.", "danger")
    elif error_msg == "user_not_found":
        flash("Impossibile trovare l'utente da eliminare.", "warning")
    else: 
        flash("Errore interno durante l'eliminazione dell'utente.", "danger")
        
    return redirect(url_for("staff_index"))
    

def db_update_role(user_id, role, staff_username, staff_level):
    try:
        conn = get_db_connection()

        user_exists = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if user_exists is None:
            return False, "user_not_found"
            
        username = user_exists["username"]

        # 2. Trova il livello massimo dell'utente
        user_info = conn.execute("""
            SELECT MAX(R.level) as max_level FROM users U
            LEFT JOIN user_role UR ON U.id = UR.user_id
            LEFT JOIN roles R ON UR.role_id = R.id
            WHERE U.id = ?
        """, (user_id,)).fetchone()

        # Se non ha ruoli, è un "User" base di livello 0
        user_level = user_info["max_level"] if user_info["max_level"] is not None else 0


        if staff_level <= user_level:
            logger.warning(f"Permessi insufficienti: {staff_username} (Lvl {staff_level}) ha provato a modificare {username} (Lvl {user_level})")
            return False, "permission_denied"

        if role == "User":
            role_id = None
            role_level = 0
        else:
            role_data = conn.execute("SELECT id, level FROM roles WHERE role = ?", (role,)).fetchone()
            if role_data is None:
                logger.info(f"Tentativo di assegnare ruolo inesistente: {role} a {username}")
                return False, "unknown_role"
            role_id = role_data["id"]
            role_level = role_data["level"]

        if staff_level <= role_level:
            logger.warning(f"Permessi insufficienti: {staff_username} (Lvl {staff_level}) ha provato a promuovere {username} a {role} (Lvl {role_level})")
            return False, "permission_denied"

        conn.execute("DELETE FROM user_role WHERE user_id = ?", (user_id,))

        if role_id is not None:
            conn.execute(
                "INSERT INTO user_role (user_id, role_id) VALUES (?, ?)",
                (user_id, role_id)
            )

        conn.commit()
        logger.info(f"Lo staff {staff_username} ha aggiornato il ruolo di {username} a {role}")
        return True, None

    except Error as e:
        logger.error(f"Errore DB aggiornamento ruolo utente ID {user_id} da {staff_username}: {e}", exc_info=True)
        return False, "DB_error"
    finally:
        if 'conn' in locals() and conn:
            conn.close()


@app.route("/staff/update_role/<int:user_id>", methods=["POST"])
@require_staff_login
def staff_update_role(user_id):
    # Evita l'auto-modifica
    if user_id == session.get("user_id"):
        flash("Non puoi modificare i tuoi stessi privilegi!", "danger")
        return redirect(url_for("staff_index"))

    role = request.form.get("role")
    
    if not role:
        flash("Devi selezionare un nuovo ruolo.", "danger")
        return redirect(url_for("staff_index"))

    success, error_msg = db_update_role(user_id, role, session["username"], session["role_level"])
    
    if success:
        flash("Ruolo aggiornato con successo.", "success")
    elif error_msg == "permission_denied":
        flash("Non hai i permessi per effettuare questa modifica.", "danger")
    elif error_msg == "user_not_found":
        flash("Impossibile trovare l'utente specificato.", "warning")
    elif error_msg == "unknown_role":
        flash("Il ruolo selezionato non è valido.", "danger")
    else: 
        flash("Errore interno durante l'aggiornamento del ruolo.", "danger")
        
    return redirect(url_for("staff_index"))
    
def db_get_user_notes(user_id):
    try:
        conn = get_db_connection()
        user_notes = conn.execute(
            "SELECT * FROM notes WHERE user_id = ? ORDER BY created DESC", (user_id,)
        ).fetchall()
        return True, None, user_notes
    except Error as e:
        logger.error(f"Errore DB durante il recupero note per l'utente {user_id}: {e}", exc_info=True)
        return False, "DB_error", []
    finally:
        if 'conn' in locals() and conn:
            conn.close()
    
@app.route("/index", methods=["GET"])
@require_user_login
def index():
    success, error_msg, notes = db_get_user_notes(session["user_id"])
    
    if not success:
        flash("Si è verificato un errore durante il caricamento delle note.", "danger")
        
    return render_template("index.html", notes=notes)


@app.route("/logout")
def logout():
    user_id = session.get("user_id", "Sconosciuto")
    logger.info(f"L'utente {user_id} ha effettuato il logout")
    session.clear()
    
    flash("Logout effettuato con successo.", "success")
    return redirect(url_for("user_login"))

def db_add_note(title, body, user_id):
    try:
        conn = get_db_connection()
        cursor = conn.execute(
            "INSERT INTO notes (title, body, user_id) VALUES (?, ?, ?)",
            (title, body, user_id),
        )
        conn.commit()
        
        new_note_id = cursor.lastrowid
        logger.info(f"L'utente {user_id} ha aggiunto la nota {new_note_id}")
        return True, None
    except Error as e:
        logger.error(f"Errore DB inserimento nota per utente {user_id}: {e}", exc_info=True)
        return False, "DB_error"
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/add_note", methods=["POST"])
@require_user_login
def add_note():
    title = request.form.get("title")
    body = request.form.get("body")

    if not title or not body:
        flash("Titolo e corpo della nota sono obbligatori!", "danger")
        return redirect(url_for("index"))

    success, error_msg = db_add_note(title, body, session["user_id"])
    
    if success:
        flash("Nota aggiunta con successo!", "success")
    else:
        flash("Si è verificato un errore durante l'aggiunta della nota.", "danger")
        
    return redirect(url_for("index"))


def db_delete_note(note_id, user_id):
    try:
        conn = get_db_connection()
        
        # Selezioniamo solo lo user_id, è più leggero
        note_to_delete = conn.execute(
            "SELECT user_id FROM notes WHERE id = ?", (note_id,)
        ).fetchone()

        if note_to_delete is None:
            return False, "note_not_found"

        if note_to_delete["user_id"] != user_id:
            logger.warning(f"Permessi negati: l'utente {user_id} ha provato a eliminare la nota {note_id} dell'utente {note_to_delete['user_id']}")
            return False, "permission_denied"

        conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        conn.commit()
        logger.info(f"Eliminata la nota {note_id} dall'utente {user_id}")
        return True, None
        
    except Error as e:
        logger.error(f"Errore DB eliminazione nota {note_id}: {e}", exc_info=True)
        return False, "DB_error"
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/delete_note/<int:note_id>", methods=["POST"])
@require_user_login
def delete_note(note_id):
    success, error_msg = db_delete_note(note_id, session["user_id"])
    
    if success:
        flash("Nota eliminata con successo.", "success")
    elif error_msg == "note_not_found":
        flash("Impossibile trovare la nota da eliminare.", "warning")
    elif error_msg == "permission_denied":
        flash("Operazione non permessa: non sei il proprietario della nota.", "danger")
    else:
        flash("Si è verificato un errore durante l'eliminazione della nota.", "danger")
        
    return redirect(url_for("index"))

def db_update_note(note_id, user_id, title, body):
    try:
        conn = get_db_connection()
        

        note_to_update = conn.execute(
            "SELECT user_id FROM notes WHERE id = ?", (note_id,)
        ).fetchone()

        if note_to_update is None:
            return False, "note_not_found"

        if note_to_update["user_id"] != user_id:
            logger.warning(f"Operazione non permessa: tentativo di modifica della nota {note_id} (proprietario {note_to_update['user_id']}) da parte di {user_id}")
            return False, "permission_denied"

        conn.execute(
            "UPDATE notes SET title = ?, body = ? WHERE id = ?",
            (title, body, note_id),
        )
        conn.commit()
        logger.info(f"Nota {note_id} aggiornata con successo dall'utente {user_id}")
        return True, None

    except Error as e:
        logger.error(f"Errore DB durante la modifica della nota {note_id}: {e}", exc_info=True)
        return False, "DB_error"
    finally:
        if 'conn' in locals() and conn:
            conn.close()


@app.route("/update_note/<int:note_id>", methods=["POST"])
@require_user_login
def update_note(note_id):
    title = request.form.get("title")
    body = request.form.get("body")

    if not title or not body:
        flash("Titolo e corpo della nota sono obbligatori!", "danger")
        return redirect(url_for("index"))

    success, error_msg = db_update_note(note_id, session["user_id"], title, body)

    if success:
        flash("Nota aggiornata con successo!", "success")
    elif error_msg == "note_not_found":
        flash("Nota non trovata.", "warning")
    elif error_msg == "permission_denied":
        flash("Operazione non permessa: non sei il proprietario di questa nota.", "danger")
    else: # DB_error
        flash("Si è verificato un errore durante il salvataggio della nota.", "danger")

    return redirect(url_for("index"))


def db_register_user(username, password):
    # La codifica in bytes serve a bcrypt
    password_bytes = password.encode("utf-8")
    try:
        conn = get_db_connection()
        
        # Inseriamo l'utente. Essendo la registrazione pubblica, 
        # non assegniamo ruoli, così gode dell'"Implicit Default Role" (User base)
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashpw(password_bytes, gensalt()).decode("utf-8")),
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
        if 'conn' in locals() and conn:
            conn.close()


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("auth/register.html")

    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        flash("Username e password sono obbligatori.", "danger")
        return render_template("auth/register.html")

    success, error_msg = db_register_user(username, password)

    if success:
        flash(f"Account creato con successo per {username}! Ora puoi accedere.", "success")
        return redirect(url_for("user_login")) 
        
    elif error_msg == "integrity_error":
        flash(f"L'utente '{username}' è già registrato. Si prega di usare un altro username.", "danger")
        return render_template("auth/register.html")
        
    else: # DB_error
        flash("Errore interno durante la registrazione. Riprova più tardi.", "danger")
        return render_template("auth/register.html")
