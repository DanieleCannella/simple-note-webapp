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


def require_admin_login(f):
    @wraps(f) #mantiene nome e docstring della funzione originale, cruciale perchè sennò flask vede le funzioni tutte come la funzione wrapper invece di vedere la funzione originale ma wrappata.
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or not session.get("is_admin"):
            return redirect(url_for("admin_login"))
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
        return redirect(url_for("index"))
    else:
        if error_msg in ["user_not_found", "wrong_password"]:
            flash("Username o password errati", "danger")
                
        else: # DB_error
            flash("Errore interno durante il login.", "danger")
            
        return render_template("auth/login.html")


def db_admin_login(username, password):
    try:
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user is None:
            checkpw(password.encode("utf-8"), DUMMY_HASH) # Controllo fittizio per evitare timing attack
            logger.warning(f"Tentativo di accesso per admin inesistente: '{username}'")
            return (False, "admin_not_found", None)
            
        elif not checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            logger.warning(f"Password errata per l'admin: '{username}'")
            return (False, "wrong_password", None)
        
        is_admin = conn.execute("""
            SELECT 1 FROM user_role U_R
            JOIN roles R ON U_R.role_id = R.id
            WHERE U_R.user_id = ? AND R.role = 'Admin'
        """, (user["id"],)).fetchone()

        if is_admin is None:
            logger.info(f"Permesso negato: l'utente '{username}' ha provato ad accedere come Admin")
            return (False, "Permission_denied", None)

        # Login avvenuto con successo
        logger.info(f"L'utente '{username}' ha effettuato l'accesso come admin")
        return (True, None, user)

    except Error as e:
        logger.error(f"Errore DB durante l'accesso per l'admin '{username}': {e}", exc_info=True)
        return (False, "DB_error", None)
    finally:
        if 'conn' in locals() and conn:
            conn.close()


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("auth/admin_login.html")

    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        flash("Username e password sono obbligatori", "danger")
        return render_template("auth/admin_login.html")

    success, error_msg, user = db_admin_login(username, password)

    if success:
        session.clear()
        session["user_id"] = user["id"]
        session["is_admin"] = True
        return redirect(url_for("admin_index"))
    else:
        if error_msg in ["admin_not_found", "wrong_password"]:
            flash("Username o password errati", "danger")
            
        elif error_msg == "Permission_denied":
            flash("Operazione negata, necessari permessi admin", "danger")
            
        else: # DB_error
            flash("Errore interno durante il login.", "danger")
            
        return render_template("auth/admin_login.html")
    

def db_get_users_and_roles():
    try:
        conn = get_db_connection()
        users_and_roles = conn.execute("SELECT U.id, U.username, R.role FROM users U JOIN user_role U_R ON U.id = U_R.user_id JOIN roles R ON U_R.role_id = R.id ").fetchall()
        return (True, None, users_and_roles)
    except Error as e:
        logger.error(f"Errore DB durante il recupero degli utenti e i rispettivi ruoli: {e}", exc_info=True)
        return (False, "DB_error", None)
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/admin/users", methods=["GET"])
@require_admin_login
def admin_index():
    success, error_msg, users_and_roles = db_get_users_and_roles()
    if success:
        return render_template("admin_index.html", users_and_roles=users_and_roles)
    else:#  DB_error
        flash("Si è verificato un errore durante il caricamento degli utenti", "danger")
        return render_template("admin_index.html", users_and_roles=[])



@app.route("/admin/add_user", methods=["POST"])
@require_admin_login
def admin_add_user():
    username = request.form.get("username")
    password = request.form.get("password")
    role = request.form.get("role")
    if not username or not password or not role:
        flash("Username, Password e Role sono obbligatori.", "danger")
        return redirect(url_for("admin_index"))
    try:
        password = password.encode("utf-8")

        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashpw(password, gensalt()).decode("utf-8")),
        )

        if role == "Admin":
            conn.execute(
                """
                INSERT INTO user_role (user_id, role_id)
                SELECT u.id, r.id
                FROM users u, roles r
                WHERE u.username = ? AND r.role = ?
                """,
                (username, "Admin")
            )
        conn.commit()
        app.logger.info(f"Creato l'utente:{username}")
        if role == "Admin":
            app.logger.info(f"Fornito ruolo \"Admin\" all'utente:{username} ")
            
        flash(f"Creato L'utente {username} con successo!", "success")
        return redirect(url_for("admin_index"))
    except IntegrityError:
        error = f"L'utente:{username} è già registrato si prega di usare un altro username."
        flash(error, "danger")
        app.logger.warning(f"Tentativo di registrazione negato: username '{username}' già in uso.")
        return redirect(url_for("admin_index"))
    except Error as e:
        error = f"Errore durante l'aggiunta dell'utente:{username}"
        flash(error, "danger")
        app.logger.error(f"Errore durante l'aggiunta dell'utente:{username}", exc_info = True)
        return redirect(url_for("admin_index"))
    finally:
        conn.close()



    

@app.route("/admin/delete_user/<int:target_user_id>", methods=["POST"])
@require_admin_login
def admin_delete_user(target_user_id):        
    #Evita l'auto-eliminazione
    if target_user_id == session["user_id"]:
        flash("Non puoi eliminare il tuo stesso account!", "danger")
        app.logger.warning(f"L'admin {session['user_id']} ha tentato di eliminare se stesso.")
        return redirect(url_for("admin_index"))
    
@app.route("/admin/update_role/<int:target_user_id>", methods=["POST"])
@require_admin_login
def admin_update_role(target_user_id):
    #Evita l'auto-declassamento
    if target_user_id == session["user_id"]:
        flash("Non puoi modificare i tuoi stessi privilegi!", "danger")
        return redirect(url_for("admin_index"))

    new_role = request.form.get("role")
    
@app.route("/index", methods=["GET", "POST"])
@require_user_login
def index():
    conn = get_db_connection()
    try:
        user_id = session["user_id"]
        user_notes = conn.execute(
            "SELECT * FROM note WHERE author_id = ? ORDER BY created DESC", (user_id,)
        ).fetchall()
        return render_template("index.html", notes=user_notes)
    except Error as e:
        app.logger.error(f"errore durante l'esecuzione della query per recuperare le note dell'utente {user_id}: {e}", exc_info = True)
        flash("Si è verificato un errore durante il caricamento delle note", "danger")
        return render_template("index.html", notes=[])
    finally:
        conn.close()


@app.route("/logout")
def logout():
    user_id = session.get("user_id", "Sconosciuto")
    app.logger.info(f"L'utente {user_id} ha effettuato il logout")
    session.clear()
    
    flash("Logout effettuato con successo.", "success")
    return redirect(url_for("login"))


@app.route("/add_note", methods=["POST"])
@require_user_login
def add_note():
    title = request.form.get("title")
    body = request.form.get("body")
    user_id = session["user_id"]

    if not title or not body:
        flash("Titolo e corpo della nota sono obbligatori!", "danger")
        return redirect(url_for("index"))

    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "INSERT INTO note (title, body, author_id) VALUES (?, ?, ?)",
            (title, body, user_id),
        )
        conn.commit()

        new_note_id = cursor.lastrowid
    except Error as e:
        app.logger.error(f"errore durante l'esecuzione della query per inserire una nota: {e}", exc_info = True)
        flash("Si è verificato un errore durante l'aggiuta della nota.", "danger")
        return redirect(url_for("index"))
    finally:
        conn.close()
    app.logger.info(f"L'utente:{session['user_id']} ha aggiunto una nuova nota con ID: {new_note_id}")
    flash("Nota aggiunta con successo!", "success")
    return redirect(url_for("index"))


@app.route("/delete_note/<int:note_id>", methods=["POST"])
@require_user_login
def delete_note(note_id):
    conn = get_db_connection()
    try:
        note_to_delete = conn.execute(
            "SELECT * FROM note WHERE id = ?", (note_id,)
        ).fetchone()
        if note_to_delete and note_to_delete["author_id"] == session["user_id"]:
            conn.execute("DELETE FROM note WHERE id = ?", (note_id,))
            conn.commit()
            flash("Nota eliminata.", "info")
            app.logger.info(f"Eliminata la nota {note_id}, da parte di {session['user_id']}")
        else:
            flash("Operazione non permessa.", "danger")
    except Error as e:
        app.logger.error(f"errore durante l'esecuzione della query per eliminare una nota: {e}", exc_info=True)
        flash("Si è verificato un errore durante l'eliminazione della nota.", "danger")
        return redirect(url_for("index"))
    finally:
        conn.close()

    return redirect(url_for("index"))


@app.route("/update_note/<int:note_id>", methods=["POST"])
@require_user_login
def update_note(note_id):
    title = request.form.get("title")
    body = request.form.get("body")

    if not title or not body:
        flash("Titolo e corpo della nota sono obbligatori!", "danger")
        return redirect(url_for("index"))

    conn = get_db_connection()
    try:
        note_to_update = conn.execute(
            "SELECT * FROM note WHERE id = ?", (note_id,)
        ).fetchone()

        if note_to_update is None:
            flash("Nota non trovata.", "danger")
            return redirect(url_for("index"))

        if note_to_update["author_id"] != session["user_id"]:
            app.logger.warning(f"Operazione non permessa: tentativo di modifica di una nota {note_id} con proprietario {note_to_update['author_id']} da parte di {session['user_id']}")
            flash("Operazione non permessa.", "danger")
            return redirect(url_for("index"))

        conn.execute(
            "UPDATE note SET title = ?, body = ? WHERE id = ?",
            (title, body, note_id),
        )
        conn.commit()
    except Error as e:
        app.logger.error(f"errore durante l'esecuzione della query per la modifica di una nota: {e}", exc_info=True)
        flash("Si è verificato un errore durante il salvataggio della nota.", "danger")
        return redirect(url_for("index"))
    finally:
        conn.close()
    app.logger.info(f"aggiornata nota:{note_id} da parte di utente:{session['user_id']}")
    flash("Nota aggiornata con successo!", "success")
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
@require_user_login
def register():
    conn = get_db_connection()
    try:
        username = request.form.get("username")
        password = request.form.get("password").encode("utf-8")
        error = None

        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."

        if error:
            flash(error, "danger")
            return render_template("auth/register.html")
        
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashpw(password, gensalt()).decode("utf-8")),
        )
        conn.commit()

        flash(f"Account creato con successo per {username}!", "success")
        return redirect(url_for("login"))
    except IntegrityError:
        error = f"L'utente:{username} è già registrato si prega di usare un altro username."
        flash(error, "danger")
        app.logger.warning(f"Tentativo di registrazione negato: username '{username}' già in uso.")
        return render_template("auth/register.html")
    finally:
        conn.close()