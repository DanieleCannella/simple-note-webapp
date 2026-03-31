from flask import Flask, session, render_template, request, redirect, url_for, flash
from bcrypt import hashpw, gensalt, checkpw
from db_connection import get_db_connection
from sqlite3 import IntegrityError, Error
import logging

app = Flask(__name__)

app.secret_key = b"Really_random_bytes"

app.logger.setLevel(logging.INFO)


@app.route("/", methods=["GET"])
def root():
    if "user_id" in session:
        return redirect(url_for("index"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("auth/login.html")

    conn = get_db_connection()
    try:
        username = request.form.get("username")
        password = request.form.get("password")
        error = None

        if not username:
            error = "Username is required"
        elif not password:
            error = "password is required"
        if error:
            flash(error, "danger")
            return render_template("auth/login.html")

        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user is None:
            error = "Incorrect username."
        elif not checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            error = "Incorrect password."

        if error:
            flash(error, "danger")
            return render_template("auth/login.html")

        app.logger.info(f"L'utente:{username}, ha effettuato l'accesso")
        session.clear()
        session["user_id"] = user["id"]
        return redirect(url_for("index"))
    except Error as e:
        app.logger.error(f"Errore durante l'accesso per l'utente:{username}", exc_info = True)
        flash("Errore durante l'accesso", "danger")
        return render_template("auth/login.html")
    finally:
        conn.close()

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("auth/admin_login.html")

    conn = get_db_connection()
    try:
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Username e password sono obbligatori", "danger")
            return render_template("auth/admin_login.html")

        #controllo se il nome utente esiste e se la password è corretta
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user is None or not checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            flash("Username o password non validi.", "danger")
            return render_template("auth/admin_login.html")
        
        #controllo tramite l'id dell'utente se quest'ultimo ha i permessi di admin
        is_admin = conn.execute("""
            SELECT 1 FROM user_role U_R
            JOIN roles R ON U_R.role_id = R.id
            WHERE U_R.user_id = ? AND R.role = 'Admin'
        """, (user["id"],)).fetchone()

        if is_admin is None:
            flash("Accesso negato: sono necessari i privilegi di amministratore.", "danger")
            app.logger.info(f"L'utente:{username} ha provato ad accedere come Admin")
            return render_template("auth/admin_login.html")

        session.clear()
        session["user_id"] = user["id"]
        session["is_admin"] = True
        app.logger.info(f"L'utente:{username} ha effettuato l'accesso come admin")
        return redirect(url_for("admin_index"))
    except Error as e:
        app.logger.error(f"Errore durante la query di login per l'utente {username}: {e}",exc_info = True)
        flash(f"errore durante le query per il login", "danger")
        return render_template("auth/admin_login.html")
    finally:
        conn.close()

@app.route("/admin/users", methods=["GET"])
def admin_index():
    if "user_id" not in session or session.get("is_admin") != True:
        return redirect(url_for("admin_login"))
    conn = get_db_connection()
    try:
        users_and_roles = conn.execute("SELECT U.id, U.username, R.role FROM users U JOIN user_role U_R ON U.id = U_R.user_id JOIN roles R ON U_R.role_id = R.id ").fetchall()
        return render_template("admin_index.html", users_and_roles=users_and_roles)
    except Error as e:
        app.logger.error(f"errore durante l'esecuzione della query per recuperare gli utenti e i rispettivi ruoli: {e}", exc_info = True)
        flash("Si è verificato un errore durante il caricamento degli utenti", "danger")
        return render_template("admin_index.html", users_and_roles=[])
    finally:
        conn.close()


@app.route("/admin/add_user", methods=["POST"])
def admin_add_user():
    if "user_id" not in session or not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    conn = get_db_connection()
    try:
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role")
        error = None

        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."
        elif not role:
            error = "Role is required."

        if error:
            flash(error, "danger")
            return redirect(url_for("admin_index"))

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
def admin_delete_user(target_user_id):
    if "user_id" not in session or not session.get("is_admin"):
        return redirect(url_for("admin_login"))
        
    #Evita l'auto-eliminazione
    if target_user_id == session["user_id"]:
        flash("Non puoi eliminare il tuo stesso account!", "danger")
        app.logger.warning(f"L'admin {session['user_id']} ha tentato di eliminare se stesso.")
        return redirect(url_for("admin_index"))
    
@app.route("/admin/update_role/<int:target_user_id>", methods=["POST"])
def admin_update_role(target_user_id):
    if "user_id" not in session or not session.get("is_admin"):
        return redirect(url_for("admin_login"))

    #Evita l'auto-declassamento
    if target_user_id == session["user_id"]:
        flash("Non puoi modificare i tuoi stessi privilegi!", "danger")
        return redirect(url_for("admin_index"))

    new_role = request.form.get("role")
    
@app.route("/index", methods=["GET", "POST"])
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))

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
def add_note():
    if "user_id" not in session:
        return redirect(url_for("login"))

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
def delete_note(note_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

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
def update_note(note_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

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
def register():
    if request.method == "GET":
        return render_template("auth/register.html")
    
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