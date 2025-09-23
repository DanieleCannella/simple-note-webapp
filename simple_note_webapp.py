from flask import Flask, session, render_template, request, redirect, url_for, flash
from bcrypt import hashpw, gensalt, checkpw
from db import get_db_connection
from sqlite3 import IntegrityError

app = Flask(__name__)

app.secret_key = b"Really_random_bytes"


@app.route("/", methods=["GET", "POST"])
def root():
    if "user_id" in session:
        return redirect(url_for("index"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("auth/login.html")

    conn = get_db_connection()
    username = request.form.get("username")
    password = request.form.get("password")
    error = None

    if not username:
        error = "Username is required"
    elif not password:
        error = "password is required"
    if error:
        flash(error, "error")
        return render_template("auth/login.html")

    user = conn.execute("SELECT * FROM user WHERE username = ?", (username,)).fetchone()

    if user is None:
        error = "Incorrect username."
    elif not checkpw(password.encode("utf-8"), user["password"]):
        error = "Incorrect password."

    if error:
        flash(error, "error")
        return render_template("auth/login.html")

    session.clear()
    session["user_id"] = user["id"]
    return redirect(url_for("index"))


@app.route("/index", methods=["GET", "POST"])
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    user_id = session["user_id"]

    user_notes = conn.execute(
        "SELECT * FROM note WHERE author_id = ? ORDER BY created DESC", (user_id,)
    ).fetchall()

    return render_template("index.html", notes=user_notes)


@app.route("/logout")
def logout():
    session.pop("username", None)
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
        flash("Titolo e corpo della nota sono obbligatori!", "error")
        return redirect(url_for("index"))

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO note (title, body, author_id) VALUES (?, ?, ?)",
        (title, body, user_id),
    )
    conn.commit()

    flash("Nota aggiunta con successo!", "success")
    return redirect(url_for("index"))


@app.route("/delete_note/<int:note_id>")
def delete_note(note_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    note_to_delete = conn.execute(
        "SELECT * FROM note WHERE id = ?", (note_id,)
    ).fetchone()
    if note_to_delete and note_to_delete["author_id"] == session["user_id"]:
        conn.execute("DELETE FROM note WHERE id = ?", (note_id,))
        conn.commit()
        flash("Nota eliminata.", "info")
    else:
        flash("Operazione non permessa.", "error")

    return redirect(url_for("index"))


@app.route("/update_note/<int:note_id>", methods=["POST"])
def update_note(note_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    title = request.form.get("title")
    body = request.form.get("body")

    if not title or not body:
        flash("Titolo e corpo della nota sono obbligatori!", "error")
        return redirect(url_for("index"))

    conn = get_db_connection()
    note_to_update = conn.execute(
        "SELECT * FROM note WHERE id = ?", (note_id,)
    ).fetchone()

    if note_to_update is None:
        flash("Nota non trovata.", "error")
        return redirect(url_for("index"))

    if note_to_update["author_id"] != session["user_id"]:
        flash("Operazione non permessa.", "error")
        return redirect(url_for("index"))

    conn.execute(
        "UPDATE note SET title = ?, body = ? WHERE id = ?",
        (title, body, note_id),
    )
    conn.commit()

    flash("Nota aggiornata con successo!", "success")
    return redirect(url_for("index"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("auth/register.html")
    conn = get_db_connection()
    username = request.form.get("username")
    password = request.form.get("password").encode("utf-8")
    error = None

    if not username:
        error = "Username is required."
    elif not password:
        error = "Password is required."

    if error:
        flash(error, "error")
        return render_template("auth/register.html")

    try:
        conn.execute(
            "INSERT INTO user (username, password) VALUES (?, ?)",
            (username, hashpw(password, gensalt())),
        )
        conn.commit()

    except IntegrityError:
        error = f"User {username} is already registered."
        flash(error, "error")
        return render_template("auth/register.html")

    flash(f"Account creato con successo per {username}!", "success")
    return redirect(url_for("login"))
