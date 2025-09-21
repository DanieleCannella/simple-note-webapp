from flask import Flask, session, render_template, request, redirect, url_for, flash
from bcrypt import hashpw, gensalt, checkpw
from db import get_db_connection
from sqlite3 import IntegrityError

app = Flask(__name__)

app.secret_key = b"Really_random_bytes"


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
        flash(error)
        return render_template("auth/login.html")

    user = conn.execute("SELECT * FROM user WHERE username = ?", (username,)).fetchone()

    if user is None:
        error = "Incorrect username."
    elif not checkpw(password.encode("utf-8"), user["password"]):
        error = "Incorrect password."

    if error:
        flash(error)
        return render_template("auth/login.html")

    session.clear()
    session["user_id"] = user["id"]
    return redirect(url_for("index"))


@app.route("/index", methods=["GET", "POST"])
def index():
    if "user_id" in session:
        return render_template("index.html")
    return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))


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
        flash(error)
        return render_template("auth/register.html")

    try:
        conn.execute(
            "INSERT INTO user (username, password) VALUES (?, ?)",
            (username, hashpw(password, gensalt())),
        )
        conn.commit()

    except IntegrityError:
        error = f"User {username} is already registered."
        flash(error)
        return render_template("auth/register.html")

    return redirect(url_for("login"))
