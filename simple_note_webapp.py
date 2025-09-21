from flask import Flask, session, render_template, request, redirect, url_for

app = Flask(__name__)

app.secret_key = b'Really_random_bytes'

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        session["username"] = request.form["username"]
        return redirect(url_for("index"))
    return render_template("auth/login.html")

@app.route("/index", methods=["GET", "POST"])
def index():
    if "username" in session:
        return render_template("index.html")
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))




    
