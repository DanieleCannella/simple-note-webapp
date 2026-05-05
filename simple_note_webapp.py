from flask import Flask, session, render_template, request, redirect, url_for, flash, jsonify, has_request_context
from flask_wtf.csrf import CSRFProtect, CSRFError
from functools import wraps
import logging
import math
import os
from dotenv import load_dotenv

from flask_session import Session
import redis
from datetime import timedelta

import db_connections
import queries
from datetime import datetime, timezone


load_dotenv()

class FlaskUserContextFilter(logging.Filter):
    def filter(self, record):
        record.user_context = ""
        try:
            if has_request_context() and "user_id" in session:
                record.user_context = f"| UserID: {session['user_id']} "
        except Exception:
            pass
        return True
    

logging.basicConfig(
    level=getattr(logging, os.getenv("LOGGING_LEVEL", "INFO")),
    format='%(asctime)s | %(levelname)-8s | [%(filename)s:%(lineno)d] %(user_context)s| %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
user_filter = FlaskUserContextFilter()
for handler in logging.root.handlers:
    handler.addFilter(user_filter)

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
csrf = CSRFProtect(app)

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.from_url(os.getenv("REDIS_URL"))
app.config['SESSION_USE_SIGNER'] = True

app.config['SESSION_PERMANENT'] = False
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=int(os.getenv("SESSION_TIMEOUT_REMEMBER_ME_DAYS")))

Session(app)
db_connections.init_app(app)

def wants_json_response():
    is_api_route = request.path.startswith('/api/')
    wants_json = request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    return is_api_route or wants_json

@app.errorhandler(Exception)
@app.errorhandler(500)
def handle_internal_error(e):
    logger.critical("Unexpected server error: %s", e, exc_info=True)
    
    if wants_json_response():
        return jsonify({
            "success": False,
            "error_code": "internal_server_error",
            "message": "Si è verificato un errore interno del server."
        }), 500
        
    return render_template('500.jinja'), 500

@app.errorhandler(404)
def handle_not_found_error(e):
    logger.warning("Page or endpoint not found: %s", request.path)
    
    if wants_json_response():
        return jsonify({
            "success": False,
            "error_code": "not_found",
            "message": "La risorsa richiesta non esiste."
        }), 404
        
    return render_template('404.jinja'), 404

@app.errorhandler(403)
def handle_forbidden_error(e):
    logger.warning("Access forbidden: attempt to access protected route %s", request.path)
    
    if wants_json_response():
        return jsonify({
            "success": False,
            "error_code": "forbidden",
            "message": "Accesso negato. Permessi insufficienti."
        }), 403
        
    return render_template('403.jinja'), 403

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    user = session.get("user_id", "Guest")
    logger.warning("CSRF token validation failed (User ID: %s, Route: %s) - Reason: %s", user, request.path, e.description)
    
    if wants_json_response():
        return jsonify({
            "success": False,
            "error_code": "csrf_token_invalid",
            "message": "Token di sicurezza mancante o scaduto. Ricarica i dati."
        }), 400
        
    flash("La tua sessione di lavoro è scaduta per inattività, oppure la richiesta non è valida. Ti preghiamo di riprovare.", "warning")
    return redirect(request.referrer or url_for('user_login'))

#in questa funzione non controlliamo che sia scaduta la sessione delle persone che hanno cliccato
#remember me perchè viene gestito in automatico da flask_session grazione a PERMANENT_SESSION_LIFETIME
#e a SESSION_REFRESH_EACH_REQUEST.
@app.before_request
def manage_session_timeout():
    if "user_id" not in session:
        return

    now = datetime.now(timezone.utc).timestamp()
    
    last_activity = session["last_activity"]
    
    if not session.get("remember_me", False):#se non ha "remember_me"
        timeout_seconds = int(os.getenv("SESSION_TIMEOUT_MINUTES", "60")) * 60
        if now - last_activity > timeout_seconds:
            logger.info("Session expired due to inactivity (User ID: %s)", session["user_id"])
            session.clear()
            return 

    session["last_activity"] = now


def require_user_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("user_login"))
        return f(*args, **kwargs)
    return decorated_function


def require_staff_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or session.get("role_level", 0) < 5:
            logger.warning("Staff route access denied (User ID: %s, Route: %s)", session.get("user_id", "Guest"), request.path)
            flash("Accesso negato. Area riservata allo staff.", "danger")
            return redirect(url_for("staff_login"))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/", methods=["GET"])
def root():
    if "user_id" in session:
        return redirect(url_for("index"))
    return redirect(url_for("user_login"))


@app.route("/login", methods=["GET", "POST"])
def user_login():
    if request.method == "GET":
        return render_template("auth/login.jinja")

    username = request.form.get("username")
    password = request.form.get("password")
    remember_me = request.form.get("remember_me")
    
    if not username or not password:
        flash("Username e password sono obbligatori", "danger")
        return render_template("auth/login.jinja")

    success, error_msg, user = queries.user_login(username, password)

    if success:
        session.clear()

        is_remember_me = (remember_me == "True")
        
        session.permanent = is_remember_me
        
        session["remember_me"] = is_remember_me
        session["last_activity"] = datetime.now(timezone.utc).timestamp()
        
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("index"))
    else:
        if error_msg in ["user_not_found", "wrong_password"]:
            flash("Username o password errati", "danger")
        else:
            flash("Errore interno durante il login.", "danger")
        return render_template("auth/login.jinja")


@app.route("/staff/login", methods=["GET", "POST"])
def staff_login():
    if request.method == "GET":
        return render_template("auth/staff_login.jinja")

    username = request.form.get("username")
    password = request.form.get("password")
    remember_me = request.form.get("remember_me")

    if not username or not password:
        flash("Username e password sono obbligatori", "danger")
        return render_template("auth/staff_login.jinja")

    success, error_msg, user, role_data = queries.staff_login(username, password)

    if success:
        session.clear()
        
        is_remember_me = (remember_me == "True")
        session.permanent = is_remember_me
        session["remember_me"] = is_remember_me
        session["last_activity"] = datetime.now(timezone.utc).timestamp()
        
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
        return render_template("auth/staff_login.jinja")


@app.route("/staff/users", methods=["GET"])
@require_staff_login
def staff_index():
    success, error_msg, users_and_roles = queries.get_users_and_roles()
    if success:
        return render_template("staff_index.jinja", users_and_roles=users_and_roles)
    else:
        flash("Si è verificato un errore durante il caricamento degli utenti", "danger")
        return render_template("staff_index.jinja", users_and_roles=[])


@app.route("/staff/add_user", methods=["POST"])
@require_staff_login
def staff_add_user():
    username = request.form.get("username")
    password = request.form.get("password")
    role = request.form.get("role")
    
    if not username or not password or not role:
        flash("Username, Password e Role sono obbligatori.", "danger")
        return redirect(url_for("staff_index"))

    success, error_msg = queries.add_user(username, password, role, session["username"], session["role_level"])
    
    if success:
        flash(f"Creato l'utente {username} con successo!", "success")
    elif error_msg == "permission_denied":
        flash("Non hai i permessi sufficienti per assegnare questo ruolo.", "danger")
    elif error_msg == "integrity_error":
        flash(f"L'utente {username} è già registrato.", "danger")
    else:
        flash(f"Errore durante l'aggiunta dell'utente {username}", "danger")
        
    return redirect(url_for("staff_index"))


@app.route("/staff/delete_user/<int:user_id>", methods=["POST"])
@require_staff_login
def staff_delete_user(user_id):
    if user_id == session.get("user_id"):
        flash("Non puoi eliminare il tuo stesso account!", "danger")
        return redirect(url_for("staff_index"))
        
    success, error_msg = queries.delete_user(user_id, session["username"], session["role_level"])
    
    if success:
        flash("Utente eliminato con successo.", "success")
    elif error_msg == "permission_denied":
        flash("Non hai i permessi per eliminare questo utente.", "danger")
    elif error_msg == "user_not_found":
        flash("Impossibile trovare l'utente da eliminare.", "warning")
    else: 
        flash("Errore interno durante l'eliminazione dell'utente.", "danger")
        
    return redirect(url_for("staff_index"))


@app.route("/staff/update_role/<int:user_id>", methods=["POST"])
@require_staff_login
def staff_update_role(user_id):
    if user_id == session.get("user_id"):
        flash("Non puoi modificare i tuoi stessi privilegi!", "danger")
        return redirect(url_for("staff_index"))

    role = request.form.get("role")
    
    if not role:
        flash("Devi selezionare un nuovo ruolo.", "danger")
        return redirect(url_for("staff_index"))

    success, error_msg = queries.update_role(user_id, role, session["username"], session["role_level"])
    
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

@app.route("/index", methods=["GET"])
@require_user_login
def index():
    sort_by = request.args.get("sort", "modified_desc")
    page = request.args.get("page", 1, type=int) 
    show_all = request.args.get("all", 0, type=int) 
    
    success_count, _, total_notes = queries.get_user_notes_count(session["user_id"])
    NOTES_PER_PAGE = total_notes if show_all == 1 and total_notes > 0 else 6
    total_pages = math.ceil(total_notes / NOTES_PER_PAGE) if success_count and NOTES_PER_PAGE > 0 else 0

    if page < 1 or (total_pages > 0 and page > total_pages):
        return redirect(url_for('index', sort=sort_by, page=1))

    offset = (page - 1) * NOTES_PER_PAGE

    if sort_by == "title_asc":
        success, error_msg, notes = queries.get_user_notes_ordered_by_title(session["user_id"], True, NOTES_PER_PAGE, offset)
    elif sort_by == "title_desc":
        success, error_msg, notes = queries.get_user_notes_ordered_by_title(session["user_id"], False, NOTES_PER_PAGE, offset)
    elif sort_by == "created_asc":
        success, error_msg, notes = queries.get_user_notes_by_created(session["user_id"], True, NOTES_PER_PAGE, offset)
    elif sort_by == "created_desc":
        success, error_msg, notes = queries.get_user_notes_by_created(session["user_id"], False, NOTES_PER_PAGE, offset)
    elif sort_by == "modified_asc":
        success, error_msg, notes = queries.get_user_notes_by_modified(session["user_id"], True, NOTES_PER_PAGE, offset)
    else: # modified_desc (default)
        success, error_msg, notes = queries.get_user_notes_by_modified(session["user_id"], False, NOTES_PER_PAGE, offset)
    
    if not success:
        notes = []
        
    return render_template("index.jinja", notes=notes, current_sort=sort_by, current_page=page, total_pages=total_pages, show_all=show_all)

    
@app.route("/logout")
def logout():
    user_id = session.get("user_id", "Sconosciuto")
    session.clear()
    logger.info("Logout successful (User ID: %s)", user_id)
    
    flash("Logout effettuato con successo.", "success")
    return redirect(url_for("user_login"))


@app.route("/add_note", methods=["POST"])
@require_user_login
def add_note():
    title = request.form.get("title")
    body = request.form.get("body")

    if not title or not body:
        flash("Titolo e corpo della nota sono obbligatori!", "danger")
        return redirect(url_for("index"))

    success, error_msg = queries.add_note(title, body, session["user_id"])
    
    if success:
        flash("Nota aggiunta con successo!", "success")
    else:
        flash("Si è verificato un errore durante l'aggiunta della nota.", "danger")
        
    return redirect(url_for("index"))


@app.route("/delete_note/<int:note_id>", methods=["POST"])
@require_user_login
def delete_note(note_id):
    success, error_msg = queries.delete_note(note_id, session["user_id"])
    
    if success:
        flash("Nota eliminata con successo.", "success")
    elif error_msg == "note_not_found":
        flash("Impossibile trovare la nota da eliminare.", "warning")
    elif error_msg == "permission_denied":
        flash("Operazione non permessa: non sei il proprietario della nota.", "danger")
    else:
        flash("Si è verificato un errore durante l'eliminazione della nota.", "danger")
        
    return redirect(url_for("index"))


@app.route("/update_note/<int:note_id>", methods=["POST"])
@require_user_login
def update_note(note_id):
    title = request.form.get("title")
    body = request.form.get("body")

    if not title or not body:
        flash("Titolo e corpo della nota sono obbligatori!", "danger")
        return redirect(url_for("index"))

    success, error_msg = queries.update_note(note_id, session["user_id"], title, body)

    if success:
        flash("Nota aggiornata con successo!", "success")
    elif error_msg == "note_not_found":
        flash("Nota non trovata.", "warning")
    elif error_msg == "permission_denied":
        flash("Operazione non permessa: non sei il proprietario di questa nota.", "danger")
    else:
        flash("Si è verificato un errore durante il salvataggio della nota.", "danger")

    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("auth/register.jinja")

    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        flash("Username e password sono obbligatori.", "danger")
        return render_template("auth/register.jinja")

    success, error_msg = queries.register_user(username, password)

    if success:
        flash(f"Account creato con successo per {username}! Ora puoi accedere.", "success")
        return redirect(url_for("user_login"))
        
    elif error_msg == "integrity_error":
        flash(f"L'utente '{username}' è già registrato. Si prega di usare un altro username.", "danger")
        return render_template("auth/register.jinja")
        
    else:
        flash("Errore interno durante la registrazione. Riprova più tardi.", "danger")
        return render_template("auth/register.jinja")