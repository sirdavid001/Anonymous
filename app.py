import os
import secrets
from datetime import datetime
import re
from urllib.parse import urljoin, urlparse
from flask import Flask, abort, render_template, redirect, request, flash, url_for
from sqlalchemy import inspect, text
from flask_login import (
    LoginManager, login_user,
    login_required, logout_user, current_user
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from models import db, User, Message, RateLimit
from time import time
import requests

# --------------------
# BASIC SETUP
# --------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
PRIMARY_ADMIN_EMAIL = "itssirdavid@gmail.com"
ADMIN_EMAILS = {PRIMARY_ADMIN_EMAIL}


DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "static/uploads")
app.config["MAX_CONTENT_LENGTH"] = 250 * 1024 * 1024  # 250MB

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=not app.debug
)

print("DB URI:", app.config["SQLALCHEMY_DATABASE_URI"])


db.init_app(app)

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


def ensure_database_schema():
    db.create_all()

    def ensure_column(table_name, column_name, ddl_fragment):
        columns = {col["name"] for col in inspect(db.engine).get_columns(table_name)}
        if column_name in columns:
            return

        try:
            db.session.execute(
                text(f'ALTER TABLE "{table_name}" ADD COLUMN {ddl_fragment}')
            )
            db.session.commit()
            print(f"Migrated DB schema: added {table_name}.{column_name}")
        except Exception:
            db.session.rollback()
            refreshed = {
                col["name"] for col in inspect(db.engine).get_columns(table_name)
            }
            if column_name not in refreshed:
                raise

    def ensure_unique_index(table_name, index_name, column_name):
        inspector = inspect(db.engine)
        indexes = inspector.get_indexes(table_name)
        unique_constraints = inspector.get_unique_constraints(table_name)

        has_unique_for_column = any(
            idx.get("unique") and idx.get("column_names") == [column_name]
            for idx in indexes
        ) or any(
            constraint.get("column_names") == [column_name]
            for constraint in unique_constraints
        )

        if has_unique_for_column or any(idx["name"] == index_name for idx in indexes):
            return
        db.session.execute(
            text(
                f'CREATE UNIQUE INDEX IF NOT EXISTS "{index_name}" '
                f'ON "{table_name}" ({column_name})'
            )
        )
        db.session.commit()

    ensure_column("message", "reported", "reported BOOLEAN DEFAULT FALSE")
    ensure_column("message", "sender_ip", "sender_ip VARCHAR(64)")
    ensure_column("message", "sender_user_agent", "sender_user_agent TEXT")
    ensure_column("message", "sender_account_email", "sender_account_email VARCHAR(120)")
    ensure_column("message", "edited_at", "edited_at TIMESTAMP")
    ensure_column("user", "username", "username VARCHAR(30)")
    ensure_column("user", "is_suspended", "is_suspended BOOLEAN DEFAULT FALSE")
    ensure_column("user", "suspended_at", "suspended_at TIMESTAMP")

    # Backfill and normalize usernames for existing records.
    users = User.query.order_by(User.id.asc()).all()
    taken = set()
    changed = False

    for user in users:
        username = (user.username or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9_]{3,30}", username):
            seed = (
                (user.email.split("@")[0] if user.email else None)
                or user.slug
                or f"user{user.id}"
            )
            base = re.sub(r"[^a-z0-9_]", "", seed.lower())
            if len(base) < 3:
                base = f"user{user.id}"
            username = base[:30]

        candidate = username
        suffix = 1
        while (
            candidate in taken
            or User.query.filter(User.id != user.id, User.username == candidate).first()
        ):
            suffix_txt = str(suffix)
            prefix_max = max(1, 30 - len(suffix_txt) - 1)
            candidate = f"{username[:prefix_max]}_{suffix_txt}"
            suffix += 1

        if user.username != candidate:
            user.username = candidate
            changed = True
        taken.add(candidate)

    if changed:
        db.session.commit()

    ensure_unique_index("user", "ux_user_username", "username")


with app.app_context():
    ensure_database_schema()



ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif",
    "mp4", "webm", "mov",
    "mp3", "wav", "aac"
}

def allowed_file(filename):
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_strong_password(password):
    if not password or len(password) < 8:
        return False
    return bool(re.search(r"[A-Z]", password) and re.search(r"[a-z]", password) and re.search(r"\d", password))


def ensure_admin_access():
    if not current_user.is_authenticated:
        abort(403)
    if not is_admin_email(current_user.email):
        abort(403)
    if sync_admin_status(current_user):
        db.session.commit()
    if not current_user.is_admin:
        abort(403)


def remove_uploaded_media(media_path):
    if not media_path:
        return

    file_path = os.path.join(app.static_folder, media_path)
    if os.path.isfile(file_path):
        try:
            os.remove(file_path)
        except OSError:
            pass


def admin_redirect_back(default_endpoint="admin", **values):
    referrer = request.referrer
    if referrer and is_safe_redirect_target(referrer):
        return redirect(referrer)
    return redirect(url_for(default_endpoint, **values))


def is_admin_email(email):
    return bool(email) and email.strip().lower() in ADMIN_EMAILS


def normalize_email(value):
    return (value or "").strip().lower()


def normalize_username(value):
    return (value or "").strip().lower()


def build_unique_slug(base_slug):
    base_slug = re.sub(r"[^a-z0-9_-]", "", (base_slug or "").strip().lower())
    if len(base_slug) < 3:
        base_slug = "user"
    base_slug = base_slug[:40]

    candidate = base_slug
    suffix = 1
    while User.query.filter_by(slug=candidate).first():
        suffix_txt = str(suffix)
        prefix_max = max(1, 50 - len(suffix_txt) - 1)
        candidate = f"{base_slug[:prefix_max]}-{suffix_txt}"
        suffix += 1
    return candidate


def sync_admin_status(user):
    should_be_admin = is_admin_email(user.email)
    if user.is_admin != should_be_admin:
        user.is_admin = should_be_admin
        return True

    return False


def enforce_admin_assignments():
    changed = False
    for user in User.query.all():
        should_be_admin = is_admin_email(user.email)
        if user.is_admin != should_be_admin:
            user.is_admin = should_be_admin
            changed = True

    if changed:
        db.session.commit()


with app.app_context():
    enforce_admin_assignments()


def is_safe_redirect_target(target):
    if not target:
        return False

    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return (
        redirect_url.scheme in {"http", "https"}
        and host_url.netloc == redirect_url.netloc
    )





# --------------------
# LOGIN MANAGER
# --------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

PUBLIC_ENDPOINTS = {
    "landing",
    "login",
    "register",
    "drop",
    "forgot_password",
    "reset_password",
    "verify_email",
    "privacy",
    "about",
    "terms",
    "static",
}


@app.before_request
def enforce_login_for_private_routes():
    endpoint = request.endpoint
    if endpoint is None:
        return None

    if current_user.is_authenticated:
        if sync_admin_status(current_user):
            db.session.commit()
        if current_user.is_suspended and endpoint != "logout":
            logout_user()
            flash("Your account is suspended. Contact support.", "danger")
            return redirect(url_for("login"))
        if endpoint in PUBLIC_ENDPOINTS or endpoint.startswith("static"):
            return None
        return None

    if endpoint in PUBLIC_ENDPOINTS or endpoint.startswith("static"):
        return None

    return redirect(url_for("login", next=request.full_path.rstrip("?")))


@app.context_processor
def inject_permission_helpers():
    is_admin_user = (
        current_user.is_authenticated
        and is_admin_email(getattr(current_user, "email", None))
    )
    return {"can_access_admin": is_admin_user}


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


# --------------------
# FORMS
# --------------------
class RegisterForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=30),
            Regexp(
                r"^[A-Za-z0-9_]+$",
                message="Username can only use letters, numbers, and underscore.",
            ),
        ],
    )
    email = StringField(validators=[Email(), DataRequired()])
    password = PasswordField(validators=[
        DataRequired(),
        Length(min=8),
        Regexp(
            r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)",
            message="Password must include uppercase, lowercase, and a number."
        )
    ])


class DropForm(FlaskForm):
    message = TextAreaField(validators=[DataRequired()])


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[Email(), DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])


# --------------------
# ROUTES
# --------------------
@app.route("/", methods=["GET"])
def landing():
    return render_template("landing.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        if current_user.is_verified:
            return redirect(url_for("dashboard"))
        return redirect(url_for("unverified"))

    form = RegisterForm()

    if form.validate_on_submit():
        email = normalize_email(form.email.data)
        username = normalize_username(form.username.data)

        # Check if email/username already exists
        if User.query.filter_by(email=email).first():
            flash("Email already registered.")
            return redirect(url_for("login"))
        if User.query.filter_by(username=username).first():
            flash("Username already taken. Please choose another one.", "danger")
            return render_template("register.html", form=form)

        # Create user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(form.password.data),
            slug=build_unique_slug(username),
            is_verified=False,
            is_admin=is_admin_email(email)
        )

        db.session.add(user)
        db.session.commit()

        # Generate verification token
        token = generate_verify_token(user.email)
        verify_link = url_for("verify_email", token=token, _external=True)

        # Send verification email (verification is enforced before dashboard access)
        send_email_http(
            user.email,
            "Verify your Uknowme email",
            f"""
            <h3>Welcome to Uknowme 👋</h3>
            <p>Please verify your email address by clicking the link below:</p>
            <p><a href="{verify_link}">Verify my email</a></p>
            <p>If you didn’t create this account, you can ignore this email.</p>
            """
        )

        flash("Account created. Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        ip = request.remote_addr
        now = time()
        record = RateLimit.query.filter_by(ip=ip).first()

        if record and now - record.last_hit < 10:
            flash("Too many attempts. Try again shortly.")
            return redirect(url_for("login"))

        if record:
            record.last_hit = now
        else:
            db.session.add(RateLimit(ip=ip, last_hit=now))
        db.session.commit()

        user = User.query.filter_by(email=normalize_email(form.email.data)).first()

        if user and check_password_hash(user.password_hash, form.password.data):
            if user.is_suspended:
                flash("Your account is suspended. Contact support.")
                return redirect(url_for("login"))

            if sync_admin_status(user):
                db.session.commit()

            login_user(user)

            if not user.is_verified:
                flash("Please verify your email before continuing.")
                return redirect(url_for("unverified"))

            next_url = request.args.get("next")
            if is_safe_redirect_target(next_url):
                return redirect(next_url)

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html", form=form)




@app.route("/unverified")
@login_required
def unverified():
    if current_user.is_verified:
        return redirect(url_for("dashboard"))
    return render_template("unverified.html")





@app.route("/dashboard")
@login_required
def dashboard():
    
    if not current_user.is_verified:
        return redirect(url_for("unverified"))
    
    messages = Message.query.filter_by(user_id=current_user.id).order_by(
        Message.created_at.desc()
    ).all()

    inbox_link = f"{request.host_url}drop/{current_user.slug}"

    # mark messages as read
    for msg in messages:
        if not msg.is_read:
            msg.is_read = True
    db.session.commit()

    return render_template(
        "dashboard.html",
        inbox_link=inbox_link,
        messages=messages
    )



@app.route("/drop/<slug>", methods=["GET", "POST"])
def drop(slug):
    user = User.query.filter_by(slug=slug).first_or_404()

    if not user.is_verified:
        abort(403)
    if user.is_suspended:
        abort(403)

    form = DropForm()

    # Reject invalid POSTs (CSRF / tampering)

    if form.validate_on_submit():
        ip = request.remote_addr
        now = time()
        record = RateLimit.query.filter_by(ip=ip).first()

        if record and now - record.last_hit < 15:
            flash("Slow down. Try again in a few seconds.", "warning")
            return redirect(request.url)

        if record:
            record.last_hit = now
        else:
            db.session.add(RateLimit(ip=ip, last_hit=now))

        file = request.files.get("file")
        media_path = None
        media_type = None

        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Unsupported file type.", "danger")
                return redirect(request.url)

            # size check BEFORE saving
            file.seek(0, os.SEEK_END)
            size = file.tell()
            file.seek(0)

            if size > 250 * 1024 * 1024:
                flash("File too large.", "danger")
                return redirect(request.url)

            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            ext = file.filename.rsplit(".", 1)[-1].lower()
            filename = f"{secrets.token_hex(16)}.{ext}"
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            media_path = f"uploads/{filename}"

            if ext in ["png", "jpg", "jpeg", "gif"]:
                media_type = "image"
            elif ext in ["mp4", "webm", "mov"]:
                media_type = "video"
            elif ext in ["mp3", "wav", "aac"]:
                media_type = "audio"

        msg = Message(
            user_id=user.id,
            text=form.message.data,
            media_path=media_path,
            media_type=media_type,
            sender_ip=get_client_ip(),
            sender_user_agent=(request.headers.get("User-Agent", "") or "")[:512],
            sender_account_email=(
                current_user.email if current_user.is_authenticated else None
            ),
        )

        db.session.add(msg)
        db.session.commit()

        if user.email_notifications:
            send_email_http(
                user.email,
                "You received a new anonymous message 👀",
                "<p>You just received a new anonymous message.</p>"
            )

        flash("Message sent anonymously.", "success")
        return redirect(request.url)

    recipient_name = user.username or user.slug
    return render_template(
        "drop.html",
        form=form,
        recipient_name=recipient_name,
    )



@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


def send_email_http(to, subject, html):
    try:
        api_key = os.getenv("MAIL_PASSWORD")
        sender = os.getenv("MAIL_DEFAULT_SENDER")

        if not api_key or not sender:
            raise ValueError("Email env vars missing")

        headers = {
            "accept": "application/json",
            "api-key": api_key,
            "content-type": "application/json",
        }

        payload = {
            "sender": {"email": sender, "name": "Uknowme"},
            "to": [{"email": to}],
            "subject": subject,
            "htmlContent": html,
        }

        r = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            json=payload,
            headers=headers,
            timeout=10,
        )

        if r.status_code >= 400:
            print("Brevo error:", r.text)

    except Exception as e:
        print("Email system failure:", e)




def generate_reset_token(email):
    return serializer.dumps(email, salt="password-reset")

def verify_reset_token(token, expiration=3600):
    try:
        return serializer.loads(token, salt="password-reset", max_age=expiration)
    except Exception:
        return None

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = normalize_email(request.form.get("email", ""))
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(user.email)
            reset_link = url_for("reset_password", token=token, _external=True)

            send_email_http(
                user.email,
                "Reset your Uknowme password",
                f"""
                <p>Click the link below to reset your password:</p>
                <a href="{reset_link}">{reset_link}</a>
                """
            )
        return redirect(url_for("forgot_password", sent="1"))

    sent = request.args.get("sent") == "1"
    return render_template("forgot_password.html", sent=sent)






@app.route("/verify-email/<token>")
def verify_email(token):
    email = verify_email_token(token)
    if not email:
        return render_template("verify_failed.html")

    user = User.query.filter_by(email=email).first()
    if user:
        user.is_verified = True
        db.session.commit()

    return render_template("verify_success.html", success=True)





@app.route("/resend-verification", methods=["POST"])
@login_required
def resend_verification():
    if current_user.is_verified:
        return redirect(url_for("dashboard"))

    token = generate_verify_token(current_user.email)
    verify_link = url_for("verify_email", token=token, _external=True)

    send_email_http(
        current_user.email,
        "Verify your Uknowme email",
        f"""
        <p>Please verify your email by clicking the link below:</p>
        <p><a href="{verify_link}">Verify my email</a></p>
        """
    )

    flash("Verification email resent.")
    return redirect(url_for("unverified"))



@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        return "Invalid or expired token."

    user = User.query.filter_by(email=email).first()
    if not user:
        return "User not found."

    if request.method == "POST":
        new_password = request.form.get("password")
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        logout_user()

        return redirect(url_for("login"))


    return render_template("reset_password.html")



def generate_verify_token(email):
    return serializer.dumps(email, salt="email-verify")

def verify_email_token(token):
    try:
        return serializer.loads(token, salt="email-verify", max_age=86400)
    except Exception:
        return None

@app.cli.command("init-db")
def init_db():
    """Initialize database tables."""
    with app.app_context():
        db.create_all()
    print("Database initialized.")




@app.route("/test-email")
@login_required
def test_email():
    send_email_http(
        current_user.email,
        "Brevo test – Uknowme ✅",
        "<h3>Email is working perfectly 🎉</h3><p>Sent via Brevo HTTP API.</p>"
    )
    return "Email sent. Check your inbox."



@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        # Toggle email notifications
        current_user.email_notifications = bool(
            request.form.get("email_notifications")
        )

        # Change password (optional)
        new_password = request.form.get("new_password")
        if new_password:
            current_user.password_hash = generate_password_hash(new_password)

        db.session.commit()
        flash("Settings updated successfully.")

    return render_template("settings.html")


@app.route("/admin")
@login_required
def admin():
    ensure_admin_access()

    users = User.query.order_by(User.id.desc()).all()
    messages = Message.query.order_by(Message.created_at.desc()).limit(250).all()
    suspended_count = sum(1 for user in users if user.is_suspended)
    verified_count = sum(1 for user in users if user.is_verified)

    return render_template(
        "admin.html",
        messages=messages,
        users=users,
        suspended_count=suspended_count,
        verified_count=verified_count,
        total_messages=Message.query.count(),
    )


@app.route("/admin/user/<int:user_id>")
@login_required
def admin_user(user_id):
    ensure_admin_access()
    user = User.query.get_or_404(user_id)
    user_messages = Message.query.filter_by(user_id=user.id).order_by(
        Message.created_at.desc()
    ).all()

    return render_template(
        "admin_user.html",
        user=user,
        messages=user_messages,
    )


@app.route("/admin/user/<int:user_id>/suspend", methods=["POST"])
@login_required
def admin_toggle_suspend(user_id):
    ensure_admin_access()
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You cannot suspend your own account.", "danger")
        return admin_redirect_back("admin_user", user_id=user.id)

    if user.email.lower() == PRIMARY_ADMIN_EMAIL:
        flash("The primary admin account cannot be suspended.", "danger")
        return admin_redirect_back("admin_user", user_id=user.id)

    user.is_suspended = not user.is_suspended
    user.suspended_at = datetime.utcnow() if user.is_suspended else None
    db.session.commit()
    flash(
        f"Account {'suspended' if user.is_suspended else 'reactivated'} for {user.email}.",
        "success",
    )
    return admin_redirect_back("admin_user", user_id=user.id)


@app.route("/admin/user/<int:user_id>/verify", methods=["POST"])
@login_required
def admin_toggle_verify(user_id):
    ensure_admin_access()
    user = User.query.get_or_404(user_id)
    user.is_verified = not user.is_verified
    db.session.commit()
    flash(
        f"Verification {'enabled' if user.is_verified else 'disabled'} for {user.email}.",
        "success",
    )
    return admin_redirect_back("admin_user", user_id=user.id)


@app.route("/admin/user/<int:user_id>/identity", methods=["POST"])
@login_required
def admin_update_user_identity(user_id):
    ensure_admin_access()
    user = User.query.get_or_404(user_id)

    new_email = normalize_email(request.form.get("email"))
    new_slug = (request.form.get("slug") or "").strip()

    if not new_email or "@" not in new_email or "." not in new_email.split("@")[-1]:
        flash("Enter a valid email address.", "danger")
        return admin_redirect_back("admin_user", user_id=user.id)

    if not re.fullmatch(r"[A-Za-z0-9_-]{4,50}", new_slug):
        flash(
            "Slug must be 4-50 characters and contain only letters, numbers, _ or -.",
            "danger",
        )
        return admin_redirect_back("admin_user", user_id=user.id)

    email_taken = User.query.filter(
        User.id != user.id,
        User.email == new_email,
    ).first()
    if email_taken:
        flash("That email is already used by another account.", "danger")
        return admin_redirect_back("admin_user", user_id=user.id)

    slug_taken = User.query.filter(
        User.id != user.id,
        User.slug == new_slug,
    ).first()
    if slug_taken:
        flash("That slug is already used by another account.", "danger")
        return admin_redirect_back("admin_user", user_id=user.id)

    user.email = new_email
    user.slug = new_slug
    user.is_admin = is_admin_email(new_email)
    db.session.commit()
    flash("User identity updated.", "success")
    return admin_redirect_back("admin_user", user_id=user.id)


@app.route("/admin/user/<int:user_id>/password", methods=["POST"])
@login_required
def admin_change_user_password(user_id):
    ensure_admin_access()
    user = User.query.get_or_404(user_id)
    new_password = (request.form.get("new_password") or "").strip()

    if not is_strong_password(new_password):
        flash(
            "Password must be at least 8 chars and include uppercase, lowercase, and a number.",
            "danger",
        )
        return admin_redirect_back("admin_user", user_id=user.id)

    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    flash(f"Password updated for {user.email}.", "success")
    return admin_redirect_back("admin_user", user_id=user.id)


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
def admin_delete_user(user_id):
    ensure_admin_access()
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return admin_redirect_back("admin_user", user_id=user.id)

    if user.email.lower() == PRIMARY_ADMIN_EMAIL:
        flash("The primary admin account cannot be deleted.", "danger")
        return admin_redirect_back("admin_user", user_id=user.id)

    messages = Message.query.filter_by(user_id=user.id).all()
    for msg in messages:
        remove_uploaded_media(msg.media_path)
        db.session.delete(msg)

    db.session.delete(user)
    db.session.commit()
    flash("User and all associated messages deleted.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/message/<int:msg_id>/edit", methods=["POST"])
@login_required
def admin_edit_message(msg_id):
    ensure_admin_access()
    msg = Message.query.get_or_404(msg_id)
    new_text = (request.form.get("text") or "").strip()

    if not new_text:
        flash("Message text cannot be empty.", "danger")
        return admin_redirect_back("admin_user", user_id=msg.user_id)

    msg.text = new_text
    msg.edited_at = datetime.utcnow()
    db.session.commit()
    flash("Message updated.", "success")
    return admin_redirect_back("admin_user", user_id=msg.user_id)


@app.route("/admin/message/<int:msg_id>/delete", methods=["POST"])
@login_required
def admin_delete_message(msg_id):
    ensure_admin_access()
    msg = Message.query.get_or_404(msg_id)
    owner_id = msg.user_id

    remove_uploaded_media(msg.media_path)
    db.session.delete(msg)
    db.session.commit()
    flash("Message deleted.", "success")
    return admin_redirect_back("admin_user", user_id=owner_id)


@app.route("/admin/message/<int:msg_id>/reported", methods=["POST"])
@login_required
def admin_toggle_message_reported(msg_id):
    ensure_admin_access()
    msg = Message.query.get_or_404(msg_id)
    msg.reported = not msg.reported
    db.session.commit()
    flash(
        f"Reported flag {'enabled' if msg.reported else 'cleared'} for message #{msg.id}.",
        "success",
    )
    return admin_redirect_back("admin_user", user_id=msg.user_id)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    endpoint = request.endpoint or ""
    if endpoint not in PUBLIC_ENDPOINTS and not endpoint.startswith("static"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return response


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/report/<int:msg_id>", methods=["POST"])
@login_required
def report_message(msg_id):
    msg = Message.query.get_or_404(msg_id)
    msg.reported = True
    db.session.commit()
    flash("Message reported.")
    return redirect(request.referrer)


# --------------------
# INIT DB
# --------------------

if __name__ == "__main__":
    app.run()
