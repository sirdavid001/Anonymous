import os
import secrets
from flask import Flask, abort, render_template, redirect, request, flash, url_for
from flask_login import (
    LoginManager, login_user,
    login_required, logout_user, current_user
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Email
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
    SESSION_COOKIE_SECURE=True,  
)



db.init_app(app)

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])



ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif",
    "mp4", "webm", "mov",
    "mp3", "wav", "aac"
}

def allowed_file(filename):
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS





# --------------------
# LOGIN MANAGER
# --------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        return None

# --------------------
# FORMS
# --------------------
class RegisterForm(FlaskForm):
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

# --------------------
# ROUTES
# --------------------
@app.route("/", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        # Check if email already exists
        if User.query.filter_by(email=form.email.data).first():
            flash("Email already registered.")
            return redirect(url_for("login"))

        # Create user
        user = User(
            email=form.email.data,
            password_hash=generate_password_hash(form.password.data),
            slug=secrets.token_urlsafe(6),
            is_verified=False
        )

        db.session.add(user)
        db.session.commit()

        # Generate verification token
        token = generate_verify_token(user.email)
        verify_link = url_for("verify_email", token=token, _external=True)

        # Send verification email (NOT enforced)
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

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)

            if not user.is_verified:
                flash("Please verify your email before continuing.")
                return redirect(url_for("unverified"))

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

    form = DropForm()

    if form.validate_on_submit():
        ip = request.remote_addr
        now = time()
        record = RateLimit.query.filter_by(ip=ip).first()

        if record and now - record.last_hit < 15:
            flash("Slow down. Try again in a few seconds.")
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
                flash("Unsupported file type.")
                return redirect(request.url)

            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            ext = file.filename.rsplit(".", 1)[-1]
            filename = f"{secrets.token_hex(16)}.{ext}"
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)
            file.seek(0, os.SEEK_END)
            size = file.tell()
            file.seek(0)

            if size > 250 * 1024 * 1024:
                flash("File too large.")
                return redirect(request.url)

            media_path = f"uploads/{filename}"

            ext = filename.rsplit(".", 1)[-1].lower()
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
            media_type=media_type
        )

        db.session.add(msg)
        db.session.commit()

        if user.email_notifications:
            send_email_http(
                user.email,
                "You received a new anonymous message 👀",
                "<p>You just received a new anonymous message.</p>"
            )

        flash("Message sent anonymously.")
        return redirect(request.url)

    return render_template("drop.html", form=form)




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
        email = request.form.get("email")
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
        return "If that email exists, a reset link has been sent."

    return render_template("forgot_password.html")






@app.route("/verify-email/<token>")
def verify_email(token):
    email = verify_email_token(token)
    if not email:
        return render_template("verify_failed.html")

    user = User.query.filter_by(email=email).first()
    if user:
        user.is_verified = True
        db.session.commit()

    return render_template("verify_success.html")





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
    if not current_user.is_admin:
        abort(403)

    messages = Message.query.order_by(Message.created_at.desc()).limit(100).all()
    users = User.query.all()

    return render_template(
        "admin.html",
        messages=messages,
        users=users
    )


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response





# --------------------
# INIT DB
# --------------------

if __name__ == "__main__":
    app.run()


