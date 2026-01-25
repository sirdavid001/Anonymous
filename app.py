import os
import secrets
from flask import Flask, render_template, redirect, request, flash
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
from flask_mail import Message
from models import db, User, Message
from time import time

DROP_LIMIT = {}

# --------------------
# BASIC SETUP
# --------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///uknowme.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "static/uploads")
app.config["MAX_CONTENT_LENGTH"] = 250 * 1024 * 1024  # 250MB


db.init_app(app)


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
    password = PasswordField(validators=[DataRequired()])


class LoginForm(FlaskForm):
    email = StringField(validators=[Email(), DataRequired()])
    password = PasswordField(validators=[DataRequired()])


class DropForm(FlaskForm):
    message = TextAreaField(validators=[DataRequired()])

# --------------------
# ROUTES
# --------------------
@app.route("/", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("Email already registered.")
            return redirect("/login")

        user = User(
            email=form.email.data,
            password_hash=generate_password_hash(form.password.data),
            slug=secrets.token_urlsafe(6)
        )
        db.session.add(user)
        db.session.commit()

        flash("Account created. Please log in.")
        return redirect("/login")

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect("/dashboard")

        flash("Invalid email or password.")

    return render_template("login.html", form=form)


@app.route("/dashboard")
@login_required
def dashboard():
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
    form = DropForm()

    if form.validate_on_submit():
        file = request.files.get("file")
        media_path = None
        media_type = None

        if file and file.filename and allowed_file(file.filename):
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            media_path = f"uploads/{filename}"
            

            ext = filename.lower().rsplit(".", 1)[-1]
            if ext in ["png", "jpg", "jpeg", "gif"]:
                media_type = "image"
            elif ext in ["mp4", "webm", "mov"]:
                media_type = "video"
            elif ext in ["mp3", "wav", "aac"]:
                media_type = "audio"

            elif file and file.filename:
                flash("Unsupported file type.")
                return redirect(request.url)
            
            ip = request.remote_addr
            now = time()
            last = DROP_LIMIT.get(ip)
            if last and now - last < 15:
                flash("Slow down. Try again in a few seconds.")
                return redirect(request.url)
            DROP_LIMIT[ip] = now


        msg = Message(
            user_id=user.id,
            text=form.message.data,
            media_path=media_path,
            media_type=media_type
        )

        db.session.add(msg)
        db.session.commit()

        flash("Message sent anonymously.")
        return redirect(request.url)

    return render_template("drop.html", form=form)



@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")

# --------------------
# INIT DB
# --------------------
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)


@app.route("/test-email")
@login_required
def test_email():
    msg = Message(
        subject="Brevo test – Uknowme ✅",
        recipients=[current_user.email],
        html="<h3>Email is working perfectly 🎉</h3><p>This email was sent via Brevo.</p>"
    )
    mail.send(msg)
    return "Email sent. Check your inbox (and spam)."