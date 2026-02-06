from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(50), unique=True, nullable=False)

    email_notifications = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_suspended = db.Column(db.Boolean, default=False)
    suspended_at = db.Column(db.DateTime, nullable=True)

    messages = db.relationship("Message", backref="user", lazy=True)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    text = db.Column(db.Text, nullable=True)
    media_path = db.Column(db.String(255))
    media_type = db.Column(db.String(20))
    is_read = db.Column(db.Boolean, default=False)
    reported = db.Column(db.Boolean, default=False)
    sender_ip = db.Column(db.String(64), nullable=True)
    sender_user_agent = db.Column(db.Text, nullable=True)
    sender_account_email = db.Column(db.String(120), nullable=True)
    edited_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class RateLimit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, nullable=False)
    last_hit = db.Column(db.Float, nullable=False)
