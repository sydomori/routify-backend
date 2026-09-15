from datetime import datetime, timezone
from app.extensions import db

ROLES = ("driver", "manager")
DRIVER_STATUSES = ("pending_documents", "pending_review", "verified", "rejected")

#freshly called every time a row is inserted
def utcnow():
    return datetime.now(timezone.utc)

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    must_change_password = db.Column(db.Boolean, default=True, nullable=False)
    driver_status = db.Column(db.String(30), nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)

def __repr__(self):
    return f"<User id={self.id} phone={self.phone} role={self.role}>"