from datetime import datetime, timezone
from app.extensions import db

ROLES = ("driver", "manager")
DRIVER_STATUSES = ("pending_documents", "pending_review", "verified", "rejected")