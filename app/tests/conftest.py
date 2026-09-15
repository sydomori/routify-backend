import pytest
from flask_jwt_extended import create_access_token

from app import create_app
from app.extensions import db as _db
from app.auth.models import User
from app.auth.utils import hash_password


#set up temporary isolated testing environment
@pytest.fixture()
def app():
    """Fresh app + in-memory DB per test function"""
    application = create_app("testing")
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


