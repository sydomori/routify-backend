import pytest
from flask_jwt_extended import create_access_token

from app import create_app
from app.extensions import db as _db
from app.auth.models import User
from app.auth.utils import hash_password


"""
set up temporary isolated testing environment
ensures every test runs in a blank db
"""
@pytest.fixture() #tells pytest the function is a set up tool
def app():
    """Fresh app + in-memory DB per test function"""
    application = create_app("testing") #app factory function from app/__init__.py used to create a testing environment
    with application.app_context():
        _db.create_all()
        yield application #run the test
        _db.session.remove() #close the db session. Clears out leftover database transactions
        _db.drop_all() #deletes tables & data created from the test leaving the db empty


@pytest.fixture()
def db(app):
    return _db


