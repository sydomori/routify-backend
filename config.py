import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    """base configuration class with shared default settings for all environments"""

    SECRET_KEY = os.environ.get('SECRET_KEY',"dev-secret-change-me")
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY',"dev-jwt-secret-change-me")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=12)

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    #third party integrations read from env, not hardcoded in config.py

    TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
    TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER')

    SUPABASE_URL = os.environ.get('SUPABASE_URL')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
    SUPABASE_BUCKET = os.environ.get('SUPABASE_BUCKET', "driver-documents")

    #frontend origin for CORS, default to localhost:5173 for development
    FRONTEND_ORIGIN = os.environ.get('FRONTEND_ORIGIN', "http://localhost:5173")
