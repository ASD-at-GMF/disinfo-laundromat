import os

class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = True
class DevelopmentConfig(Config):
    DEVELOPMENT = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.getenv("DEVELOPMENT_DATABASE_URL")
    SQLALCHEMY_ENGINE_OPTIONS = {
        'connect_args': {
            'options': '-c statement_timeout=5000'
        }
    }
class UATConfig(Config):
    DEVELOPMENT = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:postgres@flask_db:5432/postgres"
    SQLALCHEMY_ENGINE_OPTIONS = {
        'connect_args': {
            'options': '-c statement_timeout=5000'
        }
    }
class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.getenv("PRODUCTION_DATABASE_URL")
    SQLALCHEMY_ENGINE_OPTIONS = {
        'connect_args': {
            'options': '-c statement_timeout=5000'
        }
    }
config = {
    "development": DevelopmentConfig,
    "uat": UATConfig,
    "production": ProductionConfig
}