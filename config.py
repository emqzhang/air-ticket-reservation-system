import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    SECRET_KEY = os.environ["SECRET_KEY"]        # required: app fails fast if missing
    DB_HOST = os.environ.get("DB_HOST", "localhost")
    DB_PORT = int(os.environ.get("DB_PORT", 3306))
    DB_USER = os.environ["DB_USER"]
    DB_PASSWORD = os.environ["DB_PASSWORD"]
    DB_NAME = os.environ.get("DB_NAME", "air_ticket")
