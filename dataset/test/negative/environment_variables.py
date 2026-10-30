# Tham chiếu biến môi trường, không chứa giá trị secret
import os


API_KEY = os.getenv("API_KEY")
PASSWORD = os.environ.get("PASSWORD")
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
SECRET_KEY = os.environ.get("SECRET_KEY")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
DB_PASSWORD = "${DB_PASSWORD}"
TOKEN = "$ACCESS_TOKEN"
PRIVATE_KEY = os.getenv("PRIVATE_KEY")