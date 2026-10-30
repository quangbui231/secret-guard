# Mã nguồn thông thường
def calculate_total(price, quantity):
    return price * quantity

def greet_user(name):
    return f"Hello, {name}"

def calculate_average(values):
    return sum(values) / len(values)

class User:
    def __init__(self, username):
        self.username = username

MAX_RETRIES = 5
DEFAULT_PORT = 8080
APP_NAME = "Secret Guard Demo"
DEBUG_MODE = True