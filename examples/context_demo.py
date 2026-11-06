# Synthetic fixtures for scanning only; do not execute this file.
password = load_password()
token = config["TOKEN"]

settings = {"password": "DemoPass123!"}
connect(client_secret="alpha!987")
fallback = os.getenv("PASSWORD", "Fallback!123")

# Placeholder must not become a blocking finding.
template = {"password": "your_password_here"}
