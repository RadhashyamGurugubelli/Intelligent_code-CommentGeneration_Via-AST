import os

from backend.app import app

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "5000"))

if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=app.config["DEBUG"])
