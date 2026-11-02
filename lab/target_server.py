from flask import Flask, request

app = Flask(__name__)


@app.get("/")
def index():
    return "Lab target is running\n"


@app.get("/search")
def search():
    return f"Results for: {request.args.get('q', '')}\n"


@app.post("/login")
def login():
    return "Invalid credentials\n", 401


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)