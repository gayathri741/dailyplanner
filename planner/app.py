from cs50 import SQL
from tempfile import mkdtemp
from flask import Flask, redirect, render_template, request, session, jsonify
from flask_session.__init__ import Session
from helpers import apology, login_required, lookup
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///registers.db")

@app.route("/")
@login_required
def tasks():
    if "todos" not in session:
        session["todos"] = []
    return render_template("tasks.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("Must provide username")
        elif not request.form.get("password"):
            return apology("Must provide password")

        rows = db.execute("SELECT * FROM registers WHERE username = :username", username=request.form.get("username"))
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]
        return redirect("/")

    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        if not request.form.get("username"):
            return apology("Must provide username")
        elif not request.form.get("password"):
            return apology("Must provide password")
        username = request.form.get("username")
        rows = db.execute("SELECT * FROM registers WHERE username = :username", username=username)
        if len(rows) != 0:
            return apology("Username taken")
        if request.form.get("password") != request.form.get("password2"):
            return apology("Passwords don't match")
        password = generate_password_hash(request.form.get("password"))
        db.execute("insert into registers (username,password) values (:name, :password)", name=username, password=password)
        return redirect("/")

