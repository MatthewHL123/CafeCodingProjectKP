from pymongo import MongoClient
import jwt
import datetime
import hashlib
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_cors import CORS
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

SECRET_KEY = "SPARTA"

MONGODB_CONNECTION_STRING = "mongodb+srv://hamidahishaka:Trinanda13@cluster0.ldc3n3w.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGODB_CONNECTION_STRING)
db = client.dbsparta_plus_week4

@app.route('/')
def home():
    try:
        token_receive = request.cookies.get("mytoken")
        user_info = None

        if token_receive:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
            user_info = db.users.find_one({'username': payload['id']})

        if user_info:
            if user_info['role'] == 'admin':
                return render_template('home.html', user_info=user_info)
            else:
                return render_template('home.html', user_info=user_info)
        else:
            # Handle cases where the user is not logged in
            return render_template('home.html')

    except jwt.ExpiredSignatureError:
        app.logger.error("JWT ExpiredSignatureError")
        return render_template("home.html")

    except jwt.exceptions.DecodeError:
        app.logger.error("JWT DecodeError")
        return render_template("home.html")


@app.route("/login")
def login():
    token_receive = request.cookies.get("mytoken")
    try:
        if token_receive:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
            user_info = db.users.find_one({'username': payload['id']})
            if user_info:
                return redirect(url_for('home'))
            
        return render_template("login.html")
    
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return render_template("login.html")
    
@app.route("/daftar")
def daftar():
    token_receive = request.cookies.get("mytoken")
    try:
        if token_receive:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
            user_info = db.users.find_one({'username': payload['id']})
            if user_info:
                return redirect(url_for('home'))
            
        return render_template("daftar.html")
    
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return render_template("daftar.html")


@app.route("/user/<username>")
def user(username):
    # an endpoint for retrieving a user's profile information
    # and all of their posts
    token_receive = request.cookies.get("mytoken")
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
        # if this is my own profile, True
        # if this is somebody else's profile, False
        status = username == payload["id"]  

        user_info = db.users.find_one({"username": username}, {"_id": False})
        return render_template("user.html", user_info=user_info, status=status)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("home"))


@app.route("/user_signup", methods=["POST"])
def user_signup():
    try:
        username_receive = request.form["username"]
        email_receive = request.form["email"]
        pw_receive = request.form["password"]
        pw_hash = hashlib.sha256(pw_receive.encode("utf-8")).hexdigest()

        user_exists = bool(db.users.find_one({"username": username_receive}))
        if user_exists:
            return jsonify({"result": "error_uname", "msg": f"An account with username {username_receive} already exists. Please Login!"})
        else:
            doc = {
                "username": username_receive,
                "email": email_receive,
                "password": pw_hash,
                "profile_info": "",
                "role": "member"
            }
            db.users.insert_one(doc)
            app.logger.info(f"User {username_receive} successfully signed up.")
            return jsonify({"result": "success"})

    except Exception as e:
        app.logger.error(f"Error during user signup: {str(e)}")
        return jsonify({"result": "error_server", "msg": "Internal server error. Please try again."})
    
@app.route("/sign_in", methods=["POST"])
def sign_in():
    email_receive = request.form["email_give"]
    password_receive = request.form["password_give"]
    pw_hash = hashlib.sha256(password_receive.encode("utf-8")).hexdigest()
    result = db.users.find_one(
        {
            "email": email_receive,
            "password": pw_hash,
        }
    )
    if result:
        payload = {
            "id": result["username"],
            "exp": datetime.utcnow() + timedelta(seconds=60 * 60 * 24),
            "role": result["role"],
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        response = jsonify(
            {
                "result": "success",
                "token": token,
            }
        )
        response.set_cookie("mytoken", token, httponly=True)
        return response
    else:
        return jsonify(
            {
                "result": "fail",
                "msg": "We couldn't find a user with that username/password combination.",
            }
        )


if __name__ == '__main__':  
   app.run('0.0.0.0',port=5000,debug=True)
