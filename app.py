from flask import Flask, flash, render_template, session, request, redirect, url_for
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_session import Session
from zxcvbn import zxcvbn

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/cm3148"
app.secret_key = "HbXEVGi4ANN#n*wWbUnw8hTFXE9Gay"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

mongo = PyMongo(app)
users = mongo.db.users

bcrypt = Bcrypt(app)


@app.route("/")
def index():
    if session.get('username'):
        message = "Welcome, " + session['username']
    else:
        message = "Welcome, Guest"
    return render_template("index.html", message=message)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user exists
        user = users.find_one({'username': username})
        if user is None:
            flash('Invalid username or password. Please try again.', 'error')
            return render_template("login.html")
        
        # Check if the password is correct
        hashed_password = user['password']
        is_valid = bcrypt.check_password_hash(hashed_password, password) 

        if is_valid:
            flash('Login successful.', 'success')
            session['username'] = username
        else:
            flash('Invalid username or password. Please try again.', 'error')
    return render_template("login.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        password_strength = zxcvbn(password, user_inputs=[username])

        # Check if the username already exists
        if users.find_one({'username': username}):
            flash('Username already exists. Choose a different one.', 'error')
        # Check password strength
        elif password_strength['score'] < 3:
            flash('Password is too weak. Please choose a stronger password.', 'error')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            mongo.db.users.insert_one({'username': username, 'password': hashed_password})
            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template("register.html")

@app.route("/account")
def account():
    if not session.get('username'):
        return redirect("/login")
    return render_template("account.html")

@app.route("/logout")
def logout():
    session["username"] = None
    return redirect("/")

@app.route("/reset-password", methods=['POST'])
def reset_password():
    if request.method == 'POST':
        user = users.find_one({'username': session['username']})
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        hashed_old_password = user['password']
        is_valid = bcrypt.check_password_hash(hashed_old_password, old_password)
        password_strength = zxcvbn(new_password, user_inputs=[session['username']])

        # Check if old password is correct and new passwords match
        if not (is_valid) or new_password != confirm_password:
            flash('Invalid old password or new passwords do not match.', 'error')
        # Check strength of new password
        elif password_strength['score'] < 3:
            flash('New password is too weak. Please choose a stronger password.', 'error')
        # Check if old password is the same as new password
        elif old_password == new_password:
            flash('New password cannot be the same as the old password.', 'error')
        else:
            hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            mongo.db.users.insert_one({'username': session['username'], 'password': hashed_new_password})
            flash('Password reset successful.', 'success')
    return render_template("account.html")

# @app.route("/delete-account", methods=['POST'])
# def delete_account():


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)