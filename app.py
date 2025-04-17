from flask import Flask, flash, render_template, session, request, redirect, url_for
from flask_mail import Mail, Message
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_session import Session
from zxcvbn import zxcvbn
import pyotp
import datetime

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/cm3148"
app.secret_key = "HbXEVGi4ANN#n*wWbUnw8hTFXE9Gay"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 30
Session(app)

app.config['MAIL_SERVER']='sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = '352d3e31dfdc1f'
app.config['MAIL_PASSWORD'] = 'fa295d1cf087db'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

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
            session.permanent = True
        else:
            flash('Invalid username or password. Please try again.', 'error')
    return render_template("login.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        password_strength = zxcvbn(password, user_inputs=[username])

        # Check if the username or email already exists
        if users.find_one({'username': username}) or users.find_one({'email': email}):
            flash('Username or email already taken. Choose a different one.', 'error')
        # Check if passwords match
        elif password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
        # Check password strength
        elif password_strength['score'] < 3:
            flash(password_strength['suggestions'], 'error')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            mongo.db.users.insert_one({'username': username, 'email': email, 'password': hashed_password})
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

@app.route("/change-password", methods=['POST'])
def change():
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
            flash('Password changed successful.', 'success')
    return render_template("account.html")

@app.route("/delete-account", methods=['POST'])
def delete_account():
    if request.method == 'POST':
        user = users.find_one({'username': session['username']})
        password = request.form['password']
        hashed_password = user['password']
        is_valid = bcrypt.check_password_hash(hashed_password, password)

        if is_valid:
            users.delete_one({'username': session['username']})
            session["username"] = None
            flash('Account deleted successfully.', 'success')
            return redirect("/")
        else:
            flash('Invalid password. Please try again.', 'error')
    return render_template("account.html")

@app.route("/forgot-password", methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        if users.find_one({'email': email}):
            reset_token = pyotp.random_base32()
            users.update_one({'email': email}, {'$set': {'reset_token': reset_token, 'token_expiry': datetime.datetime.now() + datetime.timedelta(hours=1)}})
            reset_link = url_for('reset_password', token=reset_token, _external=True)

            msg = Message(
                'Reset Your Password',
                sender= 'test@gmail.com',
                recipients=[email],
                body='To reset your password, please click the link below:\n\n' + reset_link + '\n\nThis link will expire in one hour. If you did not request this, please ignore this email.'
            )
            mail.send(msg)
        flash('If that email address is in our database, we will send you an email to reset your password.', 'success')

    return render_template("forgot-password.html")

@app.route("/reset-password", methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        token = request.args.get('token')
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if the token is valid
        user = users.find_one({'reset_token': token})
        if user is None:
            flash('Invalid reset token. Please try again.', 'error')
            return redirect(url_for('forgot_password'))
        elif user['token_expiry'] < datetime.datetime.now():
            users.update_one({'reset_token': token}, {'$set': {'reset_token': None, 'token_expiry': None}})
            flash('Reset token has expired. Please request a new one.', 'error')
            return redirect(url_for('forgot_password'))

        # Check password strength
        strong, message = check_password_strength(new_password, confirm_password)
        if not strong:
            flash(message, 'error')
        else:
            hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            users.update_one({'reset_token': token}, {'$set': {'password': hashed_new_password, 'reset_token': None, 'token_expiry': None , 'last_password_change': datetime.datetime.now()}})
            flash('Password reset successful. You can now log in with your new password.', 'success')
            return redirect(url_for('login'))
    return render_template("reset-password.html")



def check_password_strength(password, confirm_password):
    password_acceptable = True
    message = ""
    password_strength = zxcvbn(password)

    if password != confirm_password:
        password_acceptable = False
        message = "Passwords do not match."
    elif password_strength['score'] < 3:
        password_acceptable = False
        message = "Password is too weak. Please choose a stronger password."
    elif len(password) < 12 or len(password) > 72:
        password_acceptable = False
        message = "Password must be between 12 and 72 characters."
    else:
        message = "Password is strong."
    
    return password_acceptable, message

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)