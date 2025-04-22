from flask import Flask, flash, render_template, session, request, redirect, url_for
from flask_mail import Mail, Message
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_session import Session
from flask_limiter import Limiter
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
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

mongo = PyMongo(app)
users = mongo.db.users

bcrypt = Bcrypt(app)
limiter = Limiter(
    app,
    default_limits=["200 per day", "50 per hour"],
)

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
            # Check if the user has verified their email
            if not user.get('is_verified'):
                session['username'] = username
                session.permanent = True
                flash('Please verify your email before logging in.', 'error')
                return redirect(url_for('verify_email'))
            # Check if two-factor authentication is enabled
            if '2fa_secret' in user:
                session['temp_username'] = username
                return redirect('/verify-two-factor-auth')
            # If two-factor authentication is not enabled, log in the user
            session['username'] = username
            session.permanent = True
            flash('Login successful.', 'success')
            # return redirect(url_for('/'))
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

        password_strength = zxcvbn(password, user_inputs=[username, email])

        # Check if the username or email already exists
        if users.find_one({'username': username}) or users.find_one({'email': email}):
            flash('Username or email already taken. Choose a different one.', 'error')
        # Check if passwords match
        elif password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
        # Check password strength
        elif password_strength['score'] < 3:
            flash("Password to weak:", password_strength['feedback']['suggestions'], 'error')
        # Save user details and send verification email
        else:
            # Save user details to the database
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            mongo.db.users.insert_one({'username': username, 'email': email, 'password': hashed_password, 'is_verified': False})

            # Send verification email
            verification_code = pyotp.random_base32()
            users.update_one({'username': username}, {'$set': {'verification_code': verification_code, 'verification_code_sent': datetime.datetime.now()}})
            verification_link = url_for('verify_email', _external=True)
            subject='Verify Your Email'
            body='To verify your email, please click the link below:\n\n' + verification_link + '\n\nAnd enter the following code:\n\n' + verification_code+ '\n\nThis link will expire in one hour. If you did not request this, please ignore this email.'
            send_email(email, subject, body)
            flash('Registration successful. A verification code has been sent to your email', 'success')

            # Log in the user
            session['username'] = username
            session.permanent = True
            return redirect(url_for('verify_email'))
    return render_template("register.html")

@app.route("/verify-email", methods=['GET', 'POST'])
def verify_email():
    if not session.get('username'):
        return redirect("/login")
    elif users.find_one({'username': session['username']}).get('is_verified'):
        flash('Email already verified. You can now access your account.', 'success')
        return redirect(url_for('account'))
    
    if request.method == 'POST':
        user = users.find_one({'username': session['username']})
        email = user.get('email')
        verification_code = request.form['code']

        if user is None:
            flash('Invalid email address. Please try again.', 'error')
            return render_template("verify-email.html")

        # Check if the verification code has expired
        if user.get('verification_code_sent') and (datetime.datetime.now() - user['verification_code_sent']).total_seconds() > 3600:
            flash('Verification code has expired. Please request a new one.', 'error')
            return redirect(url_for('register'))
        # Check if the verification code is correct
        if verification_code == user['verification_code']:
            users.update_one({'email': email}, {'$set': {'is_verified': True}, '$unset': {'verification_code': None, 'verification_code_sent': None}})
            flash('Email verified successfully. You can now access your account.', 'success')
            return redirect(url_for('account'))
        else:
            flash('Invalid verification code. Please try again.', 'error')
    return render_template("verify-email.html")

@app.route("/resend-verification-code", methods=['POST'])
@limiter.limit("5 per minute")
def resend_verification_code():
    if not session.get('username'):
        return redirect("/login")
    
    user = users.find_one({'username': session['username']})
    email = user.get('email')
    verification_code = pyotp.random_base32()
    users.update_one({'username': session['username']}, {'$set': {'verification_code': verification_code, 'verification_code_sent': datetime.datetime.now()}})
    verification_link = url_for('verify_email', _external=True)
    
    subject='Verify Your Email'
    body='To verify your email, please click the link below:\n\n' + verification_link + '\n\nAnd enter the following code:\n\n' + verification_code+ '\n\nThis link will expire in one hour. If you did not request this, please ignore this email.'
    send_email(email, subject, body)
    flash('A new verification code has been sent to your email.', 'success')
    return redirect(url_for('verify_email'))

@app.route("/account")
def account():
    # Check if the user is logged in
    if not session.get('username'):
        return redirect("/login")
    # Check if the user has verified their email
    elif not users.find_one({'username': session['username']}).get('is_verified'):
        flash('Please verify your email before accessing your account.', 'error')
        return redirect(url_for('verify_email'))
    
    # Check if the user has two-factor authentication enabled
    user = users.find_one({'username': session['username']})
    if user.get('2fa_secret'):
        return render_template("account.html", two_factor_enabled=True)
    else:
        return render_template("account.html", two_factor_enabled=False)


@app.route("/logout")
def logout():
    session["username"] = None
    return redirect("/")

@app.route("/change-password", methods=['POST'])
def change_password():
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
            flash("Password too weak:", password_strength['feedback']['suggestions'], 'error')
        # Check if old password is the same as new password
        elif old_password == new_password:
            flash('New password cannot be the same as the old password.', 'error')
        else:
            hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            mongo.db.users.update_one({'username': session['username']}, {'$set':{ 'password': hashed_new_password}})
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
@limiter.limit("5 per minute")
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        # If user exists, generate a reset token and send email
        if users.find_one({'email': email}):
            reset_token = pyotp.random_base32()
            users.update_one({'email': email}, {'$set': {'reset_token': reset_token, 'token_expiry': datetime.datetime.now() + datetime.timedelta(hours=1)}})
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            subject = 'Reset Your Password'
            body='To reset your password, please click the link below:\n\n' + reset_link + '\n\nThis link will expire in one hour. If you did not request this, please ignore this email.'
            send_email(email, subject, body)
        flash('If that email address is in our database, we will send you an email to reset your password.', 'success')

    return render_template("forgot-password.html")

@app.route("/reset-password", methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        token = request.args.get('token')
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if the token is associated with an existing user
        user = users.find_one({'reset_token': token})
        if user is None:
            flash('Invalid reset token. Please try again.', 'error')
            return redirect(url_for('forgot_password'))
        # Check if the token has expired
        elif user['token_expiry'] < datetime.datetime.now():
            users.update_one({'reset_token': token}, {'$unset': {'reset_token': None, 'token_expiry': None}})
            flash('Reset token has expired. Please request a new one.', 'error')
            return redirect(url_for('forgot_password'))

        password_strength = zxcvbn(new_password, user_inputs=[user['username']])

        # Check if passwords match
        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
        # Check password strength
        elif password_strength['score'] < 3:
            flash("Password to weak:", password_strength['feedback']['suggestions'], 'error')
        else:
            hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            users.update_one({'reset_token': token}, {'$set': {'password': hashed_new_password, 'last_password_change': datetime.datetime.now()}, '$unset': {'reset_token': None, 'token_expiry': None}})
            flash('Password reset successful. You can now log in with your new password.', 'success')
            return redirect(url_for('login'))
    return render_template("reset-password.html")

@app.route("/set-up-two-factor-auth", methods=['GET', 'POST'])
def set_up_two_factor_auth():
    if not session.get('username'):
        return redirect("/login")
    # Check if the user has verified their email
    elif not users.find_one({'username': session['username']}).get('is_verified'):
        flash('Please verify your email before accessing your account.', 'error')
        return redirect(url_for('verify-email'))
    
    if request.method == 'POST':
        user = users.find_one({'username': session['username']})

        # Check if the user has two-factor authentication enabled
        if user.get('2fa_secret'):
            secret = user['2fa_secret']
            totp = pyotp.TOTP(secret)
            link = totp.provisioning_uri(name=session['username'], issuer_name="CM3148Prototype")
            flash('Two-factor authentication is already set up. Please use the existing key.', 'info')
            return render_template("two-factor-auth.html", link=link, key=secret)
        # If two-factor authentication is not enabled, generate a new key
        else:
            secret = pyotp.random_base32()
            users.update_one({'username': session['username']}, {'$set': {'2fa_secret': secret}})
            totp = pyotp.TOTP(secret)
            link = totp.provisioning_uri(name=session['username'], issuer_name="CM3148Prototype")
            return render_template("two-factor-auth.html", link=link, key=secret)
    return render_template("two-factor-auth.html")

@app.route("/verify-two-factor-auth", methods=['GET', 'POST'])
def verify_two_factor_auth():
    if not session.get('temp_username'):
        return redirect("/login")
    
    if request.method == 'POST':
        temp_username = session['temp_username']
        user = users.find_one({'username': temp_username})
        if user:
            totp = pyotp.TOTP(user['2fa_secret'])
            token = request.form['totp']
            if totp.verify(token):
                session['username'] = temp_username
                session['temp_username'] = None
                session.permanent = True
                flash('Login successful.', 'success')
                return redirect('/')
            else:
                flash('Invalid token. Please try again.', 'error')
        else:
            flash('User not found.', 'error')
    return render_template("verify-two-factor-auth.html")

@app.route("/disable-two-factor-auth", methods=['POST'])
def disable_two_factor_auth():
    if not session.get('username'):
        return redirect("/login")
    
    if request.method == 'POST':
        user = users.find_one({'username': session['username']})
        password = request.form['password']
        hashed_password = user['password']
        is_valid = bcrypt.check_password_hash(hashed_password, password)

        if is_valid:
            users.update_one({'username': session['username']}, {'$unset': {'2fa_secret': None}})
            flash('Two-factor authentication disabled successfully.', 'success')
            return redirect('/account')
        else:
            flash('Invalid password. Please try again.', 'error')
    return render_template("account.html")

def send_email(email, subject, body):
    msg = Message(
        subject,
        sender= 'admin@cm3148.com',
        recipients=[email],
        body=body
    )
    mail.send(msg)
    return "Email sent successfully."

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)