import os

from dotenv import load_dotenv
from flask import Flask, jsonify, request, url_for
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer

from forms import LoginForm, RegistrationForm
from models import db, User

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
mail = Mail(app)
jwt = JWTManager(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
limiter = Limiter(app=app, key_func=get_remote_address)


@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.json
    form = RegistrationForm(data=data, csrf_enabled=False)

    if not form.validate():
        return jsonify(errors=form.errors), 400

    email = request.json.get('email')
    username = request.json.get('username')
    password = request.json.get('password')

    existing_user_email = User.query.filter_by(email=email).first()
    existing_user_username = User.query.filter_by(username=username).first()
    if existing_user_email or existing_user_username:
        return jsonify(message="Email or username already exists."), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, username=username, password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()

    token = s.dumps(email, salt='email-confirm')
    link = url_for('confirm_email', token=token, _external=True)
    msg = Message('Confirm Email', sender='noreply@example.com', recipients=[email])
    msg.body = f'Please click the link to confirm your email: {link}'
    print("token", token)
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")
    access_token = create_access_token(identity=new_user.id)
    return jsonify(message="Success! Please check your email to confirm your account.", access_token=access_token), 201


@app.route('/confirm/<token>', methods=['GET'])
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except Exception as e:
        return jsonify(message=f"The confirmation link is invalid or has expired. {e}"), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify(message="User not found."), 404

    if user.confirmed:
        return jsonify(message="Account already confirmed."), 400

    user.confirmed = True
    db.session.commit()

    return jsonify(message="Account confirmed!"), 200


@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.json
    form = LoginForm(data=data, csrf_enabled=False)

    if not form.validate():
        return jsonify(errors=form.errors), 400

    email_or_username = request.json.get('email_or_username')
    password = request.json.get('password')

    user = User.query.filter((User.email == email_or_username) | (User.username == email_or_username)).first()
    if not user:
        return jsonify(message="User not found."), 404

    if not user.confirmed:
        return jsonify(message="Please confirm your email before logging in."), 400

    if bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200

    return jsonify(message="Invalid login credentials."), 401


@app.route('/reset_password_request', methods=['POST'])
@limiter.limit("5 per minute")
def reset_password_request():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify(message="Email not found."), 404

    token = s.dumps(email, salt='recover-key')
    link = url_for('reset_password', token=token, _external=True)
    msg = Message('Password Reset Request', sender='noreply@example.com', recipients=[email])
    msg.body = f'Please click the link to reset your password: {link}'
    mail.send(msg)
    print("token", token)

    return jsonify(message="Email sent for password reset."), 200


@app.route('/reset_password', methods=['POST'])
@limiter.limit("5 per minute")
def reset_password(token):
    try:
        email = s.loads(token, salt='recover-key', max_age=3600)
    except Exception as e:
        return jsonify(message=f"The reset link is invalid or has expired.{e}"), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify(message="User not found."), 404

    new_password = request.json.get('password')
    hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_pw
    db.session.commit()

    return jsonify(message="Password reset successful!"), 200


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run()
