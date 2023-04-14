from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from string import ascii_uppercase
from flask_sqlalchemy import SQLAlchemy
from werkzeug.urls import url_parse
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, logout_user, LoginManager
from wtforms import StringField, SubmitField, EmailField, PasswordField
from wtforms.validators import DataRequired, EqualTo
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_bcrypt import Bcrypt 
from sqlalchemy import update
from decouple import config
import random

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = config('SECRET_KEY')
socketio = SocketIO(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///my_database.db'

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'nuutti.project@gmail.com'
app.config['MAIL_PASSWORD'] = config('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'nuutti.project@gmail.com'
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_ASCII_ATTACHMENTS'] = False

db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'

mail = Mail(app)

s = URLSafeTimedSerializer('ThisIsSecret')

@app.before_first_request
def create_tables():
    db.create_all()

@login.user_loader
def load_user(id):
  return User.query.get(int(id))

rooms = {}

def generate_unique_code(length):
    while True:
        code = ""
        for _ in range(length):
            code += random.choice(ascii_uppercase)
        
        if code not in rooms:
            break
    
    return code

class SignUp(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Signup')

class LogIn(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('Login')

class EmailField(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    submit = SubmitField('Reset')

class PasswordReset(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat password', validators=[DataRequired()])
    submit = SubmitField('Reset')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, index=True, unique=True)
    email = db.Column(db.String, index=True, unique=True)
    password_hash = db.Column(db.String, index=True, unique=True)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password_hash(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password_hash(self, password):
        return check_password_hash(self.password_hash, password)

class History(db.Model):

    __tablename__ = 'History'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    code = db.Column(db.String(20), index=True, unique=True)
    message = db.Column(db.String(500), index=False, unique=False)

    def __repr__(self):
        return '<Code {}'.format(self.code)


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LogIn(crsf_enabled=False)
    if form.validate_on_submit():
        print('validates')
        global name
        name = form.username.data
        user = User.query.filter_by(username=form.username.data).first()

        if user is None or not user.check_password_hash(form.password.data):
            flash('Invalid password or username')
            print('Invalid password or username')
            return redirect(url_for('signup'))
        login_user(user)
        next_page = request.args.get('next')

        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('chatlogin')
        return redirect(next_page)
    
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUp(crsf_enabled=False)

    if form.validate_on_submit():
        print('validates')
        user = User(username=form.username.data, email=form.email.data)
        user.set_password_hash(form.password.data)
        print(user)
        db.session.add(user)
        db.session.commit()
        print('You are registered!')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/reset', methods=['GET', 'POST'])
def reset():
    form = EmailField()
    if form.validate_on_submit():
        global emailValue
        emailValue = form.email.data
        token = s.dumps(emailValue, salt='password-reset')
        msg = Message('Password Reset', sender='nuutti.project@gmail.com', recipients=[emailValue])
        link = url_for('password_reset', token=token, _external=True)
        msg.body = 'Your link is {}'.format(link)
        mail.send(msg)
        flash('Link was sent successfully!')
        # return '<h1>The email you entered is {} and the token is {}</h1>'.format(emailValue, token)
    return render_template('reset.html', form=form)

@app.route('/password_reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except SignatureExpired:
        return '<h1>The token is expired</h1>'
    
    if request.method == 'POST':
        password = request.form.get("password")
        submit = request.form.get('submit', False)
        if submit != False:
            users = User.query.filter_by(email=emailValue).first()
            if users:
                new_password = generate_password_hash(password)
                print(new_password)
                User.query.filter_by(email=emailValue).update(dict(password_hash=new_password))
                db.session.commit()
                return redirect('/')
            else:
                print("Wrong email address")

    return render_template('password_reset.html', token=token)


@app.route('/chatlogin', methods=['GET', 'POST'])
def chatlogin():
    session.clear()
    logout = request.form.get('logout', False)
    exists = db.session.query(db.session.query(History).filter_by(code=request.form.get('code')).exists()).scalar()

    if logout != False:
        logout_user()
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = name
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get('create', False)

        if join != False and not exists:
            print("This room is not created yet!")
            return render_template('chatlogin.html')
        
        room = code
        if join != False and exists:
            rooms[room] = {"members": 0, "messages": []}

        if create != False and exists:
            print("This room already exists")
            return render_template('chatlogin.html')

        if create != False:
            room = request.form.get('code')
            roomCode = History(code=request.form.get("code"))
            db.session.add(roomCode)
            db.session.commit()
            rooms[room] = {"members": 0, "messages": []}
        
        specificRoom = request.form.get("code")

        session['username'] = username
        session['room'] = specificRoom
        return redirect(url_for("chat"))
    
    return render_template('chatlogin.html')

@app.route('/chat')
def chat():
    username = session.get('username')
    room = session.get("room")
    if room is None or session.get("username") is None:
        return redirect(url_for("chatlogin"))
    return render_template('chat.html', username=username, room=room)

@socketio.on('message')
def message(data):
    room = session.get('room')
    
    content = {
        "username": session.get("username"),
        "message": data['data']
    }
    send(content, to=room)
    rooms[room]["messages"].append(content)
    print(f"{session.get('name')} said: {data['data']}")

@socketio.on('connect')
def connect(auth):
    username = session.get('username')
    room = session.get('room')
    join_room(room)

    send({"username": username, "message": "has joined the room "}, to=room)
    rooms[room]["members"] += 1
    print(f"{username} joined room {room}")

@socketio.on('disconnect')
def disconnect():
    username = session.get('username')
    room = session.get('room')
    leave_room(room)
    send({"username": username, "message": "has left the room"}, to=room)
    print(f"{username} has left the room {room}")

if __name__ == '__main__':
    socketio.run(app)