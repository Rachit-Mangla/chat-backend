from flask import Flask, render_template, request, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ================== Models ==================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class PrivateMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ================ Routes =================

@app.route('/')
@login_required
def home():
    return render_template('index.html', current_user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        user = User.query.filter_by(username=data['username']).first()
        if user and user.password == data['password']:
            login_user(user)
            return redirect('/')
        return 'Invalid Credentials'
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.form
        if User.query.filter_by(username=data['username']).first():
            return 'Username already exists'
        user = User(username=data['username'], password=data['password'])
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/messages')
@login_required
def get_messages():
    messages = Message.query.order_by(Message.timestamp.desc()).limit(50).all()
    messages.reverse()
    return jsonify([
        {'username': m.username, 'content': m.content, 'timestamp': m.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
        for m in messages
    ])

@app.route('/dm/<username>')
@login_required
def direct_message(username):
    receiver = User.query.filter_by(username=username).first_or_404()
    messages = PrivateMessage.query.filter(
        ((PrivateMessage.sender_id == current_user.id) & (PrivateMessage.receiver_id == receiver.id)) |
        ((PrivateMessage.sender_id == receiver.id) & (PrivateMessage.receiver_id == current_user.id))
    ).order_by(PrivateMessage.timestamp.asc()).all()
    return render_template('dm.html', receiver=receiver, messages=messages, current_user=current_user)

@app.route('/inbox')
@login_required
def inbox():
    user_id = current_user.id

    # Fetch all usernames you've ever DMed or received from
    sent = db.session.query(User.username).join(PrivateMessage, PrivateMessage.receiver_id == User.id)\
        .filter(PrivateMessage.sender_id == user_id)

    received = db.session.query(User.username).join(PrivateMessage, PrivateMessage.sender_id == User.id)\
        .filter(PrivateMessage.receiver_id == user_id)

    all_conversations = set([r[0] for r in sent.union(received).all()])
    
    return render_template('inbox.html', conversations=all_conversations, current_user=current_user)


# ================ SocketIO ================

online_users = {}
typing_users = {}

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        online_users[current_user.username] = request.sid
        emit('user_list', list(online_users.keys()), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    for username, sid in list(online_users.items()):
        if sid == request.sid:
            del online_users[username]
            break
    emit('user_list', list(online_users.keys()), broadcast=True)

@socketio.on('message')
def handle_message(data):
    if not current_user.is_authenticated:
        return
    msg = Message(username=current_user.username, content=data)
    db.session.add(msg)
    db.session.commit()
    emit('chat message', {'username': current_user.username, 'message': data}, broadcast=True)

@socketio.on('typing')
def handle_typing(data):
    emit('typing', {'username': current_user.username}, broadcast=True, include_self=False)

@socketio.on('private_message')
def handle_private_message(data):
    sender = current_user.username
    receiver = data['receiver']
    content = data['message']

    sender_obj = User.query.filter_by(username=sender).first()
    receiver_obj = User.query.filter_by(username=receiver).first()
    pm = PrivateMessage(sender_id=sender_obj.id, receiver_id=receiver_obj.id, content=content)
    db.session.add(pm)
    db.session.commit()

    receiver_sid = online_users.get(receiver)
    if receiver_sid:
        emit('dm', {'sender': sender, 'message': content}, to=receiver_sid)

@socketio.on('dm_typing')
def handle_dm_typing(data):
    receiver = data['receiver']
    receiver_sid = online_users.get(receiver)
    if receiver_sid:
        emit('dm_typing', {'sender': current_user.username}, to=receiver_sid)

# ================ Main ================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000)
