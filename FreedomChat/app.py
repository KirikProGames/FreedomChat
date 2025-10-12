import os
import random
import string
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import json
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-super-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['VOICE_FOLDER'] = 'uploads/voice'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['VOICE_FOLDER'], exist_ok=True)
os.makedirs('static/avatars', exist_ok=True)

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Модели БД
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    online = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(100), default='default.png')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(100), default='')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    bio = db.Column(db.Text, default='')
    phone = db.Column(db.String(20))
    
    messages = db.relationship('Message', backref='author', lazy=True)
    chat_rooms = db.relationship('ChatRoom', secondary='user_chatroom', backref='members')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    is_private = db.Column(db.Boolean, default=False)
    is_channel = db.Column(db.Boolean, default=False)
    is_direct = db.Column(db.Boolean, default=False)
    code = db.Column(db.String(10), unique=True)
    invite_link = db.Column(db.String(20), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    theme = db.Column(db.String(20), default='light')
    
    created_by_user = db.relationship('User', backref='created_chats', foreign_keys=[created_by])
    messages = db.relationship('Message', backref='chat_room', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    chat_room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    message_type = db.Column(db.String(20), default='text')
    file_path = db.Column(db.String(200))
    file_name = db.Column(db.String(200))
    file_size = db.Column(db.Integer)
    duration = db.Column(db.Integer)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('message.id'))
    edited = db.Column(db.Boolean, default=False)
    
    reply_to = db.relationship('Message', remote_side=[id], backref='replies')

class Call(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    caller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    chat_room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'))
    call_type = db.Column(db.String(10), default='video')
    status = db.Column(db.String(20), default='calling')
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)

user_chatroom = db.Table('user_chatroom',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('chat_room_id', db.Integer, db.ForeignKey('chat_room.id'), primary_key=True)
)

# WebSocket события
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        current_user.online = True
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        emit('user_status', {
            'user_id': current_user.id,
            'online': True,
            'status': 'online'
        }, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.online = False
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        emit('user_status', {
            'user_id': current_user.id,
            'online': False,
            'status': 'offline'
        }, broadcast=True)

@socketio.on('join_room')
def handle_join_room(data):
    room = data['room']
    join_room(room)
    emit('user_joined', {
        'user': current_user.email,
        'message': f'{current_user.email} присоединился к чату'
    }, room=room)

@socketio.on('leave_room')
def handle_leave_room(data):
    room = data['room']
    leave_room(room)
    emit('user_left', {
        'user': current_user.email,
        'message': f'{current_user.email} покинул чат'
    }, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    try:
        room = data['room']
        content = data['message']
        message_type = data.get('type', 'text')
        file_path = data.get('file_path')
        file_name = data.get('file_name')
        file_size = data.get('file_size')
        duration = data.get('duration')
        
        new_message = Message(
            content=content,
            user_id=current_user.id,
            chat_room_id=room,
            message_type=message_type,
            file_path=file_path,
            file_name=file_name,
            file_size=file_size,
            duration=duration
        )
        
        db.session.add(new_message)
        db.session.commit()
        
        emit('new_message', {
            'id': new_message.id,
            'content': new_message.content,
            'user_id': current_user.id,
            'user_email': current_user.email,
            'user_avatar': current_user.avatar,
            'timestamp': new_message.timestamp.isoformat(),
            'type': message_type,
            'file_path': file_path,
            'file_name': file_name,
            'file_size': file_size,
            'duration': duration
        }, room=room)
        
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('typing')
def handle_typing(data):
    room = data['room']
    emit('user_typing', {
        'user': current_user.email,
        'typing': data['typing']
    }, room=room, include_self=False)

@socketio.on('voice_message')
def handle_voice_message(data):
    try:
        room = data['room']
        audio_data = data['audio_data']
        duration = data['duration']
        
        filename = f"voice_{current_user.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.webm"
        filepath = os.path.join(app.config['VOICE_FOLDER'], filename)
        
        audio_bytes = base64.b64decode(audio_data.split(',')[1])
        with open(filepath, 'wb') as f:
            f.write(audio_bytes)
        
        voice_message = Message(
            content="🎤 Голосовое сообщение",
            user_id=current_user.id,
            chat_room_id=room,
            message_type='voice',
            file_path=f'/uploads/voice/{filename}',
            duration=duration
        )
        db.session.add(voice_message)
        db.session.commit()
        
        emit('new_message', {
            'id': voice_message.id,
            'content': voice_message.content,
            'user_id': current_user.id,
            'user_email': current_user.email,
            'user_avatar': current_user.avatar,
            'timestamp': voice_message.timestamp.isoformat(),
            'type': 'voice',
            'file_path': f'/uploads/voice/{filename}',
            'duration': duration
        }, room=room)
        
    except Exception as e:
        emit('error', {'message': f'Voice error: {str(e)}'})

# Звонки
@socketio.on('start_call')
def handle_start_call(data):
    call_type = data.get('type', 'video')
    receiver_id = data.get('receiver_id')
    chat_room_id = data.get('chat_room_id')
    
    call = Call(
        caller_id=current_user.id,
        receiver_id=receiver_id,
        chat_room_id=chat_room_id,
        call_type=call_type
    )
    db.session.add(call)
    db.session.commit()
    
    emit('incoming_call', {
        'call_id': call.id,
        'caller_id': current_user.id,
        'caller_name': current_user.username or current_user.email,
        'call_type': call_type,
        'chat_room_id': chat_room_id
    }, room=receiver_id if receiver_id else f'chat_{chat_room_id}')

@socketio.on('answer_call')
def handle_answer_call(data):
    call_id = data['call_id']
    call = Call.query.get(call_id)
    
    if call:
        call.status = 'active'
        db.session.commit()
        
        call_room = f'call_{call_id}'
        emit('call_accepted', {
            'call_id': call_id,
            'call_room': call_room
        }, room=call.caller_id)

@socketio.on('reject_call')
def handle_reject_call(data):
    call_id = data['call_id']
    call = Call.query.get(call_id)
    
    if call:
        call.status = 'ended'
        call.ended_at = datetime.utcnow()
        db.session.commit()
        
        emit('call_rejected', {
            'call_id': call_id
        }, room=call.caller_id)

@socketio.on('end_call')
def handle_end_call(data):
    call_id = data['call_id']
    call = Call.query.get(call_id)
    
    if call:
        call.status = 'ended'
        call.ended_at = datetime.utcnow()
        db.session.commit()
        
        emit('call_ended', {
            'call_id': call_id
        }, room=f'call_{call_id}')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_code(length=6):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def generate_invite_link():
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))

# Инициализация БД
with app.app_context():
    db.drop_all()
    db.create_all()
    
    admin = User(
        email='admin@freedomchat.com',
        username='admin',
        is_admin=True
    )
    admin.set_password('Admin123!')
    db.session.add(admin)
    
    test_user = User(email='test@example.com', username='testuser')
    test_user.set_password('123456')
    db.session.add(test_user)
    
    db.session.commit()
    print("✅ База данных создана!")
    print("🔑 Админ: admin@freedomchat.com / Admin123!")
    print("👤 Тест: test@example.com / 123456")

# Маршруты
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            user.online = True
            db.session.commit()
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный email или пароль')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Пароли не совпадают')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует')
            return redirect(url_for('register'))
        
        user = User(email=email, username=username)
        user.set_password(password)
        user.avatar = random.choice(['avatar1.png', 'avatar2.png', 'avatar3.png', 'avatar4.png'])
        
        db.session.add(user)
        db.session.commit()
        
        flash('Регистрация прошла успешно')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_chat_rooms = current_user.chat_rooms
    return render_template('dashboard.html', chat_rooms=user_chat_rooms)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        username = request.form.get('username')
        status = request.form.get('status')
        bio = request.form.get('bio')
        phone = request.form.get('phone')
        
        if username and username != current_user.username:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user and existing_user.id != current_user.id:
                flash('Этот username уже занят')
            else:
                current_user.username = username
        
        current_user.status = status
        current_user.bio = bio
        current_user.phone = phone
        
        if 'avatar' in request.files:
            avatar_file = request.files['avatar']
            if avatar_file.filename:
                filename = f"avatar_{current_user.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.png"
                filepath = os.path.join('static/avatars', filename)
                avatar_file.save(filepath)
                current_user.avatar = filename
        
        db.session.commit()
        flash('Профиль обновлен!')
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

@app.route('/create_chat', methods=['POST'])
@login_required
def create_chat():
    chat_name = request.form.get('chat_name')
    chat_type = request.form.get('chat_type', 'group')
    is_private = request.form.get('is_private') == 'on'
    
    is_channel = chat_type == 'channel'
    is_direct = chat_type == 'direct'
    
    code = None
    invite_link = None
    
    if is_private:
        code = generate_code()
        while ChatRoom.query.filter_by(code=code).first():
            code = generate_code()
    
    if chat_type in ['channel', 'private_channel']:
        invite_link = generate_invite_link()
        while ChatRoom.query.filter_by(invite_link=invite_link).first():
            invite_link = generate_invite_link()
    
    new_chat = ChatRoom(
        name=chat_name,
        is_private=is_private,
        is_channel=is_channel,
        is_direct=is_direct,
        code=code,
        invite_link=invite_link,
        created_by=current_user.id
    )
    
    new_chat.members.append(current_user)
    db.session.add(new_chat)
    db.session.commit()
    
    flash('Чат создан успешно!')
    return redirect(url_for('dashboard'))

@app.route('/join_chat', methods=['POST'])
@login_required
def join_chat():
    code = request.form.get('code')
    chat_room = ChatRoom.query.filter_by(code=code).first()
    
    if chat_room:
        if current_user not in chat_room.members:
            chat_room.members.append(current_user)
            db.session.commit()
            flash('Вы присоединились к чату!')
        else:
            flash('Вы уже в этом чате')
    else:
        flash('Чат с таким кодом не найден')
    
    return redirect(url_for('dashboard'))

@app.route('/chat/<int:chat_id>')
@login_required
def chat(chat_id):
    chat_room = ChatRoom.query.get_or_404(chat_id)
    
    if current_user not in chat_room.members:
        flash('У вас нет доступа к этому чату')
        return redirect(url_for('dashboard'))
    
    messages = Message.query.filter_by(chat_room_id=chat_id)\
        .order_by(Message.timestamp.asc())\
        .limit(100).all()
    
    return render_template('chat.html', chat_room=chat_room, messages=messages)

@app.route('/call/<int:chat_id>')
@login_required
def video_call(chat_id):
    chat_room = ChatRoom.query.get_or_404(chat_id)
    return render_template('call.html', chat_room=chat_room)

@app.route('/uploads/voice/<filename>')
def serve_voice(filename):
    return send_file(os.path.join(app.config['VOICE_FOLDER'], filename))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        file_size = os.path.getsize(file_path)
        
        return jsonify({
            'success': True,
            'file_path': f'/uploads/{filename}',
            'file_name': filename,
            'file_size': file_size
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Доступ запрещен')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    chats = ChatRoom.query.all()
    return render_template('admin.html', users=users, chats=chats)

@app.route('/logout')
@login_required
def logout():
    current_user.online = False
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

# Обработка всех остальных маршрутов
@app.route('/<path:path>')
def catch_all(path):
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)