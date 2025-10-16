import os
import random
import string
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
from flask_migrate import Migrate
import json
import base64
import requests
from dotenv import load_dotenv
import mimetypes
import traceback

# Загружаем переменные из .env файла
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'delta-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///delta.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['VOICE_FOLDER'] = 'uploads/voice'
app.config['IMAGES_FOLDER'] = 'uploads/images'
app.config['DOCUMENTS_FOLDER'] = 'uploads/documents'
app.config['OTHER_FOLDER'] = 'uploads/other'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['JSON_AS_ASCII'] = False

# Создаем папки если их нет
for folder in [app.config['UPLOAD_FOLDER'], app.config['VOICE_FOLDER'], 
               app.config['IMAGES_FOLDER'], app.config['DOCUMENTS_FOLDER'],
               app.config['OTHER_FOLDER'], 'static/avatars', 'static/chat_avatars']:
    os.makedirs(folder, exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Конфигурация цен
CURRENCY_RATES = {
    100: 100,
    200: 200,  
    500: 500,
    900: 900,
    1000: 1000,
    10000: 10000
}

PREMIUM_PRICES = {
    1: 120,
    3: 300,
    6: 540,  
    12: 960
}

# Модели БД (упрощенные для начала)
class UserChatRoom(db.Model):
    __tablename__ = 'user_chatroom'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    chat_room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), primary_key=True)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)
    online = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(100), default='default.png')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    display_name = db.Column(db.String(50))
    
    # Премиум система
    premium_expires = db.Column(db.DateTime)
    currency = db.Column(db.Integer, default=0)
    is_premium = db.Column(db.Boolean, default=False)
    
    messages = db.relationship('Message', backref='author', lazy=True)
    chat_rooms = db.relationship('ChatRoom', secondary='user_chatroom', backref='members')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)
    
    def get_display_name(self):
        return self.display_name or self.username or f"User{self.id:04d}"
    
    def check_premium(self):
        if self.premium_expires and self.premium_expires > datetime.utcnow():
            self.is_premium = True
        else:
            self.is_premium = False
        return self.is_premium

class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    is_private = db.Column(db.Boolean, default=False)
    is_channel = db.Column(db.Boolean, default=False)
    is_direct = db.Column(db.Boolean, default=False)
    code = db.Column(db.String(10), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    messages = db.relationship('Message', backref='chat_room', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    chat_room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    message_type = db.Column(db.String(20), default='text')

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Float)
    currency_amount = db.Column(db.Integer)
    payment_method = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_code(length=6):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

# Базовые маршруты
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
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()
            
            if user and user.check_password(password):
                user.online = True
                user.last_seen = datetime.utcnow()
                user.check_premium()
                db.session.commit()
                login_user(user, remember=True)
                return redirect(url_for('dashboard'))
            else:
                flash('Неверные учетные данные')
        except Exception as e:
            flash('Ошибка входа')
            print(f"Login error: {str(e)}")
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            username = request.form.get('username')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            if not email or not password:
                flash('Заполните все поля')
                return redirect(url_for('register'))
                
            if password != confirm_password:
                flash('Пароли не совпадают')
                return redirect(url_for('register'))
            
            if User.query.filter_by(email=email).first():
                flash('Этот email уже используется')
                return redirect(url_for('register'))
            
            if not username:
                username = f"user_{random.randint(1000,9999)}"
            
            user = User(email=email, username=username, display_name=username)
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            flash('Аккаунт создан! Добро пожаловать в DELTA.')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash('Ошибка регистрации')
            print(f"Register error: {str(e)}")
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        user_chat_rooms = current_user.chat_rooms
        current_user.check_premium()
        return render_template('dashboard.html', chat_rooms=user_chat_rooms)
    except Exception as e:
        flash('Ошибка загрузки дашборда')
        print(f"Dashboard error: {str(e)}")
        return render_template('dashboard.html', chat_rooms=[])

@app.route('/premium')
@login_required
def premium():
    try:
        current_user.check_premium()
        return render_template('premium.html', 
                             premium_prices=PREMIUM_PRICES,
                             currency_rates=CURRENCY_RATES,
                             user_premium=current_user.is_premium,
                             premium_expires=current_user.premium_expires)
    except Exception as e:
        flash('Ошибка загрузки страницы премиума')
        print(f"Premium error: {str(e)}")
        return render_template('premium.html', 
                             premium_prices=PREMIUM_PRICES,
                             currency_rates=CURRENCY_RATES,
                             user_premium=False,
                             premium_expires=None)

@app.route('/create_chat', methods=['POST'])
@login_required
def create_chat():
    try:
        chat_name = request.form.get('chat_name')
        if not chat_name:
            flash('Введите название чата')
            return redirect(url_for('dashboard'))
        
        new_chat = ChatRoom(
            name=chat_name,
            created_by=current_user.id
        )
        
        db.session.add(new_chat)
        db.session.flush()
        
        owner_association = UserChatRoom(
            user_id=current_user.id,
            chat_room_id=new_chat.id,
            role='owner'
        )
        db.session.add(owner_association)
        db.session.commit()
        
        flash('Чат создан!')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash('Ошибка создания чата')
        print(f"Create chat error: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/chat/<int:chat_id>')
@login_required
def chat(chat_id):
    try:
        chat_room = ChatRoom.query.get_or_404(chat_id)
        
        # Проверяем доступ
        if current_user not in chat_room.members:
            flash('Доступ запрещен')
            return redirect(url_for('dashboard'))
        
        messages = Message.query.filter_by(chat_room_id=chat_id)\
            .order_by(Message.timestamp.asc())\
            .limit(100).all()
        
        return render_template('chat.html', 
                             chat_room=chat_room, 
                             messages=messages,
                             can_send_messages=True)
                             
    except Exception as e:
        flash('Ошибка загрузки чата')
        print(f"Chat error: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/search_users')
@login_required
def search_users():
    try:
        query = request.args.get('q', '')
        if query:
            users = User.query.filter(
                (User.username.ilike(f'%{query}%')) | 
                (User.display_name.ilike(f'%{query}%'))
            ).filter(User.id != current_user.id).limit(20).all()
            return jsonify([{
                'id': user.id,
                'username': user.get_display_name(),
                'online': user.online
            } for user in users])
        return jsonify([])
    except Exception as e:
        print(f"Search error: {str(e)}")
        return jsonify([])

# WebSocket события
@socketio.on('connect')
def handle_connect():
    try:
        if current_user.is_authenticated:
            current_user.online = True
            current_user.last_seen = datetime.utcnow()
            db.session.commit()
    except Exception as e:
        print(f"Connect error: {str(e)}")

@socketio.on('disconnect')
def handle_disconnect():
    try:
        if current_user.is_authenticated:
            current_user.online = False
            current_user.last_seen = datetime.utcnow()
            db.session.commit()
    except Exception as e:
        print(f"Disconnect error: {str(e)}")

@socketio.on('join_room')
def handle_join_room(data):
    try:
        room = data['room']
        join_room(room)
    except Exception as e:
        print(f"Join room error: {str(e)}")

@socketio.on('send_message')
def handle_send_message(data):
    try:
        room = data['room']
        content = data.get('message', '').strip()
        
        if not content:
            return
            
        chat_room = ChatRoom.query.get(room)
        if not chat_room:
            return
        
        # Проверяем доступ
        if current_user not in chat_room.members:
            return
        
        new_message = Message(
            content=content,
            user_id=current_user.id,
            chat_room_id=room
        )
        
        db.session.add(new_message)
        db.session.commit()
        
        emit('new_message', {
            'id': new_message.id,
            'content': new_message.content,
            'user_id': current_user.id,
            'user_name': current_user.get_display_name(),
            'timestamp': new_message.timestamp.isoformat(),
            'is_premium': current_user.is_premium
        }, room=room)
        
    except Exception as e:
        print(f"Send message error: {str(e)}")

@app.route('/logout')
@login_required
def logout():
    try:
        current_user.online = False
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        logout_user()
    except Exception as e:
        print(f"Logout error: {str(e)}")
    finally:
        return redirect(url_for('login'))

# Обработчик ошибок
@app.errorhandler(500)
def internal_error(error):
    print(f"500 Error: {str(error)}")
    print(traceback.format_exc())
    flash('Внутренняя ошибка сервера')
    return redirect(url_for('dashboard'))

@app.errorhandler(404)
def not_found_error(error):
    return redirect(url_for('dashboard'))

# Инициализация БД
with app.app_context():
    try:
        db.create_all()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Database error: {str(e)}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    print(f"🚀 DELTA Messenger starting on port {port} (debug: {debug})")
    socketio.run(app, host='0.0.0.0', port=port, debug=debug, allow_unsafe_werkzeug=True)
