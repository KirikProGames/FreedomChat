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

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'delta-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///delta.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['VOICE_FOLDER'] = 'uploads/voice'
app.config['CHAT_AVATARS_FOLDER'] = 'static/chat_avatars'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['JSON_AS_ASCII'] = False

# Создаем папки если их нет
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['VOICE_FOLDER'], exist_ok=True)
os.makedirs(app.config['CHAT_AVATARS_FOLDER'], exist_ok=True)
os.makedirs('static/avatars', exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Конфигурация цен
CURRENCY_RATES = {
    100: 100,    # 102 рубля = 100 DELTA Coins
    200: 200,    # 159 рублей = 200 DELTA Coins  
    500: 500,    # 549 рублей = 500 DELTA Coins
    900: 900,    # 981 рубль = 900 DELTA Coins
    1000: 1000,  # 1100 рублей = 1000 DELTA Coins
    10000: 10000 # 10010 рублей = 10000 DELTA Coins
}

PREMIUM_PRICES = {
    1: 120,    # 1 месяц - 120 Coins
    3: 300,    # 3 месяца - 300 Coins (экономия 60)
    6: 540,    # 6 месяцев - 540 Coins (экономия 180)  
    12: 960    # 12 месяцев - 960 Coins (экономия 480)
}

# Настройки ЮMoney
YOOMONEY_CLIENT_ID = os.environ.get('YOOMONEY_CLIENT_ID', 'your_client_id')
YOOMONEY_CLIENT_SECRET = os.environ.get('YOOMONEY_CLIENT_SECRET', 'your_client_secret')
YOOMONEY_ACCESS_TOKEN = os.environ.get('YOOMONEY_ACCESS_TOKEN', 'your_access_token')
YOOMONEY_RECEIVER = os.environ.get('YOOMONEY_RECEIVER', '410011XXXXXXXXXX')  # Ваш кошелек ЮMoney

class UserChatRoom(db.Model):
    __tablename__ = 'user_chatroom'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    chat_room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), primary_key=True)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='chat_associations')
    chat_room = db.relationship('ChatRoom', backref='user_associations')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)
    online = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(100), default='default.png')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    display_name = db.Column(db.String(50))
    is_anonymous = db.Column(db.Boolean, default=True)
    
    # Премиум система
    premium_expires = db.Column(db.DateTime)
    balance = db.Column(db.Float, default=0.0)
    currency = db.Column(db.Integer, default=0)
    is_premium = db.Column(db.Boolean, default=False)
    premium_features = db.Column(db.Text, default='{}')  # JSON с активными фичами
    
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
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.get_display_name(),
            'email': self.email if not self.is_anonymous else 'anonymous@delta.chat',
            'avatar': self.avatar,
            'online': self.online,
            'is_anonymous': self.is_anonymous,
            'is_premium': self.is_premium
        }
    
    def get_role_in_chat(self, chat_room_id):
        association = UserChatRoom.query.filter_by(
            user_id=self.id, 
            chat_room_id=chat_room_id
        ).first()
        return association.role if association else None
    
    def check_premium(self):
        if self.premium_expires and self.premium_expires > datetime.utcnow():
            self.is_premium = True
        else:
            self.is_premium = False
        return self.is_premium
    
    def get_premium_features(self):
        return json.loads(self.premium_features) if self.premium_features else {}
    
    def has_premium_feature(self, feature):
        features = self.get_premium_features()
        return features.get(feature, False)

class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    avatar = db.Column(db.String(100), default='default_chat.png')
    is_private = db.Column(db.Boolean, default=False)
    is_channel = db.Column(db.Boolean, default=False)
    is_direct = db.Column(db.Boolean, default=False)
    code = db.Column(db.String(10), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    theme = db.Column(db.String(20), default='dark')
    settings = db.Column(db.Text, default='{}')
    is_encrypted = db.Column(db.Boolean, default=False)
    
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    created_by_user = db.relationship('User', backref='created_chats', foreign_keys=[created_by])
    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])
    messages = db.relationship('Message', backref='chat_room', lazy=True)

    def get_settings(self):
        return json.loads(self.settings) if self.settings else {}
    
    def set_settings(self, settings_dict):
        self.settings = json.dumps(settings_dict)
    
    def can_user_send_messages(self, user_id):
        if self.is_direct:
            return True
        
        user_role = UserChatRoom.query.filter_by(
            user_id=user_id, 
            chat_room_id=self.id
        ).first()
        
        if not user_role:
            return False
            
        settings = self.get_settings()
        
        if self.is_channel:
            return user_role.role in ['owner', 'admin']
        
        if settings.get('only_admins_can_post', False):
            return user_role.role in ['owner', 'admin']
        
        return True

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
    is_encrypted = db.Column(db.Boolean, default=False)
    encryption_key = db.Column(db.String(500))
    
    reply_to = db.relationship('Message', remote_side=[id], backref='replies')

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Float)
    currency_amount = db.Column(db.Integer)
    payment_method = db.Column(db.String(50))
    payment_id = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='transactions')

class PremiumPurchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    months = db.Column(db.Integer)
    currency_cost = db.Column(db.Integer)
    purchased_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='premium_purchases')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_code(length=6):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def generate_anonymous_name():
    adjectives = ['Hidden', 'Secret', 'Shadow', 'Dark', 'Mysterious', 'Silent', 'Ghost', 'Stealth']
    nouns = ['Wolf', 'Fox', 'Raven', 'Phantom', 'Stranger', 'Visitor', 'Watcher', 'Wanderer']
    return f"{random.choice(adjectives)}_{random.choice(nouns)}_{random.randint(1000,9999)}"

# Функции для премиум возможностей
def get_max_file_size(user):
    return 2 * 1024 * 1024 * 1024 if user.is_premium else 50 * 1024 * 1024  # 2GB vs 50MB

def can_use_advanced_features(user):
    return user.is_premium

def get_message_history_limit(user):
    return float('inf') if user.is_premium else 1000  # Бесконечная история vs 1000 сообщений

def can_create_large_groups(user):
    return user.is_premium  # Премиум пользователи могут создавать большие группы

# ЮMoney API функции
def create_yoomoney_payment(amount, description, user_id):
    try:
        # Создаем запрос на оплату через ЮMoney
        payment_data = {
            'pattern_id': 'p2p',
            'to': YOOMONEY_RECEIVER,
            'amount_due': amount,
            'comment': description,
            'message': f'DELTA Coins для пользователя {user_id}',
            'label': f'delta_{user_id}_{int(datetime.utcnow().timestamp())}',
            'test': True if os.environ.get('FLASK_DEBUG') == 'True' else False
        }
        
        headers = {
            'Authorization': f'Bearer {YOOMONEY_ACCESS_TOKEN}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        response = requests.post(
            'https://yoomoney.ru/api/request-payment',
            data=payment_data,
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                'success': True,
                'payment_url': data.get('payment_url'),
                'payment_id': data.get('request_id')
            }
        else:
            return {
                'success': False,
                'error': 'Ошибка создания платежа'
            }
            
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def process_yoomoney_payment(payment_id):
    try:
        headers = {
            'Authorization': f'Bearer {YOOMONEY_ACCESS_TOKEN}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        response = requests.post(
            'https://yoomoney.ru/api/process-payment',
            data={'request_id': payment_id},
            headers=headers
        )
        
        return response.status_code == 200
        
    except Exception as e:
        return False

# Основные маршруты
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
            user.last_seen = datetime.utcnow()
            user.check_premium()  # Проверяем статус премиума
            db.session.commit()
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
        else:
            flash('Неверные учетные данные')
    
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
        stay_anonymous = request.form.get('stay_anonymous') == 'on'
        
        if password != confirm_password:
            flash('Пароли не совпадают')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Этот email уже используется')
            return redirect(url_for('register'))
        
        if stay_anonymous or not username:
            username = generate_anonymous_name()
        
        user = User(
            email=email, 
            username=username,
            display_name=username,
            is_anonymous=stay_anonymous
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Аккаунт создан! Добро пожаловать в DELTA.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_chat_rooms = current_user.chat_rooms
    current_user.check_premium()  # Обновляем статус премиума
    return render_template('dashboard.html', chat_rooms=user_chat_rooms)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        display_name = request.form.get('display_name')
        current_user.display_name = display_name
        
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

@app.route('/premium')
@login_required
def premium():
    current_user.check_premium()
    return render_template('premium.html', 
                         premium_prices=PREMIUM_PRICES,
                         currency_rates=CURRENCY_RATES,
                         user_premium=current_user.is_premium,
                         premium_expires=current_user.premium_expires)

@app.route('/buy_currency', methods=['POST'])
@login_required
def buy_currency():
    amount_rub = int(request.form.get('amount'))
    payment_method = request.form.get('payment_method', 'yoomoney')
    
    if amount_rub not in CURRENCY_RATES:
        flash('Неверная сумма пополнения')
        return redirect(url_for('premium'))
    
    currency_amount = CURRENCY_RATES[amount_rub]
    
    # Создаем транзакцию
    transaction = Transaction(
        user_id=current_user.id,
        amount=amount_rub,
        currency_amount=currency_amount,
        payment_method=payment_method,
        status='pending'
    )
    db.session.add(transaction)
    db.session.flush()
    
    # Создаем платеж в ЮMoney
    if payment_method == 'yoomoney':
        payment_result = create_yoomoney_payment(
            amount_rub,
            f'Пополнение DELTA Coins: {currency_amount}',
            current_user.id
        )
        
        if payment_result['success']:
            transaction.payment_id = payment_result['payment_id']
            db.session.commit()
            # Перенаправляем на страницу оплаты ЮMoney
            return redirect(payment_result['payment_url'])
        else:
            flash('Ошибка создания платежа')
            return redirect(url_for('premium'))
    
    # Для других методов оплаты (заглушка)
    elif payment_method in ['card', 'crypto']:
        transaction.status = 'completed'
        current_user.currency += currency_amount
        db.session.commit()
        flash(f'Баланс пополнен на {currency_amount} DELTA Coins!')
        return redirect(url_for('premium'))
    
    db.session.commit()
    return redirect(url_for('premium'))

@app.route('/payment_callback')
@login_required
def payment_callback():
    payment_id = request.args.get('payment_id')
    status = request.args.get('status')
    
    transaction = Transaction.query.filter_by(payment_id=payment_id, user_id=current_user.id).first()
    
    if transaction and status == 'success':
        transaction.status = 'completed'
        current_user.currency += transaction.currency_amount
        db.session.commit()
        flash('Оплата прошла успешно! Баланс пополнен.')
    else:
        flash('Ошибка оплаты. Попробуйте еще раз.')
    
    return redirect(url_for('premium'))

@app.route('/purchase_premium', methods=['POST'])
@login_required
def purchase_premium():
    months = int(request.form.get('months'))
    
    if months not in PREMIUM_PRICES:
        flash('Неверный период подписки')
        return redirect(url_for('premium'))
    
    cost = PREMIUM_PRICES[months]
    
    if current_user.currency < cost:
        flash('Недостаточно DELTA Coins')
        return redirect(url_for('premium'))
    
    # Списываем валюту
    current_user.currency -= cost
    
    # Активируем премиум
    if current_user.premium_expires and current_user.premium_expires > datetime.utcnow():
        new_expires = current_user.premium_expires + timedelta(days=30*months)
    else:
        new_expires = datetime.utcnow() + timedelta(days=30*months)
    
    current_user.premium_expires = new_expires
    current_user.is_premium = True
    
    # Активируем все премиум функции
    premium_features = {
        'large_files': True,
        'advanced_chat': True,
        'unlimited_history': True,
        'premium_stickers': True,
        'custom_themes': True,
        'priority_support': True,
        'large_groups': True,
        'advanced_privacy': True
    }
    current_user.premium_features = json.dumps(premium_features)
    
    # Записываем покупку
    purchase = PremiumPurchase(
        user_id=current_user.id,
        months=months,
        currency_cost=cost
    )
    db.session.add(purchase)
    db.session.commit()
    
    flash(f'DELTA Premium активирован на {months} месяцев!')
    return redirect(url_for('premium'))

@app.route('/create_chat', methods=['POST'])
@login_required
def create_chat():
    chat_name = request.form.get('chat_name')
    chat_type = request.form.get('chat_type', 'group')
    is_private = request.form.get('is_private') == 'on'
    is_encrypted = request.form.get('is_encrypted') == 'on'
    
    # Проверяем лимиты для обычных пользователей
    if chat_type == 'group' and not current_user.is_premium:
        user_groups_count = ChatRoom.query.filter_by(created_by=current_user.id, is_channel=False).count()
        if user_groups_count >= 5:
            flash('Базовые пользователи могут создавать до 5 групп. Активируйте Premium!')
            return redirect(url_for('dashboard'))
    
    is_channel = chat_type == 'channel'
    is_direct = chat_type == 'direct'
    
    code = None
    if is_private:
        code = generate_code()
        while ChatRoom.query.filter_by(code=code).first():
            code = generate_code()
    
    new_chat = ChatRoom(
        name=chat_name,
        is_private=is_private,
        is_channel=is_channel,
        is_direct=is_direct,
        code=code,
        created_by=current_user.id,
        is_encrypted=is_encrypted
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

@app.route('/join_chat', methods=['POST'])
@login_required
def join_chat():
    code = request.form.get('code')
    chat_room = ChatRoom.query.filter_by(code=code).first()
    
    if chat_room:
        if current_user not in chat_room.members:
            new_member = UserChatRoom(
                user_id=current_user.id,
                chat_room_id=chat_room.id,
                role='member'
            )
            db.session.add(new_member)
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
        flash('Доступ запрещен')
        return redirect(url_for('dashboard'))
    
    messages = Message.query.filter_by(chat_room_id=chat_id)\
        .order_by(Message.timestamp.asc())\
        .limit(get_message_history_limit(current_user)).all()
    
    user_role = current_user.get_role_in_chat(chat_id)
    can_send_messages = chat_room.can_user_send_messages(current_user.id)
    
    return render_template('chat.html', 
                         chat_room=chat_room, 
                         messages=messages,
                         user_role=user_role,
                         can_send_messages=can_send_messages)

@app.route('/search_users')
@login_required
def search_users():
    query = request.args.get('q', '')
    if query:
        users = User.query.filter(
            (User.username.ilike(f'%{query}%')) | 
            (User.display_name.ilike(f'%{query}%'))
        ).filter(User.id != current_user.id).limit(20).all()
        return jsonify([user.to_dict() for user in users])
    return jsonify([])

@app.route('/create_dm/<int:user_id>')
@login_required
def create_dm(user_id):
    target_user = User.query.get_or_404(user_id)
    
    existing_dm = ChatRoom.query.filter(
        ((ChatRoom.user1_id == current_user.id) & (ChatRoom.user2_id == user_id)) |
        ((ChatRoom.user1_id == user_id) & (ChatRoom.user2_id == current_user.id))
    ).first()
    
    if existing_dm:
        return redirect(url_for('chat', chat_id=existing_dm.id))
    
    dm = ChatRoom(
        name=f'{current_user.get_display_name()} & {target_user.get_display_name()}',
        is_direct=True,
        user1_id=current_user.id,
        user2_id=user_id
    )
    
    db.session.add(dm)
    db.session.flush()
    
    user1_assoc = UserChatRoom(user_id=current_user.id, chat_room_id=dm.id, role='member')
    user2_assoc = UserChatRoom(user_id=user_id, chat_room_id=dm.id, role='member')
    
    db.session.add(user1_assoc)
    db.session.add(user2_assoc)
    db.session.commit()
    
    return redirect(url_for('chat', chat_id=dm.id))

# WebSocket события
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        current_user.online = True
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        emit('user_status', {
            'user_id': current_user.id,
            'online': True
        }, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.online = False
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        emit('user_status', {
            'user_id': current_user.id,
            'online': False
        }, broadcast=True)

@socketio.on('join_room')
def handle_join_room(data):
    room = data['room']
    join_room(room)
    emit('user_joined', {
        'user': current_user.get_display_name(),
        'message': f'{current_user.get_display_name()} присоединился'
    }, room=room)

@socketio.on('leave_room')
def handle_leave_room(data):
    room = data['room']
    leave_room(room)
    emit('user_left', {
        'user': current_user.get_display_name(),
        'message': f'{current_user.get_display_name()} покинул чат'
    }, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    try:
        room = data['room']
        content = data['message']
        message_type = data.get('type', 'text')
        
        chat_room = ChatRoom.query.get(room)
        if not chat_room:
            emit('error', {'message': 'Чат не найден'})
            return
        
        if not chat_room.can_user_send_messages(current_user.id):
            emit('error', {'message': 'Нет прав для отправки'})
            return
        
        new_message = Message(
            content=content,
            user_id=current_user.id,
            chat_room_id=room,
            message_type=message_type,
            is_encrypted=chat_room.is_encrypted
        )
        
        db.session.add(new_message)
        db.session.commit()
        
        # Добавляем премиум бейдж к имени если есть премиум
        display_name = current_user.get_display_name()
        if current_user.is_premium:
            display_name = f"⭐ {display_name}"
        
        emit('new_message', {
            'id': new_message.id,
            'content': new_message.content,
            'user_id': current_user.id,
            'user_name': display_name,
            'user_avatar': current_user.avatar,
            'timestamp': new_message.timestamp.isoformat(),
            'type': message_type,
            'is_encrypted': chat_room.is_encrypted,
            'is_premium': current_user.is_premium
        }, room=room)
        
    except Exception as e:
        emit('error', {'message': f'Ошибка: {str(e)}'})

@socketio.on('typing')
def handle_typing(data):
    room = data['room']
    emit('user_typing', {
        'user': current_user.get_display_name(),
        'typing': data['typing']
    }, room=room, include_self=False)

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    try:
        # Проверяем размер файла
        file.seek(0, 2)  # Перемещаемся в конец файла
        file_size = file.tell()
        file.seek(0)  # Возвращаемся в начало
        
        max_size = get_max_file_size(current_user)
        if file_size > max_size:
            return jsonify({'error': f'Файл слишком большой. Максимум: {max_size//1024//1024}MB'}), 400
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        return jsonify({
            'success': True,
            'file_path': f'/uploads/{filename}',
            'file_name': filename,
            'file_size': file_size
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

@app.route('/logout')
@login_required
def logout():
    current_user.online = False
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

# Инициализация БД
with app.app_context():
    try:
        db.create_all()
        
        # Создаем тестовых пользователей
        if not User.query.filter_by(email='admin@delta.chat').first():
            admin = User(
                email='admin@delta.chat',
                username='DeltaAdmin',
                display_name='System',
                is_anonymous=False,
                is_admin=True,
                is_premium=True,
                premium_expires=datetime.utcnow() + timedelta(days=365)
            )
            admin.set_password('Delta2024!')
            db.session.add(admin)
        
        if not User.query.filter_by(email='test@delta.chat').first():
            test_user = User(
                email='test@delta.chat',
                username='Shadow_Walker_42',
                display_name='Shadow',
                is_anonymous=True
            )
            test_user.set_password('test123')
            db.session.add(test_user)
        
        db.session.commit()
        print("✅ DELTA Database initialized")
        
    except Exception as e:
        print(f"❌ Database error: {e}")
        db.session.rollback()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    print(f"🚀 DELTA Messenger starting on port {port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=debug, allow_unsafe_werkzeug=True)
