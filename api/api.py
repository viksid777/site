from datetime import datetime
import pytz
from flask import Flask, render_template, redirect, request, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
import requests as hrequests

app = Flask(__name__)

# Конфигурация приложения
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = SQLAlchemy(app)
app.config['SECRET_KEY'] = 'random_secret_key'
csrf = CSRFProtect(app)

db = app.config['SESSION_SQLALCHEMY']
Session(app)


# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_blocked = db.Column(db.Boolean, default=False)


# Модель для хранения активных сессий
class ActiveSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    logged_in = db.Column(db.Boolean, default=False)


# Модель Post (посты блога)
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.now(tz=pytz.timezone('Europe/Moscow')))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref='posts', lazy=True)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"


# Модель Comment (комментарии)
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.now(tz=pytz.timezone('Europe/Moscow')))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    post = db.relationship('Post', backref='comments', lazy=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref='comments', lazy=True)

    def __repr__(self):
        return f"Comment('{self.content}', '{self.date_posted}')"


# Форма регистрации
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message="Введите корректный Email")],
                        render_kw={"class": "form-control", "placeholder": "Введите Email"})
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6, message="Минимум 6 символов")],
                             render_kw={"class": "form-control", "placeholder": "Введите пароль"})
    confirm_password = PasswordField('Повторите пароль', validators=[DataRequired(), EqualTo('password',
                                                                                             message="Пароли должны совпадать")],
                                     render_kw={"class": "form-control", "placeholder": "Повторите пароль"})
    submit = SubmitField('Зарегистрироваться', render_kw={"class": "btn btn-primary w-100"})


# Форма авторизации
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message="Введите корректный Email")],
                        render_kw={"class": "form-control", "placeholder": "Введите Email"})
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6, message="Минимум 6 символов")],
                             render_kw={"class": "form-control", "placeholder": "Введите пароль"})
    submit = SubmitField('Войти', render_kw={"class": "btn btn-primary w-100"})


# Создаем демонстрационные посты
def create_sample_posts_with_comments():
    # Проверяем, есть ли уже данные в базе
    if Post.query.count() == 0:
        print("Добавляем пример данных...")

        # Создаем пользователей
        admin = User.query.filter_by(email="admin@example.com").first()
        user1 = User.query.filter_by(email="user1@example.com").first()
        user2 = User.query.filter_by(email="user2@example.com").first()

        if not admin:
            admin = User(email="admin@example.com",
                         password=generate_password_hash("admin123", method='pbkdf2:sha256'), role="admin")
            db.session.add(admin)

        if not user1:
            user1 = User(email="user1@example.com",
                         password=generate_password_hash("user123", method='pbkdf2:sha256'))
            db.session.add(user1)

        if not user2:
            user2 = User(email="user2@example.com",
                         password=generate_password_hash("user123", method='pbkdf2:sha256'))
            db.session.add(user2)

        db.session.commit()

        # Создаем посты
        post1 = Post(title="Добро пожаловать в наш блог", content="Это первый пост в блоге.", author_id=admin.id)
        post2 = Post(title="День открытых дверей",
                     content="Скоро в нашем приюте пройдет день открытых дверей, где вы сможете поближе познакомиться с нашими питомцами!",
                     author_id=admin.id)
        db.session.add(post1)
        db.session.add(post2)
        db.session.commit()

        # Добавляем комментарии
        comment1 = Comment(content="Отличный пост, спасибо!", post_id=post1.id, author_id=user1.id)
        comment2 = Comment(content="Жду новых публикаций!", post_id=post1.id, author_id=user2.id)
        comment3 = Comment(content="Супер, жду с нетерпением!", post_id=post2.id, author_id=user1.id)
        db.session.add(comment1)
        db.session.add(comment2)
        db.session.add(comment3)

        db.session.commit()
        print("Данные добавлены.")
    else:
        print("Данные уже существуют.")


def get_weather(city):
    url = f"http://wttr.in/{city}?format=j1"  # JSON-формат
    try:
        response = hrequests.get(url)
        response.raise_for_status()
        data = response.json()
        weather = {
            "city": city,
            "temperature": data["current_condition"][0]["temp_C"],  # Температура в °C
            "description": data["current_condition"][0]["weatherDesc"][0]["value"]  # Описание погоды
        }
        return weather
    except hrequests.RequestException as e:
        print(f"Ошибка получения данных о погоде: {e}")
        return None


@app.context_processor
def inject_weather():
    weather = get_weather(city="Saint-Petersburg")
    return dict(weather=weather)


@app.route('/')
def index():
    return render_template('index.html', session=session)


# Маршрут для авторизации
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        flash('Вы уже вошли в систему!', 'info')
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        # Проверяем email и пароль через базу данных
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.is_blocked:
            flash("Вы были заблокированы", 'danger')
            return redirect(url_for('login'))

        if user and check_password_hash(user.password, form.password.data):
            session['user'] = user.email
            session['role'] = user.role
            session['logged_in'] = True

            # Сохраняем активную сессию
            user_session = ActiveSession.query.filter_by(email=user.email).first()
            if not user_session:
                user_session = ActiveSession(email=user.email, role=user.role, logged_in=True)
                db.session.add(user_session)
                db.session.commit()

            return redirect(url_for('index'))
        else:
            flash('Неверный Email или пароль.', 'danger')
    return render_template('login.html', form=form)


# Маршрут для регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Проверяем, существует ли пользователь с таким email
        if User.query.filter_by(email=form.email.data).first():
            flash('Пользователь с таким Email уже существует.', 'danger')
        else:
            # Создаем нового пользователя
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация успешна! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)


# Маршрут для выхода из системы
@app.route('/logout', methods=['POST'])
def logout():
    if 'user' in session:
        ActiveSession.query.filter_by(email=session['user']).delete()
        db.session.commit()
        session.pop('user', None)
        session.pop('role', None)
        session.pop('logged_in', False)
        flash('Вы вышли из системы.', 'info')
        session.pop('_flashes', None)
    return redirect(url_for('index'))


@app.route('/registered-users')
def registered_users():
    if 'user' not in session or session.get('role') != 'admin':
        flash('У вас нет доступа к этой странице.', 'danger')
        return redirect(url_for('index'))

    users = User.query.all()
    return render_template('registered_users.html', users=users, session=session)


@app.route('/active-users')
def active_users():
    if 'user' not in session or session.get('role') != 'admin':
        flash('У вас нет доступа к этой странице.', 'danger')
        return redirect(url_for('index'))

    active_users = ActiveSession.query.all()
    return render_template('active_users.html', active_users=active_users, session=session)


@app.route('/toggle-block/<int:user_id>', methods=['POST'])
def toggle_block(user_id):
    if 'user' not in session or session.get('role') != 'admin':
        flash('У вас нет доступа к этой функции.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        flash('Пользователь не найден.', 'danger')
        return redirect(url_for('registered_users'))

    user.is_blocked = not user.is_blocked
    db.session.commit()

    status = "заблокирован" if user.is_blocked else "разблокирован"
    flash(f'Пользователь {user.email} {status}.', 'success')
    return redirect(url_for('registered_users'))


@app.route('/blog')
def blog():
    posts = Post.query.all()
    return render_template('blog.html', posts=posts, session=session)


@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post_id).all()

    if request.method == 'POST':
        if session.get('user') is not None:
            user = User.query.filter_by(email=session.get('user')).first()
            if not user:
                flash("Что то пошло не так", 'error')
                return redirect(url_for('index'))

            comment_content = request.form['content']
            new_comment = Comment(content=comment_content, post_id=post_id, author_id=user.id)
            db.session.add(new_comment)
            db.session.commit()
            flash('Комментарий добавлен!', 'success')
        else:
            flash('Вы должны быть авторизованы, чтобы оставлять комментарии.', 'danger')
        return redirect(url_for('post_detail', post_id=post_id))

    return render_template('post_detail.html', post=post, comments=comments, session=session)


@app.route('/create', methods=['GET', 'POST'])
def create_post():
    if session.get('role') != 'admin':  # Только администратор может создавать посты
        flash('У вас нет прав для создания постов.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.query.filter_by(email=session.get('user')).first()
        if not user:
            flash("Что то пошло не так", 'error')
            return redirect(url_for('index'))
        title = request.form['title']
        content = request.form['content']
        new_post = Post(title=title, content=content, author_id=user.id)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('blog'))

    return render_template('create_post.html', session=session)


@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if session.get('role') == 'admin':
        db.session.delete(comment)
        db.session.commit()
        flash('Комментарий был удален.', 'success')
    else:
        flash('У вас нет прав для удаления комментариев.', 'danger')
    return redirect(url_for('post_detail', post_id=comment.post_id))


@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    if session.get('role') != 'admin':
        flash('У вас нет прав для удаления постов.', 'danger')
        return redirect(url_for('index'))

    # Удаляем все связанные комментарии
    Comment.query.filter_by(post_id=post_id).delete()

    # Удаляем сам пост
    db.session.delete(post)
    db.session.commit()
    flash('Пост был удален.', 'success')
    return redirect(url_for('blog'))


@app.route('/contacts')
def contacts():
    return render_template('contacts.html', session=session)


@app.route('/about')
def about():
    return render_template('about.html', session=session)


@app.errorhandler(404)
def not_found_page(error):
    return render_template('not_found.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_sample_posts_with_comments()
    app.run(debug=True)  # в боевом окружение не использовать
