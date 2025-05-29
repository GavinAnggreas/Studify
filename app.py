from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Ensure the instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

# Use a new database name to avoid conflicts
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///studify.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    formulas = db.relationship('Formula', backref='author', lazy=True)
    quizzes = db.relationship('Quiz', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Formula(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    formula = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=False)
    subject = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    questions = db.relationship('Question', backref='quiz', lazy=True, cascade='all, delete-orphan')

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(200), nullable=False)
    option_b = db.Column(db.String(200), nullable=False)
    option_c = db.Column(db.String(200), nullable=False)
    option_d = db.Column(db.String(200), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)

def create_admin():
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@studify.com',
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect('/admin')
        return redirect('/dashboard')
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin'))
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # Clear any existing session
            session.clear()
            # Login the user
            login_user(user)
            
            if user.role == 'admin':
                return redirect(url_for('admin'))
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect('/')
        
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect('/register')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect('/register')
        
        user = User(username=username, email=email, role='user')
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect('/login')
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route('/admin')
@login_required
def admin():
    # Double check if the user is actually an admin
    if current_user.role != 'admin':
        flash('You do not have permission to access the admin area', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.filter_by(role='user').all()
    return render_template('admin/dashboard.html', users=users)

@app.route('/admin/user/<int:user_id>')
@login_required
def admin_user_details(user_id):
    if current_user.role != 'admin':
        return redirect('/')
    
    user = User.query.get_or_404(user_id)
    formulas = Formula.query.filter_by(user_id=user_id).all()
    quizzes = Quiz.query.filter_by(user_id=user_id).all()
    return render_template('admin/user_details.html', user=user, formulas=formulas, quizzes=quizzes)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'admin':
        return redirect('/')
    
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash('Cannot delete admin user', 'error')
        return redirect('/admin')
    
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect('/admin')

@app.route('/dashboard')
@login_required
def dashboard():
    formulas = Formula.query.filter_by(user_id=current_user.id).all()
    quizzes = Quiz.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', user=current_user, formulas=formulas, quizzes=quizzes)

@app.route('/quizzes')
@login_required
def quiz_list():
    quizzes = Quiz.query.filter_by(user_id=current_user.id).order_by(Quiz.created_at.desc()).all()
    return render_template('quiz_list.html', quizzes=quizzes)

@app.route('/quiz/new', methods=['GET', 'POST'])
@login_required
def new_quiz():
    if request.method == 'POST':
        title = request.form['title']
        subject = request.form['subject']
        
        quiz = Quiz(title=title, subject=subject, user_id=current_user.id)
        db.session.add(quiz)
        db.session.commit()
        
        flash('Quiz created! Now add some questions.', 'success')
        return redirect(url_for('edit_quiz', quiz_id=quiz.id))
    
    return render_template('new_quiz.html')

@app.route('/quiz/<int:quiz_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    if quiz.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to edit this quiz', 'error')
        return redirect(url_for('quiz_list'))
    
    if request.method == 'POST':
        question_text = request.form['question_text']
        option_a = request.form['option_a']
        option_b = request.form['option_b']
        option_c = request.form['option_c']
        option_d = request.form['option_d']
        correct_answer = request.form['correct_answer']
        
        question = Question(
            question_text=question_text,
            option_a=option_a,
            option_b=option_b,
            option_c=option_c,
            option_d=option_d,
            correct_answer=correct_answer,
            quiz_id=quiz.id
        )
        
        db.session.add(question)
        db.session.commit()
        
        flash('Question added successfully!', 'success')
        return redirect(url_for('edit_quiz', quiz_id=quiz.id))
    
    return render_template('edit_quiz.html', quiz=quiz)

@app.route('/quiz/<int:quiz_id>/delete', methods=['POST'])
@login_required
def delete_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    if quiz.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to delete this quiz', 'error')
        return redirect(url_for('quiz_list'))
    
    db.session.delete(quiz)
    db.session.commit()
    flash('Quiz deleted successfully!', 'success')
    return redirect(url_for('quiz_list'))

@app.route('/quiz/<int:quiz_id>/question/<int:question_id>/delete', methods=['POST'])
@login_required
def delete_question(quiz_id, question_id):
    question = Question.query.get_or_404(question_id)
    if question.quiz.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to delete this question', 'error')
        return redirect(url_for('edit_quiz', quiz_id=quiz_id))
    
    db.session.delete(question)
    db.session.commit()
    flash('Question deleted successfully!', 'success')
    return redirect(url_for('edit_quiz', quiz_id=quiz_id))

@app.route('/quiz/<int:quiz_id>/take')
@login_required
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template('take_quiz.html', quiz=quiz)

@app.route('/quiz/<int:quiz_id>/submit', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    score = 0
    total = len(quiz.questions)
    
    for question in quiz.questions:
        answer = request.form.get(f'question_{question.id}')
        if answer == question.correct_answer:
            score += 1
    
    percentage = (score / total) * 100 if total > 0 else 0
    return render_template('quiz_result.html', score=score, total=total, percentage=percentage)

@app.route('/formula/new', methods=['GET', 'POST'])
@login_required
def new_formula():
    if request.method == 'POST':
        title = request.form['title']
        formula = request.form['formula']
        description = request.form['description']
        subject = request.form['subject']

        new_formula = Formula(
            title=title,
            formula=formula,
            description=description,
            subject=subject,
            user_id=current_user.id
        )

        try:
            db.session.add(new_formula)
            db.session.commit()
            flash('Formula added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('new_formula'))

    return render_template('new_formula.html')

@app.route('/formula/<int:id>')
@login_required
def view_formula(id):
    formula = Formula.query.get_or_404(id)
    if formula.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to view this formula', 'error')
        return redirect(url_for('dashboard'))
    return render_template('view_formula.html', formula=formula)

@app.route('/formula/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_formula(id):
    formula = Formula.query.get_or_404(id)
    if formula.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to edit this formula', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        formula.title = request.form['title']
        formula.formula = request.form['formula']
        formula.description = request.form['description']
        formula.subject = request.form['subject']

        try:
            db.session.commit()
            flash('Formula updated successfully!', 'success')
            return redirect(url_for('view_formula', id=formula.id))
        except Exception as e:
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('edit_formula', id=formula.id))

    return render_template('edit_formula.html', formula=formula)

@app.route('/formula/<int:id>/delete', methods=['POST'])
@login_required
def delete_formula(id):
    formula = Formula.query.get_or_404(id)
    if formula.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to delete this formula', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Store user_id before deletion for admin redirect
        user_id = formula.user_id
        
        # Delete the formula using the model instance
        db.session.delete(formula)
        db.session.commit()
        
        flash('Formula deleted successfully!', 'success')
        
        if current_user.role == 'admin':
            return redirect(url_for('admin_user_details', user_id=user_id))
        return redirect(url_for('dashboard'))
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the formula.', 'error')
        if current_user.role == 'admin':
            return redirect(url_for('admin_user_details', user_id=formula.user_id))
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()
    app.run(debug=True) 