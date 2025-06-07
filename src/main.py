from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Configuração do Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelo de usuário simples
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

# Usuário bob (único usuário do sistema) - alterado para minúsculo
bob = User(1, 'bob', generate_password_hash('Bob@@Fatec'))
users = {1: bob}

@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

# Rotas
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == 'bob' and check_password_hash(bob.password_hash, password):
            login_user(bob)
            return redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha incorretos')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Dados zerados para o dashboard
    alunos_count = 0
    turmas_count = 0
    professores_count = 0
    eventos_count = 0
    
    return render_template(
        'dashboard.html',
        alunos_count=alunos_count,
        turmas_count=turmas_count,
        professores_count=professores_count,
        eventos_count=eventos_count,
        atividades=[],
        eventos=[]
    )

@app.route('/documentacao')
@login_required
def documentacao():
    return render_template('documentacao.html')

@app.route('/alunos')
@login_required
def alunos():
    # Dados zerados para alunos
    alunos_lista = []
    return render_template('alunos.html', alunos=alunos_lista)

@app.route('/turmas')
@login_required
def turmas():
    # Dados zerados para turmas
    turmas_lista = []
    return render_template('turmas.html', turmas=turmas_lista)

@app.route('/presencas')
@login_required
def presencas():
    # Dados zerados para presenças
    presencas_lista = []
    return render_template('presencas.html', presencas=presencas_lista)

@app.route('/configuracoes')
@login_required
def configuracoes():
    return render_template('configuracoes.html')

@app.route('/contact', methods=['POST'])
def contact():
    if request.method == 'POST':
        # Apenas registra a submissão do formulário
        flash('Mensagem enviada com sucesso!')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
