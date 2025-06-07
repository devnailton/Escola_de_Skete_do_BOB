
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, DateField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# Configuração do Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///escolinha.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialização das extensões
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelos de usuário
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    can_manage_alunos = db.Column(db.Boolean, default=False)
    can_manage_turmas = db.Column(db.Boolean, default=False)
    can_manage_presencas = db.Column(db.Boolean, default=False)
    can_view_dashboard = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(20), default='Ativo')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'

# Modelos do banco de dados
class Aluno(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    responsavel = db.Column(db.String(100), nullable=False)
    telefone = db.Column(db.String(20))
    email = db.Column(db.String(100))
    data_matricula = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    data_nascimento = db.Column(db.Date)
    status = db.Column(db.String(20), default='Ativo')
    observacoes = db.Column(db.Text)
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'))
    
    def __repr__(self):
        return f'<Aluno {self.nome}>'

class Turma(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    faixa_etaria = db.Column(db.String(50))
    professor = db.Column(db.String(100))
    dias_da_semana = db.Column(db.String(100))
    horario_inicio = db.Column(db.String(10))
    horario_fim = db.Column(db.String(10))
    local = db.Column(db.String(100))
    capacidade_maxima = db.Column(db.Integer)
    status = db.Column(db.String(20), default='Ativa')
    alunos = db.relationship('Aluno', backref='turma', lazy=True)
    
    def __repr__(self):
        return f'<Turma {self.nome}>'

class Presenca(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    aluno_id = db.Column(db.Integer, db.ForeignKey('aluno.id'), nullable=False)
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'), nullable=False)
    data = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    presente = db.Column(db.Boolean, default=True)
    observacoes = db.Column(db.Text)
    aluno = db.relationship('Aluno', backref='presencas')
    turma_rel = db.relationship('Turma', backref='presencas')
    
    def __repr__(self):
        return f'<Presenca {self.aluno.nome} - {self.data}>'

class Professor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100))
    telefone = db.Column(db.String(20))
    especialidade = db.Column(db.String(100))
    data_contratacao = db.Column(db.Date, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Ativo')
    
    def __repr__(self):
        return f'<Professor {self.nome}>'

# Formulários
class AlunoForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired(), Length(min=2, max=100)])
    responsavel = StringField('Responsável', validators=[DataRequired(), Length(min=2, max=100)])
    telefone = StringField('Telefone')
    email = StringField('Email')
    data_nascimento = DateField('Data de Nascimento')
    turma_id = SelectField('Turma', coerce=int)
    observacoes = TextAreaField('Observações')
    submit = SubmitField('Salvar')

class TurmaForm(FlaskForm):
    nome = StringField('Nome da Turma', validators=[DataRequired(), Length(min=2, max=100)])
    faixa_etaria = StringField('Faixa Etária')
    professor = StringField('Professor')
    dias_da_semana = StringField('Dias da Semana')
    horario_inicio = StringField('Horário de Início')
    horario_fim = StringField('Horário de Fim')
    local = StringField('Local')
    capacidade_maxima = StringField('Capacidade Máxima')
    submit = SubmitField('Salvar')

class UserForm(FlaskForm):
    username = StringField('Nome de Usuário', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Length(min=5, max=120)])
    password = StringField('Senha', validators=[DataRequired(), Length(min=6, max=50)])
    can_manage_alunos = SelectField('Gerenciar Alunos', choices=[('0', 'Não'), ('1', 'Sim')], coerce=int)
    can_manage_turmas = SelectField('Gerenciar Turmas', choices=[('0', 'Não'), ('1', 'Sim')], coerce=int)
    can_manage_presencas = SelectField('Gerenciar Presenças', choices=[('0', 'Não'), ('1', 'Sim')], coerce=int)
    submit = SubmitField('Salvar')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rotas de autenticação
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
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha incorretos')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Decoradores de permissão
def admin_required(f):
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Acesso negado. Você precisa ser administrador.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def permission_required(permission):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if not current_user.is_admin and not getattr(current_user, permission, False):
                flash('Acesso negado. Você não tem permissão para acessar esta área.')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

# Rotas do dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    alunos_count = Aluno.query.count()
    turmas_count = Turma.query.count()
    professores_count = Professor.query.count()
    eventos_count = 0  # Para implementar futuramente
    
    return render_template(
        'dashboard.html',
        alunos_count=alunos_count,
        turmas_count=turmas_count,
        professores_count=professores_count,
        eventos_count=eventos_count,
        atividades=[],
        eventos=[]
    )

# CRUD para Alunos
@app.route('/alunos')
@login_required
@permission_required('can_manage_alunos')
def alunos():
    alunos_lista = Aluno.query.all()
    return render_template('alunos.html', alunos=alunos_lista)

@app.route('/alunos/novo', methods=['GET', 'POST'])
@login_required
@permission_required('can_manage_alunos')
def novo_aluno():
    form = AlunoForm()
    form.turma_id.choices = [(0, 'Selecione uma turma')] + [(t.id, t.nome) for t in Turma.query.all()]
    
    if form.validate_on_submit():
        turma_id = form.turma_id.data if form.turma_id.data != 0 else None
        
        # Verificar capacidade da turma se uma turma foi selecionada
        if turma_id:
            turma = Turma.query.get(turma_id)
            if turma and turma.capacidade_maxima:
                alunos_na_turma = Aluno.query.filter_by(turma_id=turma_id).count()
                if alunos_na_turma >= turma.capacidade_maxima:
                    flash(f'Não é possível matricular o aluno. A turma "{turma.nome}" já atingiu sua capacidade máxima de {turma.capacidade_maxima} alunos.', 'error')
                    return render_template('novo_aluno.html', form=form)
        
        aluno = Aluno(
            nome=form.nome.data,
            responsavel=form.responsavel.data,
            telefone=form.telefone.data,
            email=form.email.data,
            data_nascimento=form.data_nascimento.data,
            turma_id=turma_id,
            observacoes=form.observacoes.data
        )
        db.session.add(aluno)
        db.session.commit()
        flash('Aluno cadastrado com sucesso!')
        return redirect(url_for('alunos'))
    
    return render_template('novo_aluno.html', form=form)

@app.route('/alunos/<int:aluno_id>/editar', methods=['GET', 'POST'])
@login_required
@permission_required('can_manage_alunos')
def editar_aluno(aluno_id):
    aluno = Aluno.query.get_or_404(aluno_id)
    form = AlunoForm(obj=aluno)
    form.turma_id.choices = [(0, 'Selecione uma turma')] + [(t.id, t.nome) for t in Turma.query.all()]
    
    if form.validate_on_submit():
        nova_turma_id = form.turma_id.data if form.turma_id.data != 0 else None
        turma_anterior_id = aluno.turma_id
        
        # Verificar capacidade da nova turma se mudou de turma
        if nova_turma_id and nova_turma_id != turma_anterior_id:
            turma = Turma.query.get(nova_turma_id)
            if turma and turma.capacidade_maxima:
                alunos_na_turma = Aluno.query.filter_by(turma_id=nova_turma_id).count()
                if alunos_na_turma >= turma.capacidade_maxima:
                    flash(f'Não é possível transferir o aluno. A turma "{turma.nome}" já atingiu sua capacidade máxima de {turma.capacidade_maxima} alunos.', 'error')
                    return render_template('editar_aluno.html', form=form, aluno=aluno)
        
        aluno.nome = form.nome.data
        aluno.responsavel = form.responsavel.data
        aluno.telefone = form.telefone.data
        aluno.email = form.email.data
        aluno.data_nascimento = form.data_nascimento.data
        aluno.turma_id = nova_turma_id
        aluno.observacoes = form.observacoes.data
        db.session.commit()
        flash('Aluno atualizado com sucesso!')
        return redirect(url_for('alunos'))
    
    return render_template('editar_aluno.html', form=form, aluno=aluno)

@app.route('/alunos/<int:aluno_id>/excluir', methods=['POST'])
@login_required
@permission_required('can_manage_alunos')
def excluir_aluno(aluno_id):
    aluno = Aluno.query.get_or_404(aluno_id)
    db.session.delete(aluno)
    db.session.commit()
    flash('Aluno excluído com sucesso!')
    return redirect(url_for('alunos'))

# CRUD para Turmas
@app.route('/turmas')
@login_required
@permission_required('can_manage_turmas')
def turmas():
    turmas_lista = Turma.query.all()
    for turma in turmas_lista:
        turma.alunos_count = len(turma.alunos)
    return render_template('turmas.html', turmas=turmas_lista)

@app.route('/turmas/nova', methods=['GET', 'POST'])
@login_required
@permission_required('can_manage_turmas')
def nova_turma():
    form = TurmaForm()
    
    if form.validate_on_submit():
        turma = Turma(
            nome=form.nome.data,
            faixa_etaria=form.faixa_etaria.data,
            professor=form.professor.data,
            dias_da_semana=form.dias_da_semana.data,
            horario_inicio=form.horario_inicio.data,
            horario_fim=form.horario_fim.data,
            local=form.local.data,
            capacidade_maxima=int(form.capacidade_maxima.data) if form.capacidade_maxima.data else None
        )
        db.session.add(turma)
        db.session.commit()
        flash('Turma cadastrada com sucesso!')
        return redirect(url_for('turmas'))
    
    return render_template('nova_turma.html', form=form)

@app.route('/turmas/<int:turma_id>/editar', methods=['GET', 'POST'])
@login_required
@permission_required('can_manage_turmas')
def editar_turma(turma_id):
    turma = Turma.query.get_or_404(turma_id)
    form = TurmaForm(obj=turma)
    
    if form.validate_on_submit():
        turma.nome = form.nome.data
        turma.faixa_etaria = form.faixa_etaria.data
        turma.professor = form.professor.data
        turma.dias_da_semana = form.dias_da_semana.data
        turma.horario_inicio = form.horario_inicio.data
        turma.horario_fim = form.horario_fim.data
        turma.local = form.local.data
        turma.capacidade_maxima = int(form.capacidade_maxima.data) if form.capacidade_maxima.data else None
        db.session.commit()
        flash('Turma atualizada com sucesso!')
        return redirect(url_for('turmas'))
    
    return render_template('editar_turma.html', form=form, turma=turma)

@app.route('/turmas/<int:turma_id>/excluir', methods=['POST'])
@login_required
@permission_required('can_manage_turmas')
def excluir_turma(turma_id):
    turma = Turma.query.get_or_404(turma_id)
    db.session.delete(turma)
    db.session.commit()
    flash('Turma excluída com sucesso!')
    return redirect(url_for('turmas'))

# Rotas para Presenças
@app.route('/presencas')
@login_required
@permission_required('can_manage_presencas')
def presencas():
    presencas_lista = Presenca.query.join(Aluno).join(Turma).all()
    return render_template('presencas.html', presencas=presencas_lista)

# CRUD para Usuários (apenas para admins)
@app.route('/usuarios')
@login_required
@admin_required
def usuarios():
    usuarios_lista = User.query.all()
    return render_template('usuarios.html', usuarios=usuarios_lista)

@app.route('/usuarios/novo', methods=['GET', 'POST'])
@login_required
@admin_required
def novo_usuario():
    form = UserForm()
    
    if form.validate_on_submit():
        # Verificar se username já existe
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Nome de usuário já existe!')
            return render_template('novo_usuario.html', form=form)
        
        # Verificar se email já existe
        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_email:
            flash('Email já existe!')
            return render_template('novo_usuario.html', form=form)
        
        usuario = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=generate_password_hash(form.password.data),
            can_manage_alunos=bool(form.can_manage_alunos.data),
            can_manage_turmas=bool(form.can_manage_turmas.data),
            can_manage_presencas=bool(form.can_manage_presencas.data)
        )
        db.session.add(usuario)
        db.session.commit()
        flash('Usuário cadastrado com sucesso!')
        return redirect(url_for('usuarios'))
    
    return render_template('novo_usuario.html', form=form)

@app.route('/usuarios/<int:usuario_id>/editar', methods=['GET', 'POST'])
@login_required
@admin_required
def editar_usuario(usuario_id):
    usuario = User.query.get_or_404(usuario_id)
    form = UserForm(obj=usuario)
    
    if form.validate_on_submit():
        # Verificar se username já existe (exceto o atual)
        existing_user = User.query.filter(User.username == form.username.data, User.id != usuario_id).first()
        if existing_user:
            flash('Nome de usuário já existe!')
            return render_template('editar_usuario.html', form=form, usuario=usuario)
        
        # Verificar se email já existe (exceto o atual)
        existing_email = User.query.filter(User.email == form.email.data, User.id != usuario_id).first()
        if existing_email:
            flash('Email já existe!')
            return render_template('editar_usuario.html', form=form, usuario=usuario)
        
        usuario.username = form.username.data
        usuario.email = form.email.data
        if form.password.data:  # Só atualiza senha se foi fornecida
            usuario.password_hash = generate_password_hash(form.password.data)
        usuario.can_manage_alunos = bool(form.can_manage_alunos.data)
        usuario.can_manage_turmas = bool(form.can_manage_turmas.data)
        usuario.can_manage_presencas = bool(form.can_manage_presencas.data)
        db.session.commit()
        flash('Usuário atualizado com sucesso!')
        return redirect(url_for('usuarios'))
    
    return render_template('editar_usuario.html', form=form, usuario=usuario)

@app.route('/usuarios/<int:usuario_id>/excluir', methods=['POST'])
@login_required
@admin_required
def excluir_usuario(usuario_id):
    usuario = User.query.get_or_404(usuario_id)
    if usuario.id == current_user.id:
        flash('Você não pode excluir seu próprio usuário!')
        return redirect(url_for('usuarios'))
    db.session.delete(usuario)
    db.session.commit()
    flash('Usuário excluído com sucesso!')
    return redirect(url_for('usuarios'))

# Outras rotas
@app.route('/documentacao')
@login_required
def documentacao():
    return render_template('documentacao.html')

@app.route('/configuracoes')
@login_required
def configuracoes():
    return render_template('configuracoes.html')

@app.route('/contact', methods=['POST'])
def contact():
    if request.method == 'POST':
        flash('Mensagem enviada com sucesso!')
        return redirect(url_for('index'))

# Inicialização do banco de dados
with app.app_context():
    db.create_all()
    
    # Criar usuário admin padrão (Bob) se não existir
    admin_user = User.query.filter_by(username='bob').first()
    if not admin_user:
        admin = User(
            username='bob',
            email='bob@fatec.sp.gov.br',
            password_hash=generate_password_hash('Bob@@Fatec'),
            is_admin=True,
            can_manage_alunos=True,
            can_manage_turmas=True,
            can_manage_presencas=True
        )
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
