from flask import Flask, render_template , url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_required, login_user, LoginManager , logout_user , current_user
from flask_wtf import FlaskForm
from wtforms import StringField , PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError,  Email
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from datetime import datetime

app = Flask(__name__)

# Update with MySQL connection details
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost/dbproject'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    subtitle = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    pub_date = db.Column(db.DateTime, nullable=False,default=datetime.utcnow)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'),nullable=False)
    category = db.relationship('Category',backref=db.backref('posts', lazy=True))

    def __repr__(self):
        return '<Post %r>' % self.title


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return '<Category %r>' % self.name
    

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    name = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Name"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    email = StringField(validators=[InputRequired(), Email(), Length(max=80)], render_kw={"placeholder": "Email"})
    phone = StringField(validators=[InputRequired(), Length(min=10, max=15)], render_kw={"placeholder": "Phone"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by( username = username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("That email already exists. Please choose a different one.")    
        

class LoginForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length( min=4 , max =20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators = [InputRequired(), Length(min=4 , max =20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login") 
    

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/login', methods =['GET','POST'])
def login():
    form= LoginForm() 
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user :
            if bcrypt.check_password_hash(user.password , form.password.data):
               login_user(user)
               return redirect(url_for('dashboard'))
    return render_template('login.html',form=form)


@app.route('/')
def index():
    return render_template('index.html')  

@app.route('/dashboard',methods =['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout',methods =['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/blog',methods =['GET','POST'])
def blog():
    return render_template('blog.html')

@app.route('/create-post',methods =['GET','POST'])
def create_post():
    return render_template('create-post.html')

@app.route('/register', methods =['GET','POST'])
def register():
    form= RegisterForm()

    if form.validate_on_submit():
       hashed_password = bcrypt.generate_password_hash(form.password.data)
       new_user = User(username=form.username.data, name=form.name.data, password=hashed_password, email=form.email.data, phone=form.phone.data)
       db.session.add(new_user)
       db.session.commit()
       flash('Account created successfully!', 'success')
       return redirect((url_for('login')))
    
    return render_template('register.html', form=form)



if __name__ == '__main__':
    app.run(debug=True)
