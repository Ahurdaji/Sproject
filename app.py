from flask import Flask, render_template , url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_required, login_user, LoginManager , logout_user , current_user
from flask_wtf import FlaskForm
from wtforms import StringField , PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError,  Email, DataRequired
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
    posts = db.relationship('Post', backref='author', passive_deletes=True)
    comments = db.relationship('Comment', backref='comment_author', passive_deletes=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    subtitle = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    pub_date = db.Column(db.DateTime, nullable=False,default=datetime.utcnow)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    category = db.relationship('Category',backref=db.backref('posts', lazy=True))
    comments = db.relationship('Comment', backref='post', passive_deletes=True)

def __repr__(self):
        return '<Post %r>' % self.title 
    
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    pub_date = db.Column(db.DateTime, nullable=False,default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete="CASCADE"), nullable=False) 


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return '<Category %r>' % self.name
    

class PostForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(max=255)])
    subtitle = StringField('Subtitle', validators=[InputRequired(), Length(max=255)])
    body = TextAreaField('Body', validators=[InputRequired()])
    category = SelectField('Category', coerce=int, validators=[DataRequired()])
    author = TextAreaField('Body', validators=[InputRequired()])
    submit = SubmitField('Create Post')

class CategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[InputRequired(), Length(max=50)])
    submit = SubmitField('Add Category')

    
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

@app.route('/')
def get_all_posts():
    posts = Post.query.all()
    return render_template('index.html', posts=posts) 

@app.route('/post/<int:post_id>')
def show_post(post_id):
    fetched_post = Post.query.get(post_id)
    return render_template("post.html" , post=fetched_post)

@app.route('/create-comment/<post_id>', methods =['POST'])
@login_required
def create_comment(post_id):
    text = request.form.get('text')

    if not text:
        flash('Comment can not be empty', category='error')
    else:
        post= Post.query.get(post_id) 
        if post:
            comment = Comment(text=text, author=current_user.id, post_id=post_id)
            db.session.add(comment)
            db.session.commit()
        else:
            flash('Post not found', category='error')
    return redirect(url_for('home'))

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

@app.route('/create-category', methods=['GET', 'POST'])
@login_required
def create_category():
    form = CategoryForm()
    if form.validate_on_submit():
        new_category = Category(name=form.name.data)
        db.session.add(new_category)
        db.session.commit()
        flash('Category created successfully!', 'success')
       
   
    return render_template('create-category.html', form=form)

@app.route('/create-post', methods=['GET', 'POST'])
# @login_required
def create_post():
    form = PostForm()
    if request.method == "GET":
       return render_template('create-post.html', form=form)
    else:
        category_name = request.form["category"]
        category = Category(name=category_name)
        post = Post(
        title=request.form["title"],
        subtitle=request.form["subtitle"],
        body=request.form["body"],
        category=category)
        db.session.add(post)
        db.session.commit()
        flash('Post created successfully!', 'success')
        return redirect(url_for('get_all_posts'))
    

@app.route('/register', methods =['GET','POST'])
def register():
    form= RegisterForm()

    if form.validate_on_submit():
        # Hash the password
       hashed_password = bcrypt.generate_password_hash(form.password.data)
       # Create a new User object with the form data
       new_user = User(
       username=form.username.data,
       name=form.name.data,
       password=hashed_password,
       email=form.email.data,
       phone=form.phone.data )
       # Add the new user to the session and commit to insert into the database
       db.session.add(new_user)
       db.session.commit()
       flash('Account created successfully!', 'success')
       return redirect((url_for('login')))
    
    return render_template('register.html', form=form)



if __name__ == '__main__':
    app.run(debug=True)
