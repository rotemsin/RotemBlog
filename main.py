from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)

ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)

app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user):
    return User.query.get(user)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="user")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.String(250), nullable=False)

# This line should one run once in order to create the database and the tables in it
# db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register in order to add a comment")
            return redirect(url_for("login"))
        new_comment = Comment(user_id=current_user.id, post_id=post_id, text=form.text.data)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post, current_user=current_user, form=form)


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(author=current_user, title=form.title.data, subtitle=form.subtitle.data, img_url=form.img_url.data,
                            body=form.body.data, date=datetime.now().strftime("%B %m, %Y"))
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    edited_post = BlogPost.query.get(post_id)
    form = CreatePostForm(title=edited_post.title, subtitle=edited_post.subtitle, img_url=edited_post.img_url,
                          author=edited_post.author, body=edited_post.body)
    if form.validate_on_submit():
        edited_post.title = form.title.data
        edited_post.subtitle = form.subtitle.data
        edited_post.img_url = form.img_url.data
        edited_post.author = form.author.data
        edited_post.body = form.body.data
        db.session.commit()
        return render_template("post.html", post=edited_post)
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/delete/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("get_all_posts"))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Find if this email already exists and if it is redirect to the login page
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            flash("You already registered with this email. Please login.")
            return redirect(url_for("login"))
        # Create a new entry in the database
        new_user = User(email=form.email.data,
                        password=generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8),
                        name=form.name.data)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Find if this email doesn't exist, redirect to the login page
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            flash("The email doesn't exist. Try again.")
            return redirect(url_for('login'))
        # If the password entered and the hashed password from the database aren't equal, redirect to the login page
        if not check_password_hash(user.password, form.password.data):
            flash("Incorrect password. Please try again.")
            return redirect(url_for('login'))
        # log the user in
        login_user(user)
        return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
