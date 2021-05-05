#necessary imports
import os
from flask import Flask, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user, logout_user
from flask import g

basedir = os.path.abspath(os.path.dirname(__file__))


app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite') 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'asdf'


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# create database models 
# ###########################################################################
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True) 
    Bids = db.relationship('Bid', backref='user')
    items = db.relationship('Item', secondary='bid', backref=db.backref('connectedItems', lazy='dynamic'))
    is_auctioneer = db.Column(db.Boolean, nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    
    @password.setter
    def password(self, password):
        #
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class Bid(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    price = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    

class Item(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(64), nullable=False)
    is_over = db.Column(db.Boolean, nullable=False)
    bids = db.relationship('Bid', backref='item')



# create forms
###########################################################################
class BidForm(FlaskForm):
    # user_id = IntegerField('User_id', validators=[DataRequired()])
    price = IntegerField('Price', validators=[DataRequired()])
    # item_id = IntegerField('Item_id', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ItemForm(FlaskForm):   
    item_name = StringField('Name', validators=[DataRequired()])   
    is_over = BooleanField("Over")
    submit = SubmitField('Submit')
    

class newPasswordForm(FlaskForm):
    newPassword = StringField('Username', validators=[DataRequired(), Length(1, 64)])
    pSubmit = SubmitField("Change Password")


class changeToAuctioneerForm(FlaskForm):
    aSubmit = SubmitField("Make this user an Auctioneer")


class changeToUserForm(FlaskForm):
    uSubmit = SubmitField("Make this user a user")

class IsOverForm(FlaskForm):
    item_id= IntegerField()
    submit= SubmitField("Bidding Over")


class newUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    is_auctioneer = BooleanField("is_Auctioneer")
    submit = SubmitField('Submit')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(1,64)])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('password2', message='Passwords Must Match')])
    password2 = PasswordField('Confirm Password', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Length(1, 64)])
    submit = SubmitField('Submit')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first() is not None:
            raise ValidationError('Username already in use') 


# Views
###########################################################################
@login_manager.user_loader 
def load_user(user_id):
    return User.query.get(int(user_id)) 

#set up routes
@app.route('/', methods=['GET', 'POST'])
def index():
    
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm() 
    if form.validate_on_submit(): 
        user = User(username=form.username.data, password=form.password.data, email=form.email.data, is_auctioneer=False, is_admin=False) 
        db.session.add(user) 
        db.session.commit() 
        flash('You can now login.')
        return redirect(url_for('login')) 
        
    return render_template('register.html', form=form) 

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first() 
        if user is not None and user.verify_password(form.password.data): 
            login_user(user) 
            flash("Logged in.")
           
            return redirect(url_for('index'))
        flash('Incorrect Information')
        return redirect(url_for('login'))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash("You've been logged out")
    return redirect(url_for('index'))  

@app.route('/items')
@login_required 
def items():
    items = Item.query.all()
    return render_template('items.html', items=items) 


@app.route('/item/<int:id>', methods=['GET', 'POST'])
@login_required 
def item(id):
    bidForm = BidForm()
    if bidForm.validate_on_submit():
        lastBid = Item.query.get(id)
        Bid1 = lastBid.query.first()
        formEntry = Bid(price = bidForm.price.data, user_id = current_user.get_id(), item_id = id)
        if len(lastBid.bids): #if the list is empty it will retrun false and just commit the bid with no price checks
            if formEntry.price > lastBid.bids[-1].price: #get last bid in the bids list
                db.session.add(formEntry)
                db.session.commit()
                bidForm.price.data = 0
            else:
                flash("You need to bid more")
        else:
                #if there are no bids this will run
                db.session.add(formEntry)
                db.session.commit()
                bidForm.price.data = 0
    users = User.query.all()
    item = Item.query.get(id)
    return render_template('item_id.html', item=item, form=bidForm, users = users) 

@app.route('/bidder', methods=['GET', 'POST'])
@login_required 
def bidder():
    id = current_user.get_id()
    user = User.query.get(id)
    return render_template('bidder.html', user=user )

@app.route('/auctioneer', methods=['GET', 'POST'])
@login_required
def auctioneer():
    id = current_user.get_id()
    user = User.query.get(id)
    if current_user.is_auctioneer: 
        itemForm = ItemForm()


        if itemForm.validate_on_submit():
            formEntry= Item(item_name = itemForm.item_name.data, is_over=False)
            db.session.add(formEntry)
            db.session.commit()
            b = Bid(price = 0, user_id = id, item_id = formEntry.id)
            db.session.add(b)
            db.session.commit()
            itemForm.item_name.data = ""

        return render_template('auctioneer.html', form=itemForm, user=user)
    flash("You're not auctioneer")
    return redirect(url_for('index'))

@app.route('/auctioneerItem/<int:id>', methods=['GET', 'POST'])
@login_required 
def auctioneerItem(id):
        isOverForm = IsOverForm()
        item = Item.query.get(id)
        if isOverForm.validate_on_submit():
            item.is_over = True
            db.session.commit()
        return render_template('auctioneerItem_id.html', form=isOverForm, item=item)


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    users = User.query.all()
    newuserform = newUserForm()
    if newuserform.validate_on_submit():
        hashedPassword = generate_password_hash(newuserform.password.data)
        formEntry = User(username = newuserform.username.data, password_hash = hashedPassword, email = newuserform.email.data, is_auctioneer = newuserform.is_auctioneer.data, is_admin = False)
        db.session.add(formEntry)
        db.session.commit()
        flash("New user added")
    if current_user.is_admin: 
        return render_template('admin.html', users=users, form=newuserform)
    flash("You're not admin")
    return redirect(url_for('index'))


@app.route('/user/<int:id>', methods=['GET', 'POST'])
@login_required
def user(id):
    user = User.query.get(id)
    changetoauctioneerform = changeToAuctioneerForm()
    newpasswordform = newPasswordForm()
    changetouserform = changeToUserForm()

    if newpasswordform.validate_on_submit() and newpasswordform.pSubmit.data:
        password = generate_password_hash(newpasswordform.newPassword.data)
        user.password_hash = password
        db.session.commit()
        flash("Password Changed")
    
    if changetoauctioneerform.validate_on_submit() and changetoauctioneerform.aSubmit.data:
        user.is_auctioneer = True
        flash("Role set to auctioneer")
        db.session.commit()

    if changetouserform.validate_on_submit() and changetouserform.uSubmit.data:
        user.is_auctioneer = False
        flash("Role set to user")
        db.session.commit()
    

    return render_template('user_id.html', user=user, aForm=changetoauctioneerform, form=newpasswordform, uForm=changetouserform)


if __name__ == '__main__':
    app.run(debug=True)

