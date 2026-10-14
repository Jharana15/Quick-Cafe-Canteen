from flask import Flask, render_template, request
# object ho and app ko thau ma aru ni lagna milxa
from flask_sqlalchemy import SQLAlchemy



app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quick_cafe.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db=SQLAlchemy(app)

class Role(db.Model):
    __tablename__ = 'role'
    role_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    remarks = db.Column(db.Text, nullable=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(30), nullable=False, unique=True)
    name = db.Column(db.String(10), nullable=False)
# foreign key
    role_id = db.Column(db.Integer, db.ForeignKey('role.role_id'), nullable=False)
    # soft delete
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

class Menu(db.Model):
    item_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    is_available = db.Column(db.Boolean, nullable =False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
 
class Order(db.Model):
    order_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    pickup_slot = db.Column(db.String(10), nullable=False)
    order_status = db.Column(db.Boolean, nullable =False)
    item_id = db.Column(db.Integer, db.ForeignKey('menu.item_id'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

# class Digital_token(db.Model):
#     token_id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100), nullable=False)
#     price = db.Column(db.Float, nullable=False)
#     is_available = db.Column(db.Boolean, nullable =False)
#     item_id = db.Column(db.Integer, db.ForeignKey('menu.item_id'), nullable=False)
#     order_id = db.Column(db.Integer, db.ForeignKey('order.order_id'), nullable=False)
#     is_deleted = db.Column(db.Boolean, default=False, nullable=False)

@app.route('/')

@app.route('/home')
def home():
     return render_template('home.html')

@app.route('/menu')
def menu():
     return render_template('menu.html')

@app.route('/about')
def about():
     return render_template('about.html')

@app.route('/order')
def order():
     return render_template('order.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Login logic yeta hunchha
        pass
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Form data handle garne code yeta hunchha
        pass
    return render_template('signup.html')

if __name__ =='__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)