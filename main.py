from flask import Flask, render_template, url_for, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField
from wtforms.validators import DataRequired, Length, ValidationError, NumberRange
from flask_bcrypt import Bcrypt



app = Flask(__name__)
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisissecretkey'

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create a User Model
class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    name=db.Column(db.String(40), nullable=False)
    email=db.Column(db.String(40), nullable=False, unique=True)
    username=db.Column(db.String(40), nullable=False, unique=True)
    password=db.Column(db.String(60), nullable=False, unique=True)
    

    def __repr__(self):
        return '<User {}>'.format(self.username)

# Create Category Model
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    products = db.relationship('Product', backref='category', lazy=True)

# Create Product Model
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    unit = db.Column(db.String, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    carts = db.relationship('Cart', backref='product',lazy=True)

# Create User Cart Model
class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quantity = db.Column(db.Integer, nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    


with app.app_context():
    db.create_all()
   

# Create Registerform(SignUp)

class RegisterForm(FlaskForm):
    name = StringField(validators=[DataRequired(),Length(min=4, max=50)],  
    render_kw={"placeholder":"Name"})

    email = StringField(validators=[DataRequired(),Length(min=5, max=50)],  
    render_kw={"placeholder":"email"})

    username = StringField(validators=[DataRequired(),Length(min=3, max=20)],  
    render_kw={"placeholder":"Username"})

    password = PasswordField(validators=[DataRequired(),Length(min=4)],
    render_kw={"placeholder":"Password"})
    submit = SubmitField("SignUp")

    def validate_name(self, name):
        existing_user_name=User.query.filter_by(name=name.data).first()

    

    def validate_username(self, username):
        existing_user_username=User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError('Username already in use.Please choose a different one.')


# Create Admin Login form
class AdminLoginForm(FlaskForm):
    username = StringField(validators=[DataRequired()],  
    render_kw={"placeholder":"Username"})

    password = PasswordField(validators=[DataRequired()],
    render_kw={"placeholder":"Password"})
    submit = SubmitField("LogIn")

# Create User Login form
class UserLoginForm(FlaskForm):
    username = StringField(validators=[DataRequired()],  
    render_kw={"placeholder":"Username"})

    password = PasswordField(validators=[DataRequired()],
    render_kw={"placeholder":"Password"})
    submit = SubmitField("LogIn")
   
# Create Category Form
class CategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired()])
    submit = SubmitField("Submit")

# Create Product form
class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    unit = StringField('Unit', validators=[DataRequired()])
    price = IntegerField('Price/unit', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
    category = SelectField('Category', validators=[DataRequired()])
    def __init__(self):
        super(ProductForm, self).__init__()
        self.category.choices = [(c.id, c.name) for c in Category.query.all()]


# Create User Cart Form
class CartForm(FlaskForm):
    product_name = SelectField('Product', validators=[DataRequired()])
    category_name = SelectField('Category', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])

    
#-----------------------Admin-----------------------
# Create admin Login page
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()

    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html',form=form)

#create Admin dashboard page
@app.route('/admin_dashboard', methods = ['GET', 'POST'])
def admin_dashboard():
    categories = Category.query.all()
    products = Product.query.all()
    return render_template('admin_dashboard.html', categories=categories, products=products)
 
# Create Category route
@app.route('/categories')
def categories():
    categories = Category.query.all()
    return render_template('category.html', categories=categories)

# Create New category route
@app.route('/create_category', methods=['GET', 'POST'])
def create_category():
    form = CategoryForm()
    if form.validate_on_submit():
        category = Category(name=form.name.data)
        db.session.add(category)
        db.session.commit()
        flash('New category created successfully!')
        return redirect(url_for('admin_dashboard'))
    return render_template('create_category.html', form=form)

# Create Edit category route
@app.route('/edit_category/<int:id>', methods=['GET', 'POST'])

def edit_category(id):
    category = Category.query.get(id)
    if request.method == 'POST':
        category.name = request.form['name']
        db.session.commit()
        flash('Category updated successfully!')
        return redirect(url_for('categories'))
    return render_template('edit_category.html', category=category)

# Create Delete category route
@app.route('/category/delete/<int:id>', methods=['GET', 'POST'])
def delete_category(id):
    category = Category.query.get(id)
    if request.method == 'POST':
        db.session.delete(category)
        db.session.commit()
        flash('Catgory deleted successfully!')
        return redirect(url_for('admin_dashboard'))
    return render_template('delete_category.html', category=category)

# Create product route
@app.route('/products',methods=['GET'])
def products():
    products = Product.query.all()
    product_details = []

    for product in products:
        category = Category.query.get(product.category_id)
        product_detail = {
            'id' : product.id,
            'name': product.name,
            'unit' : product.unit,
            'price' : product.price,
            'quantity': product.quantity,
            'category_name': category}
        product_details.append(product_detail)   
    return render_template('products.html', product_details=product_details)

# Create New Product route
@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    form = ProductForm()

    if form.validate_on_submit():
        product = Product(name=form.name.data,
            unit=form.unit.data,
            price=form.price.data,
            quantity=form.quantity.data,
            category_id=form.category.data)
        db.session.add(product)
        db.session.commit()
        flash('New product created successfully!')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_product.html', form=form, categories=categories)


# Create Edit Product route
@app.route('/edit_product/<int:id>', methods=['GET', 'POST'])
def edit_product(id):
    product = Product.query.get(id)
    if request.method == 'POST':
        product.name = request.form['name']
        product.unit = request.form['unit']
        product.price = request.form['price']
        product.quantity = request.form['quantity']
        db.session.commit()
        flash('Product updated successfully!')
        return redirect(url_for('products'))
    return render_template('edit_product.html', product=product)

# Create delete route
@app.route('/product/delete/<int:id>', methods=['GET', 'POST'])
def delete_product(id):
    product = Product.query.get(id)
    if request.method == 'POST':
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted successfully!')
        return redirect(url_for('admin_dashboard'))
    return render_template('delete_product.html',product=product )


#--------------User----------------

# Create User SignUp/Register Page
@app.route('/signup',methods=['GET','POST'])
def signup():
  form=RegisterForm()
  if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user=User(name=form.name.data,email=form.email.data,username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect (url_for('user_login'))
  return render_template('signup.html',form=form)


# Create User Login page
@app.route('/user_login/user', methods=['GET','POST'])
def user_login():
    form=UserLoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('home'))
    return render_template('user_login.html',form=form)

# Create User Dashboard page
@app.route('/user_dashboard',methods=['GET','POST'])
def user_dashboard():
    categories = Category.query.all()
    products = Product.query.all()
    return render_template('user_dashboard.html',categories=categories, products=products)

#------------------------------------#--------------------------------------------  
# Create Home page
@app.route('/home')
def home():
     categories = Category.query.all()
     products = Product.query.all()
     return render_template('home.html',products=products,categories=categories)

# Create index page
@app.route('/index')
def index():
    return render_template('index.html')

# Create Cart route
@app.route('/create_cart', methods=['GET', 'POST'])
def create_cart():
    form = CartForm()
    form.product_name.choices = [(p.name, p.name) for p in Product.query.all()]
    form.category_name.choices = [(c.name, c.name) for c in Category.query.all()]

    if form.validate_on_submit():
        product_name = form.product_name.data
        category_name = form.category_name.data
        quantity = form.quantity.data


        # Get the product object associated with the selected product name
        product = Product.query.filter_by(name=product_name).first()

        # Get the category object associated with the selected category name
        category = Category.query.filter_by(name=category_name).first()

        # Check if the selected category is associated with the selected product
        if category.id != product.category_id:
            flash('Please select the correct category for this product')
            return redirect(url_for('create_cart'))
        

        # Create a new cart
        cart = Cart(product_id=product.id, category_id=category.id, user_id=current_user.id, quantity=quantity)
        product.quantity -= cart.quantity
        db.session.add(cart)
        db.session.commit()

        flash('Cart created successfully!')
        return redirect(url_for('my_cart'))

    return render_template('create_cart.html', form=form)



# Create route for user cart
@app.route('/my_cart', methods=['GET'])
def my_cart():
    carts = Cart.query.filter_by(user_id=current_user.id).all()
    
    # create a list to store cart deatils
    cart_details = []
    
    for cart in carts:
        product = Product.query.get(cart.product_id)
        category = Category.query.get(cart.category_id)
        
        cart_detail = {
            'id' : cart.id,
            'product_name': product.name,
            'category_name': category.name,
            'quantity': cart.quantity,
        }
        cart_details.append(cart_detail)
      
    return render_template('my_cart.html', cart_details=cart_details)


#create delete cart route
@app.route('/delete_cart/<int:cart_id>', methods=['POST'])
def delete_cart(cart_id):
    cart = Cart.query.get(cart_id)
    if cart:
        product = Product.query.get(cart.product_id)
        product.quantity += cart.quantity
        db.session.delete(cart)
        db.session.commit()
        flash('Cart deleted successfully')
        return redirect(url_for('my_cart'))
    return redirect(url_for('user_dashboard'))


# Create Search Route
@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        search_query = request.form['search']
        products = Product.query.filter(Product.name.ilike(f'%{search_query}%')).all()
        categories = Category.query.filter(Category.name.ilike(f'%{search_query}%')).all()

    return render_template('search_results.html', products=products, categories=categories)


# Create Logout page
@app.route("/logout", methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('user_login'))

#create error page
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"),404




if __name__ == "__main__":
    app.run(debug=True)
