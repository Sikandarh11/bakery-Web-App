from functools import wraps
from flask import Flask, render_template, request, redirect, session, flash, jsonify, current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import datetime
import jwt
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

REGISTRATION_KEY = os.getenv("REGISTRATION_KEY")

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Set up SQLite database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bakery.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(200), nullable=False)
    customer_email = db.Column(db.String(200), nullable=False)
    customer_phone = db.Column(db.String(20), nullable=False)
    customer_address = db.Column(db.String(300), nullable=False)
    total = db.Column(db.Float, nullable=False)
    order_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    products = db.relationship('OrderProduct', backref='order', lazy=True)

    def __repr__(self):
        return f'<Order {self.id}>'

class OrderProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_name = db.Column(db.String(200), nullable=False)
    product_price = db.Column(db.Float, nullable=False)
    product_quantity = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f'<OrderProduct {self.id}>'

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)  # Add the quantity column

    def __repr__(self):
        return f'<Product {self.name}>'

    def to_dict(self):
        """Method to convert the Product instance into a dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'price': self.price,
            'quantity': self.quantity  # Include quantity in dictionary
        }

# User Model (Table) in the database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Only the owner will be admin

    def __repr__(self):
        return f'<User {self.username}>'

# Create the database tables (if they do not exist)
with app.app_context():
    db.create_all()

# Token Required Decorator to ensure that only authenticated users can access the routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('access_token')  # Get the token from the session

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['_id'])  # Fetch user from database
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token is expired!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 403

        if current_user is None or not current_user.is_admin:
            return jsonify({'message': 'You do not have the necessary permissions to perform this action.'}), 403

        return f(current_user, *args, **kwargs)

    return decorated

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/products')
def product_list():
    products = Product.query.all()  # Fetch all products from the database
    return render_template('product_list.html', products=products)


@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    product_id = int(request.form['product_id'])
    quantity = int(request.form['quantity'])  # Get quantity from form

    product = Product.query.get(product_id)

    if product and quantity <= product.quantity:
        cart = session.get('cart', [])

        # Check if the product is already in the cart
        for item in cart:
            if item['id'] == product_id:
                item['quantity'] += quantity  # Increase quantity in cart if product already exists
                break
        else:
            # Add new product to the cart
            cart.append({
                'id': product.id,
                'name': product.name,
                'price': product.price,
                'quantity': quantity
            })

        session['cart'] = cart  # Save updated cart to session

        # Decrease the product quantity in stock
        product.quantity -= quantity
        db.session.commit()  # Commit the change to the database

        flash('Product added to cart!', 'success')
    else:
        flash('Insufficient stock or invalid quantity!', 'danger')

    return redirect('/products')


@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    product_id = int(request.form['product_id'])  # Get product ID from form
    cart = session.get('cart', [])
    cart = [item for item in cart if item['id'] != product_id]  # Remove item from cart
    session['cart'] = cart  # Save updated cart
    return redirect('/place_order')

@app.route('/place_order')
def place_order():
    cart = session.get('cart', [])
    total = sum(item['price'] for item in cart)  # Access 'price' from the dictionary
    return render_template('place_order.html', cart=cart, total=total)
@app.route('/confirm_order', methods=['POST'])
def confirm_order():
    customer_name = request.form['customer_name']
    customer_email = request.form['customer_email']
    customer_phone = request.form['customer_phone']
    customer_address = request.form['customer_address']

    # Get cart details from session
    cart = session.get('cart', [])
    total = sum(item['price'] * item['quantity'] for item in cart)

    # Save the order to the database
    new_order = Order(
        customer_name=customer_name,
        customer_email=customer_email,
        customer_phone=customer_phone,
        customer_address=customer_address,
        total=total
    )
    db.session.add(new_order)
    db.session.commit()  # Commit to save the order in the database

    # Save order products to the database
    for item in cart:
        order_product = OrderProduct(
            order_id=new_order.id,
            product_name=item['name'],
            product_price=item['price'],
            product_quantity=item['quantity']
        )
        db.session.add(order_product)

    db.session.commit()  # Commit to save the order products

    # Send confirmation email to admin
    send_order_email(customer_name, customer_email, customer_phone, customer_address, total)

    # Clear the cart after sending the email
    session['cart'] = []

    return render_template('order_confirmation.html', customer_name=customer_name, total=total)

def send_order_email(customer_name, customer_email, customer_phone, customer_address, total):
    # Get admin's email and password from session (the admin's email and password are now in the session)
    admin_email = session.get('admin_email')  # Get admin's email from session
    admin_password = session.get('admin_password')  # Get admin's password from session

    # Check if admin email and password are saved in session
    if not admin_email or not admin_password:
        flash('Admin info not saved. Please enter admin info first.', 'danger')
        return redirect('/admin_info')

    # Get cart details from session
    cart = session.get('cart', [])
    cart_details = "\n".join([f"Product: {item['name']}, Quantity: {item['quantity']}, Price: ${item['price']} each" for item in cart])

    # Email content
    subject = f"New Order from {customer_name}"
    body = f"""
    New order details:
    Customer Name: {customer_name}
    Customer Email: {customer_email}
    Customer Phone: {customer_phone}
    Delivery Address: {customer_address}
    Total: ${total}

    Cart Details:
    {cart_details}

    """
    print(body)
    msg = MIMEMultipart()
    msg['From'] = admin_email
    msg['To'] = admin_email  # Send the email to admin's email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # SMTP configuration (using Gmail)

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(admin_email, admin_password)  # Use admin's password from session
        text = msg.as_string()
        server.sendmail(admin_email, admin_email, text)
        server.quit()

        flash('Order placed successfully. Email sent to admin.', 'success')
    except smtplib.SMTPAuthenticationError:
        flash('Authentication error. Please check your email and password.', 'danger')
    except Exception as e:
        flash(f"An error occurred while sending the email: {str(e)}", 'danger')

@app.route('/view_customer_orders')
@token_required
def view_customer_orders(current_user):
    if not current_user.is_admin:
        return redirect('/products')  # Redirect if not an admin

    # Fetch all orders from the database
    orders = Order.query.all()

    # Prepare the order data to display in the template
    order_data = []
    for order in orders:
        order_products = OrderProduct.query.filter_by(order_id=order.id).all()
        products = []
        for product in order_products:
            products.append({
                'name': product.product_name,
                'price': product.product_price,
                'quantity': product.product_quantity
            })
        order_data.append({
            'customer_name': order.customer_name,
            'customer_email': order.customer_email,
            'customer_phone': order.customer_phone,  # Added the phone number field
            'total': order.total,
            'products': products
        })

    return render_template('customer_orders.html', order_data=order_data)

@app.route('/admin_info', methods=['GET', 'POST'])
@token_required
def admin_info(current_user):
    if not current_user.is_admin:
        return redirect('/products')  # Redirect if not an admin

    if request.method == 'POST':
        admin_email = request.form['email']
        admin_password = request.form['password']  # Admin's password

        # Save the admin info to the session or database
        session['admin_email'] = admin_email
        session['admin_password'] = admin_password

        flash('Admin Info saved successfully!', 'success')
        return redirect('/owner_dashboard')  # Redirect to owner dashboard after saving

    return render_template('admin_info.html')

# Route for Owner Dashboard (Accessed only by admin)
@app.route('/owner_dashboard')
@token_required  # Protecting this route with the token_required decorator
def owner_dashboard(current_user):
    if not current_user.is_admin:  # If the user is not an admin, redirect them
        return redirect('/products')

    products = Product.query.all()  # Fetch all products for the admin
    return render_template('owner.html', products=products)

# Route for adding products
@app.route('/add_product', methods=['GET', 'POST'])
@token_required
def add_product(current_user):
    if not current_user.is_admin:
        return redirect('/products')  # Redirect if not an admin

    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        quantity = request.form['quantity']  # Get quantity from form
        new_product = Product(name=name, price=float(price), quantity=int(quantity))  # Store quantity

        db.session.add(new_product)
        db.session.commit()

        flash('Product added successfully!', 'success')
        return redirect('/owner_dashboard')  # Redirect to dashboard after adding

    return render_template('add_product.html')

@app.route('/delete_product/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(current_user, product_id):
    """Delete the product from the database."""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'You are not authorized to delete this product.'}), 403

    # Fetch the product by its ID
    product = Product.query.get_or_404(product_id)

    try:
        # Deleting the product from the database
        db.session.delete(product)
        db.session.commit()  # Commit the transaction
        return jsonify({'success': True, 'message': f'Product "{product.name}" deleted successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'message': f"An error occurred: {str(e)}"}), 500

# Route for updating products
@app.route('/update_product/<int:product_id>', methods=['GET', 'POST'])
@token_required
def update_product(current_user, product_id):
    if not current_user.is_admin:
        return redirect('/products')  # Redirect if not an admin

    product = Product.query.get_or_404(product_id)  # Get the product by ID

    if request.method == 'POST':
        product.name = request.form['name']
        product.price = float(request.form['price'])
        product.quantity = float(request.form['quantity'])
        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect('/owner_dashboard')

    return render_template('update_product.html', product=product)

# Route for user registration (only accessible to admin)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        reg_key = request.form['reg_key']

        # Validate Registration Key
        if reg_key != REGISTRATION_KEY:
            flash('Invalid registration key. Please contact the owner.', 'danger')
            return redirect('/register')

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists, please choose another one.', 'danger')
            return redirect('/register')  # Redirect back to registration form with a flash message

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new user
        new_user = User(username=username, password=hashed_password, is_admin=True)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect('/login')  # Redirect to login page after successful registration

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            # Query the database for the user by username
            user = User.query.filter_by(username=username).first()
            print(f"User found: {user}, Admin status: {user.is_admin}")

            # Check if user exists and the password is correct
            if user and check_password_hash(user.password, password):
                access_token = generate_access_token(user.id)
                print("access_token: ", access_token)

                # Store the access token in the session
                session['access_token'] = access_token

                # Check if the user is an admin (owner) and redirect accordingly
                if user.is_admin:
                    return redirect('/owner_dashboard')  # Redirect to owner dashboard for admin
                else:
                    flash('You do not have permission to access this page.', 'danger')
                    return redirect('/products')  # Redirect to product list if not an admin
            else:
                flash('Invalid credentials. Please try again.', 'danger')
                return redirect('/login')  # Invalid username or password

        except Exception as e:
            # Handle unexpected errors
            flash(f"An error occurred during login: {str(e)}", 'danger')
            return redirect('/login')  # Redirect back to login page if there's an error

    return render_template('login.html')  # Show the login form if it's a GET request

# Helper function to generate access token
def generate_access_token(user_id):
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            'iat': datetime.datetime.utcnow(),
            '_id': str(user_id)
        }
        return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
    except Exception as e:
        return str(e)

# Route for user logout
@app.route('/logout')
def logout():
    session.pop('access_token', None)  # Remove the access token from session
    return redirect('/products')

if __name__ == '__main__':
    app.run(debug=True, port=5002)
