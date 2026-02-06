from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import datetime
import os
import boto3
import uuid
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

app = Flask(__name__)
# 1️⃣ BASIC FLASK + AWS SETUP
app.secret_key = os.environ.get('SECRET_KEY', 'stylelane_secret_key_prod_safe')

REGION = 'us-east-1'
dynamodb = boto3.resource('dynamodb', region_name=REGION)
sns = boto3.client('sns', region_name=REGION)

# 2️⃣ DYNAMODB TABLE CONNECTIONS
users_table = dynamodb.Table('Users')
stores_table = dynamodb.Table('Stores')
suppliers_table = dynamodb.Table('Suppliers')
inventory_table = dynamodb.Table('Inventory')

# 📌 All Data Persisted in DynamoDB (using 4 Tables: Users, Stores, Suppliers, Inventory)
# Logical data (Shipments, Restock) is stored in the 'Inventory' table with a 'record_type' attribute.

# 3️⃣ SNS NOTIFICATION HELPER
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:339713020789:project_styleLane') # Fallback for demo

def send_notification(subject, message):
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"StyleLane: {subject}",
            Message=message
        )
    except ClientError as e:
        print(f"Error sending notification: {e}")

# --- Helper Functions & Decorators ---

def get_user_by_email(email):
    try:
        response = users_table.get_item(Key={'email': email})
        return response.get('Item')
    except ClientError as e:
        print(e.response['Error']['Message'])
        return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] != required_role:
                flash("Access denied. Authorized personnel only.", "danger")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- 4️⃣ AUTHENTICATION ROUTES (AWS VERSION) ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = get_user_by_email(email)
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['email']
            session['name'] = user['name']
            session['role'] = user['role']
            session['location'] = user.get('location', 'Global')
            session['store_id'] = user.get('store_id') 
            session['supplier_id'] = user.get('supplier_id')
            
            send_notification("User Login", f"User {user['name']} ({user['role']}) has logged in.")
            flash(f"Welcome back, {user['name']}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password.", "danger")
            
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role', 'manager') 
        
        if get_user_by_email(email):
            flash("Email already registered.", "warning")
        else:
            new_id = str(uuid.uuid4())
            new_user = {
                'id': new_id,
                'name': name,
                'email': email,
                'password': generate_password_hash(password),
                'role': role,
                'location': 'New Location' if role == 'manager' else 'Global'
            }
            users_table.put_item(Item=new_user)
            send_notification("New User Signup", f"New {role} registered: {name} ({email})")
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))
            
    return render_template('signup.html')

@app.route('/logout')
def logout():
    user_name = session.get('name', 'Unknown')
    send_notification("User Logout", f"User {user_name} has logged out.")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'manager':
        return redirect(url_for('manager_dashboard'))
    elif role == 'supplier':
        return redirect(url_for('supplier_dashboard'))
    else:
        return "Unknown Role", 403

# --- 5️⃣ ROLE-BASED DASHBOARDS & FEATURES ---

# --- Admin Routes ---
@app.route('/admin')
@login_required
@role_required('admin')
def admin_dashboard():
    # Only scan for 'product' type for main inventory stats
    inventory_all = inventory_table.scan().get('Items', [])
    products = [item for item in inventory_all if item.get('record_type', 'product') == 'product']
    users = users_table.scan().get('Items', [])
    stores = stores_table.scan().get('Items', [])
    suppliers = suppliers_table.scan().get('Items', [])
    
    low_stock_count = len([item for item in products if item['quantity'] < item['threshold']])
    total_managers = len([u for u in users if u['role'] == 'manager'])
    total_suppliers = len([u for u in users if u['role'] == 'supplier'])
    
    return render_template('dashboard_admin.html', 
                           inventory=products, 
                           users=users, 
                           stores=stores, 
                           suppliers=suppliers,
                           low_stock_count=low_stock_count,
                           total_managers=total_managers,
                           total_suppliers=total_suppliers)

@app.route('/admin/stores', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_stores():
    if request.method == 'POST':
        store_id = str(uuid.uuid4())
        store_name = request.form['store_name']
        location = request.form['location']
        stores_table.put_item(Item={'id': store_id, 'name': store_name, 'location': location})
        flash(f"Store '{store_name}' added successfully!", "success")
        return redirect(url_for('admin_stores'))
    
    stores = stores_table.scan().get('Items', [])
    return render_template('admin_stores.html', stores=stores)

@app.route('/admin/suppliers', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_suppliers():
    if request.method == 'POST':
        supplier_id = str(uuid.uuid4())
        supplier_name = request.form['supplier_name']
        contact = request.form['contact']
        suppliers_table.put_item(Item={'id': supplier_id, 'name': supplier_name, 'contact': contact})
        flash(f"Supplier '{supplier_name}' added successfully!", "success")
        return redirect(url_for('admin_suppliers'))
    
    suppliers = suppliers_table.scan().get('Items', [])
    return render_template('admin_suppliers.html', suppliers=suppliers)

@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    users = users_table.scan().get('Items', [])
    managers = [u for u in users if u['role'] == 'manager']
    role_suppliers = [u for u in users if u['role'] == 'supplier']
    return render_template('admin_users.html', managers=managers, suppliers=role_suppliers)

@app.route('/admin/inventory')
@login_required
@role_required('admin')
def admin_inventory():
    # Only show actual products
    inventory_all = inventory_table.scan().get('Items', [])
    products = [item for item in inventory_all if item.get('record_type', 'product') == 'product']
    stores = stores_table.scan().get('Items', [])
    suppliers = suppliers_table.scan().get('Items', [])

    enriched_inventory = []
    for item in products:
        store = next((s for s in stores if s['id'] == item['store_id']), {'name': 'Unknown'})
        supplier = next((sup for sup in suppliers if sup['id'] == item['supplier_id']), {'name': 'Unknown'})
        item_copy = item.copy()
        item_copy['store_name'] = store['name']
        item_copy['supplier_name'] = supplier['name']
        enriched_inventory.append(item_copy)
    return render_template('admin_inventory.html', inventory=enriched_inventory)

@app.route('/admin/reports')
@login_required
@role_required('admin')
def admin_reports():
    inventory_all = inventory_table.scan().get('Items', [])
    products = [item for item in inventory_all if item.get('record_type', 'product') == 'product']
    stores = stores_table.scan().get('Items', [])
    
    # Inventory Report: Product, Store, Quantity
    inventory_report = []
    for item in products:
        store = next((s for s in stores if s['id'] == item['store_id']), {'name': 'Unknown'})
        inventory_report.append({
            'product': item['name'],
            'store': store['name'],
            'quantity': item['quantity']
        })
    
    # Stock Summary Report: Product, Total Quantity, Status
    stock_summary = []
    for item in products:
        stock_summary.append({
            'product': item['name'],
            'total_quantity': item['quantity'],
            'status': 'Low Stock' if item['quantity'] < item['threshold'] else 'OK'
        })
        
    return render_template('admin_reports.html', inventory_report=inventory_report, stock_summary=stock_summary)

# --- Manager Routes ---
@app.route('/manager')
@login_required
@role_required('manager')
def manager_dashboard():
    manager_store_id = session.get('store_id')
    # Filter by record_type='product' AND store_id
    inventory = inventory_table.scan(
        FilterExpression=Attr('store_id').eq(manager_store_id) & Attr('record_type').eq('product')
    ).get('Items', [])
    suppliers = suppliers_table.scan().get('Items', [])
    return render_template('dashboard_manager.html', inventory=inventory, suppliers=suppliers)

@app.route('/manager/add_product', methods=['POST'])
@login_required
@role_required('manager')
def add_product():
    manager_store_id = session.get('store_id')
    if not manager_store_id:
        flash("Unauthorized: No store assigned to this manager.", "danger")
        return redirect(url_for('manager_dashboard'))

    name = request.form['name']
    category = request.form['category']
    size = request.form['size']
    price = float(request.form['price'])
    threshold = int(request.form['threshold'])
    supplier_id = int(request.form['supplier_id'])
    initial_qty = int(request.form.get('quantity', 0))

    # ID generation using UUID
    new_id = str(uuid.uuid4())
    
    new_product = {
        'id': new_id,
        'record_type': 'product',
        'name': name,
        'category': category,
        'size': size,
        'quantity': initial_qty,
        'price': price,
        'threshold': threshold,
        'store_id': manager_store_id,
        'supplier_id': supplier_id
    }
    inventory_table.put_item(Item=new_product)
    
    send_notification("New Product Added", f"Manager {session['name']} added '{name}' to store ID {manager_store_id}.")
    flash(f"Product '{name}' added successfully to your store.", "success")
    return redirect(url_for('manager_dashboard'))

@app.route('/manager/restock', methods=['POST'])
@login_required
@role_required('manager')
def restock_product():
    manager_store_id = session.get('store_id')
    product_id = request.form['product_id']
    quantity_to_add = int(request.form['quantity'])

    response = inventory_table.get_item(Key={'id': product_id})
    item = response.get('Item')
    
    if item:
        if item['store_id'] != manager_store_id:
            flash("Unauthorized: Product does not belong to your store.", "danger")
            return redirect(url_for('manager_dashboard'))
        
        new_quantity = item['quantity'] + quantity_to_add
        inventory_table.update_item(
            Key={'id': product_id},
            UpdateExpression="set quantity = :q",
            ExpressionAttributeValues={':q': new_quantity}
        )
        
        sns_msg = f"Product '{item['name']}' restocked by {quantity_to_add} units. New quantity: {new_quantity}"
        send_notification("Stock Restocked", sns_msg)
        
        # Record the restock activity in Inventory table as 'restock' record
        restock_id = str(uuid.uuid4())
        restock_record = {
            'id': restock_id,
            'record_type': 'restock',
            'product_id': product_id,
            'product_name': item['name'],
            'quantity_added': quantity_to_add,
            'store_id': manager_store_id,
            'supplier_id': item['supplier_id'],
            'date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        }
        inventory_table.put_item(Item=restock_record)
        
        flash(f"Restocked {quantity_to_add} units for {item['name']}.", "success")
    
    return redirect(url_for('manager_dashboard'))

@app.route('/manager/update_stock/<item_id>', methods=['POST'])
@login_required
@role_required('manager')
def update_stock(item_id):
    new_quantity = int(request.form['quantity'])
    
    response = inventory_table.get_item(Key={'id': item_id})
    item = response.get('Item')
    
    if item:
        inventory_table.update_item(
            Key={'id': item_id},
            UpdateExpression="set quantity = :q",
            ExpressionAttributeValues={':q': new_quantity}
        )
        
        if new_quantity < item['threshold']:
            msg = f"⚠️ Alert: {item['name']} is now Low Stock ({new_quantity} left)!"
            send_notification("Low Stock Alert", msg)
            flash(msg, "warning")
        else:
            flash(f"Stock updated for {item['name']}.", "success")
            
    return redirect(url_for('manager_dashboard'))

@app.route('/manager/request_restock/<item_id>', methods=['POST'])
@login_required
@role_required('manager')
def request_restock(item_id):
    requested_qty = int(request.form.get('restock_qty', 50))
    
    response = inventory_table.get_item(Key={'id': item_id})
    item = response.get('Item')
    item_name = item['name'] if item else "Unknown"
    supplier_id = item['supplier_id'] if item else 0
    store_id = session.get('store_id')
            
    shipment_id = str(uuid.uuid4())
    new_shipment = {
        'id': shipment_id,
        'record_type': 'shipment',
        'item_id': item_id,
        'item_name': item_name,
        'quantity': requested_qty,
        'status': 'Pending',
        'store_id': store_id,
        'supplier_id': supplier_id,
        'requested_by': session['name'],
        'date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    inventory_table.put_item(Item=new_shipment)
    
    send_notification("Restock Request Sent", f"Manager {session['name']} requested {requested_qty} units of {item_name}.")
    flash(f"Restock request sent for {item_name}.", "success")
    return redirect(url_for('manager_dashboard'))

# --- Supplier Routes ---
@app.route('/supplier')
@login_required
@role_required('supplier')
def supplier_dashboard():
    logged_in_supplier_id = session.get('supplier_id')
    
    # Filter inventory by supplier_id AND record_type='product'
    products = inventory_table.scan(
        FilterExpression=Attr('supplier_id').eq(logged_in_supplier_id) & Attr('record_type').eq('product')
    ).get('Items', [])
    
    # Filter shipments by supplier_id AND record_type='shipment'
    shipments = inventory_table.scan(
        FilterExpression=Attr('supplier_id').eq(logged_in_supplier_id) & Attr('record_type').eq('shipment')
    ).get('Items', [])
    
    stores = stores_table.scan().get('Items', [])
    
    supplier_inventory = []
    for item in products:
        store = next((s for s in stores if s['id'] == item['store_id']), {'name': 'Unknown'})
        item_copy = item.copy()
        item_copy['store_name'] = store['name']
        supplier_inventory.append(item_copy)
            
    return render_template('dashboard_supplier.html', inventory=supplier_inventory, shipments=shipments)

@app.route('/supplier/ship/<shipment_id>', methods=['POST'])
@login_required
@role_required('supplier')
def ship_order(shipment_id):
    # Update shipment status in DynamoDB
    try:
        inventory_table.update_item(
            Key={'id': shipment_id},
            UpdateExpression="set #s = :shipped_status",
            ExpressionAttributeNames={'#s': 'status'}, # 'status' is a reserved keyword in some contexts
            ExpressionAttributeValues={':shipped_status': 'Shipped'}
        )
        send_notification("Order Shipped", f"Supplier marked Shipment #{shipment_id} as Shipped.")
        flash(f"Order #{shipment_id} marked as Shipped.", "success")
    except ClientError as e:
        flash(f"Error updating shipment: {e.response['Error']['Message']}", "danger")
        
    return redirect(url_for('supplier_dashboard'))

# --- 6️⃣ AWS-READY APP RUNNER ---
if __name__ == '__main__':
    # Host 0.0.0.0 for external access on EC2
    # Port from environment or default to 5000
    PORT = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
