from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import datetime

app = Flask(__name__)
app.secret_key = 'stylelane_secret_key_dev_only'  # Change for production

# --- In-Memory Data Storage ---

# Users: Simulating User Table
# Roles: 'admin', 'manager', 'supplier'
users = [
    {
        'id': 1,
        'name': 'Admin User',
        'email': 'admin@stylelane.com',
        'password': generate_password_hash('admin123'),
        'role': 'admin'
    },
    {
        'id': 2,
        'name': 'Store Manager NYC',
        'email': 'manager@stylelane.com',
        'password': generate_password_hash('manager123'),
        'role': 'manager',
        'location': 'New York Flagship',
        'store_id': 1
    },
    {
        'id': 3,
        'name': 'Fashion Supplier Inc.',
        'email': 'supplier@stylelane.com',
        'password': generate_password_hash('supplier123'),
        'role': 'supplier',
        'supplier_id': 1
    }
]

# Stores
stores = [
    {'id': 1, 'name': 'New York Flagship', 'location': '5th Ave, NYC'},
    {'id': 2, 'name': 'Paris Boutique', 'location': 'Champs-Élysées, Paris'},
]

# Suppliers
suppliers = [
    {'id': 1, 'name': 'Fashion Supplier Inc.', 'contact': 'contact@fashionsupplier.com'},
    {'id': 2, 'name': 'Global Textiles Ltd.', 'contact': 'info@globaltextiles.com'},
]

# Inventory: Simulating Product/Inventory Table
# Updated with store_id and supplier_id
inventory = [
    {'id': 101, 'name': 'Classic Trench Coat', 'category': 'Outerwear', 'size': 'M', 'quantity': 45, 'price': 129.99, 'threshold': 10, 'store_id': 1, 'supplier_id': 1},
    {'id': 102, 'name': 'Slim Fit Jeans', 'category': 'Denim', 'size': '32', 'quantity': 8, 'price': 59.99, 'threshold': 15, 'store_id': 1, 'supplier_id': 2},
    {'id': 103, 'name': 'Silk Blouse', 'category': 'Tops', 'size': 'S', 'quantity': 25, 'price': 89.90, 'threshold': 5, 'store_id': 2, 'supplier_id': 1},
    {'id': 104, 'name': 'Leather Ankle Boots', 'category': 'Footwear', 'size': '8', 'quantity': 12, 'price': 149.00, 'threshold': 8, 'store_id': 2, 'supplier_id': 2},
]

# Shipments: Simulating Orders/Restock Requests (Marked for Future Scope in Phase 1 Admin)
shipments = []
shipment_counter = 1

# Restock Records: Phase 1 Manager Manual Record
restock_records = []

# --- Helper Functions & Decorators ---

def get_user_by_email(email):
    for user in users:
        if user['email'] == email:
            return user
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
                return redirect(url_for('dashboard')) # Redirect to their own dashboard
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Routes ---

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
            session['user_id'] = user['id']
            session['name'] = user['name']
            session['role'] = user['role']
            session['location'] = user.get('location', 'Global')
            session['store_id'] = user.get('store_id') # Store Manager's Assigned Store
            session['supplier_id'] = user.get('supplier_id') # Supplier's ID
            
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
        role = request.form.get('role', 'manager') # Default to manager for demo
        
        if get_user_by_email(email):
            flash("Email already registered.", "warning")
        else:
            new_id = users[-1]['id'] + 1 if users else 1
            new_user = {
                'id': new_id,
                'name': name,
                'email': email,
                'password': generate_password_hash(password),
                'role': role,
                'location': 'New Location' if role == 'manager' else 'Global'
            }
            users.append(new_user)
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))
            
    return render_template('signup.html')

@app.route('/logout')
def logout():
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

# --- Admin Routes ---
@app.route('/admin')
@login_required
@role_required('admin')
def admin_dashboard():
    low_stock_count = len([item for item in inventory if item['quantity'] < item['threshold']])
    total_managers = len([u for u in users if u['role'] == 'manager'])
    total_suppliers = len([u for u in users if u['role'] == 'supplier'])
    
    return render_template('dashboard_admin.html', 
                           inventory=inventory, 
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
        store_id = int(request.form['store_id'])
        store_name = request.form['store_name']
        location = request.form['location']
        stores.append({'id': store_id, 'name': store_name, 'location': location})
        flash(f"Store '{store_name}' added successfully!", "success")
        return redirect(url_for('admin_stores'))
    return render_template('admin_stores.html', stores=stores)

@app.route('/admin/suppliers', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_suppliers():
    if request.method == 'POST':
        supplier_id = int(request.form['supplier_id'])
        supplier_name = request.form['supplier_name']
        contact = request.form['contact']
        suppliers.append({'id': supplier_id, 'name': supplier_name, 'contact': contact})
        flash(f"Supplier '{supplier_name}' added successfully!", "success")
        return redirect(url_for('admin_suppliers'))
    return render_template('admin_suppliers.html', suppliers=suppliers)

@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    managers = [u for u in users if u['role'] == 'manager']
    role_suppliers = [u for u in users if u['role'] == 'supplier']
    return render_template('admin_users.html', managers=managers, suppliers=role_suppliers)

@app.route('/admin/inventory')
@login_required
@role_required('admin')
def admin_inventory():
    # Helper to get store and supplier names
    enriched_inventory = []
    for item in inventory:
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
    # Inventory Report: Product, Store, Quantity
    inventory_report = []
    for item in inventory:
        store = next((s for s in stores if s['id'] == item['store_id']), {'name': 'Unknown'})
        inventory_report.append({
            'product': item['name'],
            'store': store['name'],
            'quantity': item['quantity']
        })
    
    # Stock Summary Report: Product, Total Quantity, Status
    stock_summary = []
    for item in inventory:
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
    # Filter inventory for manager's store_id
    manager_store_id = session.get('store_id')
    store_inventory = [item for item in inventory if item['store_id'] == manager_store_id]
    return render_template('dashboard_manager.html', inventory=store_inventory, suppliers=suppliers)

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

    new_id = max([item['id'] for item in inventory]) + 1 if inventory else 101
    new_product = {
        'id': new_id,
        'name': name,
        'category': category,
        'size': size,
        'quantity': initial_qty,
        'price': price,
        'threshold': threshold,
        'store_id': manager_store_id,
        'supplier_id': supplier_id
    }
    inventory.append(new_product)
    flash(f"Product '{name}' added successfully to your store.", "success")
    return redirect(url_for('manager_dashboard'))

@app.route('/manager/restock', methods=['POST'])
@login_required
@role_required('manager')
def restock_product():
    manager_store_id = session.get('store_id')
    product_id = int(request.form['product_id'])
    quantity = int(request.form['quantity'])
    supplier_id = int(request.form['supplier_id'])

    for item in inventory:
        if item['id'] == product_id:
            if item['store_id'] != manager_store_id:
                flash("Unauthorized: Product does not belong to your store.", "danger")
                return redirect(url_for('manager_dashboard'))
            
            item['quantity'] += quantity
            
            # Record the restock activity
            restock_records.append({
                'product_id': product_id,
                'product_name': item['name'],
                'quantity_added': quantity,
                'supplier_id': supplier_id,
                'date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            
            flash(f"Restocked {quantity} units for {item['name']}.", "success")
            break
    
    return redirect(url_for('manager_dashboard'))

@app.route('/manager/update_stock/<int:item_id>', methods=['POST'])
@login_required
@role_required('manager')
def update_stock(item_id):
    new_quantity = int(request.form['quantity'])
    
    for item in inventory:
        if item['id'] == item_id:
            item['quantity'] = new_quantity
            
            # Check for Low Stock
            if item['quantity'] < item['threshold']:
                flash(f"⚠️ Alert: {item['name']} is now Low Stock ({item['quantity']} left)!", "warning")
                # TODO: Trigger SNS here in Phase 2
            else:
                flash(f"Stock updated for {item['name']}.", "success")
            break
            
    return redirect(url_for('manager_dashboard'))

@app.route('/manager/request_restock/<int:item_id>', methods=['POST'])
@login_required
@role_required('manager')
def request_restock(item_id):
    global shipment_counter
    requested_qty = int(request.form.get('restock_qty', 50))
    
    item_name = "Unknown"
    for item in inventory:
        if item['id'] == item_id:
            item_name = item['name']
            break
            
    new_shipment = {
        'id': shipment_counter,
        'item_id': item_id,
        'item_name': item_name,
        'quantity': requested_qty,
        'status': 'Pending',
        'requested_by': session['name'],
        'date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    shipments.append(new_shipment)
    shipment_counter += 1
    
    flash(f"Restock request sent for {item_name}.", "success")
    return redirect(url_for('manager_dashboard'))

# --- Supplier Routes ---
@app.route('/supplier')
@login_required
@role_required('supplier')
def supplier_dashboard():
    # Filter inventory by the logged-in supplier's ID
    logged_in_supplier_id = session.get('supplier_id')
    
    supplier_inventory = []
    for item in inventory:
        if item['supplier_id'] == logged_in_supplier_id:
            # Map store_id to store name
            store = next((s for s in stores if s['id'] == item['store_id']), {'name': 'Unknown'})
            item_copy = item.copy()
            item_copy['store_name'] = store['name']
            supplier_inventory.append(item_copy)
            
    return render_template('dashboard_supplier.html', inventory=supplier_inventory)

@app.route('/supplier/ship/<int:shipment_id>', methods=['POST'])
@login_required
@role_required('supplier')
def ship_order(shipment_id):
    for shipment in shipments:
        if shipment['id'] == shipment_id:
            shipment['status'] = 'Shipped'
            flash(f"Order #{shipment_id} marked as Shipped.", "success")
            # TODO: Trigger SNS Email to Manager in Phase 2
            break
    return redirect(url_for('supplier_dashboard'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
