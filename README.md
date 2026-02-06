# StyleLane – AWS Cloud-Based Inventory Management System

StyleLane is a **cloud-based inventory and supplier management system** built using **Flask** and **AWS services**.  
It supports **role-based access** for Admin, Manager, and Supplier with real-time inventory tracking and notifications.

---

## 🚀 Features

### 👑 Admin
- Manage stores and suppliers
- View complete inventory across all stores
- Monitor low-stock products
- Generate inventory & stock reports

### 🏬 Manager
- Add and manage products for assigned store
- Restock products
- Request restock from suppliers
- Receive low-stock alerts

### 🚚 Supplier
- View shipment requests
- Update shipment status (Pending → Shipped)
- Track products supplied to stores

---

## 🛠️ Tech Stack

- **Backend:** Flask (Python)
- **Frontend:** HTML, CSS (Jinja Templates)
- **Database:** AWS DynamoDB
- **Notifications:** AWS SNS
- **Authentication:** Flask Sessions
- **Cloud Platform:** AWS
- **Version Control:** Git & GitHub

---

## 📂 Project Structure

stylelane-aws-project/
│
├── app.py # Local Flask app
├── aws_app.py # AWS-integrated Flask app
├── requirements.txt # Python dependencies
├── static/
│ └── css/style.css
├── templates/
│ ├── dashboard_admin.html
│ ├── dashboard_manager.html
│ ├── dashboard_supplier.html
│ ├── login.html
│ ├── signup.html
│ └── ...
└── .gitignore
