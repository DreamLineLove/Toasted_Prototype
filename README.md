# 🍞 Toasted ERP (v2.4 Prototype)

**Toasted ERP** is a role-based Enterprise Resource Planning prototype for the pharmaceutical industry. It covers the full lifecycle from drug formulation research through production, quality release, logistics, and customer order fulfillment — with each role strictly scoped to its functional requirements.

---

## 📸 Preview

<p align="center">
  <img src="https://github.com/user-attachments/assets/9fe1cfd0-b42d-4390-91bf-2ae8c0446966"
       alt="Login page"
       style="max-width: 700px; width: 100%; height: auto; border-radius: 8px;">
</p>
<p align="center">
  <img src="https://github.com/user-attachments/assets/7629cab8-f8a3-42d6-b8c8-a07d6bc8bf1c"
       alt="Production Manager page"
       style="max-width: 700px; width: 100%; height: auto; border-radius: 8px;">
</p>
<p align="center">
  <img src="https://github.com/user-attachments/assets/3ff78379-68ff-4a10-a907-f8193664738a"
       alt="Customer page"
       style="max-width: 700px; width: 100%; height: auto; border-radius: 8px;">
</p>

---

## 👥 Roles & Features

### 🔬 Researcher
- Submit new drug formulations (AES-256 encrypted payload, duplicate name prevented)
- View the formulation vault
- Search formulations by name

### 📊 Production Planner
- Demand forecasting based on monthly volume input

### 🏭 Production Manager
- Create production batches linked to a formulation
- Request raw materials linked to a specific batch (max 100,000 units)
- View all production batches and their status

### 🧪 Regulatory Affairs
- View production batches with linked formulation and material approval status
- Release (or withhold) batches based on full batch detail

### 📦 Warehouse Staff
- Review raw material requests submitted by Production Manager
- Approve requests (automatically deducts from inventory) or reject them
- Manage inventory stock levels (max ±100,000 per update)

### 🚚 Delivery Manager
- Schedule deliveries linked to approved customer orders (no past dates)
- Reschedule existing deliveries
- Assign transport vehicles to scheduled deliveries

### 🛒 Customer
- Register with establishment details (pharmacy/hospital name, email, phone, business license)
- Place orders from available inventory (max 100,000 units)
- Track delivery status including scheduled date and assigned transport
- Contact sales staff via chat
- View and edit registration details

### 💼 Sales Staff
- View and approve or reject customer orders
- Respond to customer chat messages

---

## 🔗 Connected Data Flow

```
Researcher submits Formulation
        ↓
Production Manager creates Batch → linked to Formulation
        ↓
Production Manager requests Raw Materials → linked to Batch
        ↓
Warehouse Staff reviews requests → Approve (deducts inventory) / Reject
        ↓
Regulatory Affairs reviews Batch → sees Formulation + material approval status → Release
        ↓
Delivery Manager schedules Delivery → picks an Approved customer order
        ↓
Customer tracks Delivery → sees scheduled date and transport vehicle
```

---

## 🔐 Security Features

- **Role-Based Access Control:** Every route is protected with a `@require_roles` decorator. Roles are strictly scoped — no cross-role access.
- **AES-256 Encryption:** Drug formulation payloads are encrypted at rest. Only Researchers can decrypt them.
- **Audit Logging:** All significant actions (batch creation, material requests, inventory changes, order approvals, deliveries) are logged with actor, role, and timestamp.
- **Input Validation:** Duplicate names/IDs are blocked at submission. Quantity limits enforced at both frontend and backend. Past delivery dates rejected.
- **Multi-Role Authentication:** Separate accounts per role. Password reset requires username and role match.

---

## 🛠️ Tech Stack

- **Backend:** Python / Flask / SQLAlchemy / Flask-Babel
- **Database:** SQLite (auto-migrated on startup)
- **Frontend:** Jinja2 / Bootstrap 5 / Bootstrap Icons
- **Security:** bcrypt password hashing, AES-256-GCM encryption
- **i18n:** English / Thai (ภาษาไทย)

---

## 🔑 Demo Access

Select a role from the landing page and use:

- **Username:** `aaaa`
- **Password:** `aaaa`

> Customer accounts must be registered manually as they require establishment details.

---

## 🚀 Deployment

**Live Demo:** [toasted-prototype.onrender.com](https://toasted-prototype.onrender.com/)
> ⚠️ The app may take a few minutes to wake up on first load.

**Run locally:**
```bash
pip install -r requirements.txt
python main.py
```
