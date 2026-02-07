# project-nexus-online_polling_system

# Online Polling System (Flask)

A secure, role-based **Online Polling System** built with **Flask**, **PostgreSQL**, and **Swagger (Flasgger)**.  
The system supports OTP-based authentication, poll creation and management, voting, results aggregation, and full audit logging for administrative monitoring.

---

## 🚀 Features

### 🔐 Authentication & Authorization
- Email + Password authentication
- OTP-based login verification
- JWT-based authentication (Access & Refresh tokens)
- Role-Based Access Control (RBAC)
  - `VOTER`
  - `POLL_ADMIN`
  - `SYSTEM_ADMIN`

### 🗳️ Poll Management
- Create polls with multiple options
- Draft, publish, and close polls
- Update and delete polls (admin only)
- View poll details and options

### 🗳️ Voting
- Authenticated voting
- Anonymous voting support (optional)
- Prevent duplicate voting
- Vote status checks

### 📊 Results & Analytics
- Aggregated poll results
- Results hidden until poll is closed (integrity enforcement)
- Admins can view results at any time

### 🧾 Audit Logging & Monitoring
- Full audit trail of system actions
- Authentication events (login, logout, OTP)
- Poll and vote events
- Admin access to audit logs and system metrics

### 📚 API Documentation
- Interactive Swagger UI via **Flasgger**
- Consistent request/response formats
- Predictable error handling

---

## 🛠️ Technology Stack

| Layer | Technology |
|-----|------------|
| Backend | Flask (Application Factory Pattern) |
| Database | PostgreSQL |
| ORM | Flask-SQLAlchemy |
| Migrations | Flask-Migrate (Alembic) |
| Auth | Flask-JWT-Extended |
| Validation | Marshmallow |
| Email | Flask-Mail |
| API Docs | Flasgger (Swagger UI) |
| Logging | Python logging + Audit Logs |

---

## 📂 Project Structure

## poll_demo/
├── app/ │ ├── api/ │ │ ├── auth/ │ │ ├── polls/ │ │ ├── voting/ │ │ ├── 
results/ │ │ └── admin/ │ ├── models/ │ ├── schemas/ │ ├── utils/ │ ├── 
extensions.py │ ├── swagger_config.py │ ├── config.py │ └── init.py ├── 
migrations/ ├── wsgi.py ├── .env ├── requirements.txt └── README.md


## 🗂️ Database Design (ERD)

The system uses a relational PostgreSQL database designed to ensure
data integrity, security, and scalability.

The Entity Relationship Diagram (ERD) illustrates the relationships
between users, polls, options, votes, OTP challenges, and audit logs.

🔗 **View ERD Diagram**  
https://drive.google.com/file/d/1ef4R6Xa1oOmJ0VHISgtKak8oFFy2bVFN/view?usp=sharing

