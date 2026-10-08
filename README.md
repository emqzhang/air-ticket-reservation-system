# air-ticket-reservation-system
Full stack secure and usable web application that implements a plane ticket reservation complete with authetication and user sessions, server-side validation of all inputs, and supports use cases for public users, customers, booking agents, and airline staff. Project in three stages: conceptual design (ER model) -> logical design (relational schema + SQL) -> a secure web application on top of that schema


**Tools/Languages:** Python, MySQL, Jinja2 / HTML, Flask, phpMyAdmin, Werkzeug


## Overview

The system serves four kinds of users, each with their own permissions and dashboards:

| Role | What they can do |
|---|---|
| **Public visitor** | Search upcoming flights by origin/destination airport, city, and date; look up the status of in-progress flights; register or sign in |
| **Customer** | View purchased flights with date and route filters; buy tickets with server-enforced capacity and pricing; review spending with a monthly breakdown |
| **Booking agent** | Book tickets on behalf of customers, only for airlines they are authorized for; view booked flights; see commission analytics and top-customer charts |
| **Airline staff (Admin)** | Add airports and airplanes, create flights, authorize booking agents for their airline |
| **Airline staff (Operator)** | Update flight statuses (upcoming, in-progress, delayed, on-time) |

All staff can also view their airline's flights for the next 30 days, passenger lists, any customer's travel history on their airline, and airline-wide analytics.

---

## Key Features

- **Role-based access control:** every protected route checks the session, and staff permissions (Admin vs. Operator) are re-read from the database on each request rather than trusted from the session alone.
- **Seat classes (design twist):** airplanes have multiple seat classes (e.g. Economy, Business), each with its own capacity and price factor. Tickets reserve a *class*, not an individual seat. Final price = base flight price × class price factor, computed on the server.
- **Capacity enforcement:** before every sale, the server counts tickets already sold in the chosen class and rejects the purchase if the class is full. Duplicate bookings of the same flight by the same customer are blocked.
- **Agent commissions:** agents earn a fixed 10% per ticket; 30-day totals, average commission per ticket, ticket counts, and top-5 customer charts are computed in SQL.
- **Airline analytics for staff:** top booking agents (by tickets and commission, by month and year), most frequent customer, tickets sold per month, delayed vs. on-time statistics, and top destinations over the last 3 months and year.
- **Spending reports:** default view shows 12-month spending with a 6-month bar chart; a custom date range gives a total and month-by-month chart, with empty months filled in.
- **Case-insensitive, validated input:** airline names, airport codes, flight numbers, phone numbers, passport dates, and dates of birth are validated server-side.

---

## Methodology

The project was built in three deliberate stages, each feeding the next.

### Part 1: Conceptual design (ER model)
Modeled the domain as an ER diagram with strong and weak entities (Airplane and Flight are weak entities owned by Airline). Key decisions:
- **Ticket purchase** is modeled as a ternary relationship (Customer–Ticket–Booking Agent) plus a binary direct-purchase relationship. A ticket is bought either directly or through an agent, never both, and always belongs to a customer.
- **Seat classes** are modeled with a `Class` entity and a `Has_class` relationship carrying a per-airplane seat count, so each ticket belongs to a class the airplane actually offers.
- **Two price concepts:** the advertised flight price versus the per-class ticket price actually charged.
- **Airports** are a separate entity with two relationships to Flight (departure and arrival).

### Part 2: Logical design and SQL
Translated the ER model to a relational schema with `PRIMARY KEY`, `FOREIGN KEY`, `UNIQUE`, `NOT NULL`, `CHECK`, and `ON DELETE / ON UPDATE` constraints. Tables include `Airline`, `Airport`, `Airplane`, `SeatClass`, `Flight`, `Customer`, `CustomerPhone`, `BookingAgent`, `AuthorizedFor`, `AirlineStaff`, `StaffPermissions`, and `Ticket`. Populated a test dataset covering multiple airlines, airports, flight statuses, and agent- and customer-purchased tickets, and wrote validation queries against it.

### Part 3: Web application
Implemented the full application on top of the schema, with a focus on security and server-side enforcement of business rules:

- **Authentication:** passwords stored as salted hashes (Werkzeug `generate_password_hash` / `check_password_hash`); never plain text.
- **Sessions:** Flask signed-cookie sessions with a 3-hour timeout; role and identifier stored at login and checked on every protected request.
- **SQL injection prevention:** every query uses parameterized statements (`%s` placeholders with PyMySQL), never string-formatted user input.
- **Transactions:** multi-step writes (customer registration, staff registration, adding an airplane with its seat classes) run inside explicit transactions with rollback on failure so partial data is never saved.
- **Server-side validation:** all business rules (authorization, capacity, duplicate checks, date and format checks) are enforced on the server; client-side checks are for usability only.
- **Login throttling:** repeated failed logins in a session are limited to five attempts.

---

## Results

- Implemented **all required use cases** across the four roles: 30+ routes, 25+ HTML templates, and roughly 2,200 lines of Flask code.
- Every user-facing feature is mapped to the exact SQL it issues (see [`DB_queries.pdf`](docs/DB_queries.pdf)), covering multi-table joins, subqueries with `LEFT JOIN`, aggregation (`SUM`, `AVG`, `COUNT`, `GROUP BY`), date arithmetic, and conditional aggregation for on-time vs. delayed statistics.
- Delivered the seat-class twist consistently across all three stages: ER diagram, SQL schema, and purchase logic in the app.
- Authorization is enforced per request, so for example agents cannot book flights for airlines they are not authorized for, and staff can only see passengers and customers tied to their own airline.

---

## Project Structure

```
.
├── app.py                 # Flask routes, business logic, and SQL queries
├── db.py                  # PyMySQL connection helper
├── config.py              # Secret key and DB settings (not committed; see setup)
├── requirements.txt
├── html-files/             # Jinja2 templates (base layout, dashboards, forms, analytics)
└── docs/
    ├── project_p1_ER.pdf                  # Part 1 ER diagram
    ├── Part_1_Writeup.pdf                 # Part 1 assumptions and rationale
    ├── project_p2_relational_schema.pdf   # Part 2 relational schema
    ├── DB_queries.pdf                     # Feature-to-query mapping
    └── code_manifest.pdf                  # File-by-file description
```

---

## Getting Started

**Prerequisites:** Python 3.9+, MySQL 8+

```bash
# 1. Clone and install dependencies
git clone <your-repo-url>
cd <repo-name>
pip install -r requirements.txt

# 2. Create the database and load the schema
mysql -u <user> -p -e "CREATE DATABASE air_ticket;"
mysql -u <user> -p air_ticket < sql/schema.sql
mysql -u <user> -p air_ticket < sql/sample_data.sql
```

Create a `config.py` in the project root:

```python
class Config:
    SECRET_KEY = "change-me-to-a-long-random-string"
    DB_HOST = "localhost"
    DB_PORT = 3306
    DB_USER = "<user>"
    DB_PASSWORD = "<password>"
    DB_NAME = "air_ticket"
```

Run the app:

```bash
flask --app app run
```

Then open http://127.0.0.1:5000.

> `config.py` holds credentials and should be listed in `.gitignore`.

---

# Security Implementations
* **Prevents SQL injections:** `cursor.execute(sql, (identifier,))` uses %s placeholders and passes user input separately as a tuple. PyMySQL sends the values safely as parameters.
* **Protected Sessions:** sessions do not store sensitive information; airline staff sessions are checked with `get_staff_context()` that queries the DB to fetch staff permissions instead of simply relying on `session["user_type"]`.
* **Timed-out Sessions:** current logged-in session automatically logs out after 3 hours with `App.permanent_session_lifetime = timedelta(hours=3)`.
* **Log-in Attempt Limits:** Limit the number of log-in attempts the user gets to five; prevents brute-force entries.
* **Database Transactions:** Commits and rollbacks for multi-step SQL inserts with `safe_rollback()` helper function; keeps flow atomic (all inserts succeed or none).

---

## Known Limitations and Next Steps

Being upfront about scope, here is what I would improve for a production deployment:

- Add **CSRF protection** (e.g. Flask-WTF) to all POST forms.
- Move **login throttling** from the session to the server (per-IP or per-account rate limiting), since session-based counters can be reset by clearing cookies.
- Generate **ticket IDs with `AUTO_INCREMENT`** or row locking instead of `MAX(ticket_id) + 1`, to eliminate a race condition under concurrent purchases.
- Wrap the purchase flow (capacity check + insert) in a single locked transaction (`SELECT ... FOR UPDATE`) so two simultaneous buyers cannot oversell a class.
- Add automated tests and a payment-processing integration.

---

## What I Learned

- Translating an ambiguous real-world domain into a clean ER model, then into a normalized relational schema with enforceable constraints.
- Writing non-trivial SQL (joins, aggregation, date logic) and pushing business logic into queries where it belongs.
- Designing web authentication and authorization properly: hashed passwords, signed sessions, parameterized queries, and per-request permission checks.
- Reasoning about concurrency and data integrity in a multi-user booking system.

---

## Course Context

Built for **CSCI-SHU 213 (Databases)**. The three project parts are documented in `docs/`.
