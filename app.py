from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_connection #importing connection function in db.py
from config import Config
from decimal import Decimal
from datetime import date, datetime, timedelta
import calendar
import re

app = Flask(__name__, template_folder="html-files") #creates flask app object
app.secret_key = Config.SECRET_KEY
app.permanent_session_lifetime = timedelta(hours=3) #session timeout after 3 hrs
'''flask sessions are stored client-side in broswer cookies but are cryptographically signed
using SECRET_KEY, meaning the browser can store the session cookie but the user cannot
edit the cookie without invalidating the signature'''

def is_not_future_date(date_string):
    parsed = parse_date(date_string)
    return parsed is not None and parsed <= date.today()

def safe_rollback(conn):
    """
    Roll back the current transaction if one has started.
    This prevents partial inserts when a multi-step write fails.
    """
    try:
        conn.rollback()
    except Exception:
        pass

def parse_date(date_string):
    """Safely parse YYYY-MM-DD input from HTML date fields."""
    try:
        return datetime.strptime(date_string, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None
    
def add_months(original_date, months):
    """Add or subtract months safely without external libraries."""
    month = original_date.month - 1 + months
    year = original_date.year + month // 12
    month = month % 12 + 1
    day = min(original_date.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)

def first_day_of_month(d):
    return date(d.year, d.month, 1)

def next_month(d):
    return add_months(d, 1)

def month_key(d):
    return d.strftime("%Y-%m")

def month_label(d):
    return d.strftime("%b %Y")

def build_month_buckets(start_date, end_date, db_rows):
    """
    Converts DB monthly totals into complete month buckets.
    Missing months become 0.00, so the chart never breaks.
    """
    totals_by_month = {}

    for row in db_rows:
        totals_by_month[row["month_key"]] = float(row["amount"] or 0)

    buckets = []
    current = first_day_of_month(start_date)
    last = first_day_of_month(end_date)

    while current <= last:
        key = month_key(current)
        amount = totals_by_month.get(key, 0.0)

        buckets.append({
            "month": key,
            "label": month_label(current),
            "amount": round(amount, 2)
        })

        current = next_month(current)

    max_amount = max([b["amount"] for b in buckets], default=0)

    for bucket in buckets:
        if max_amount > 0:
            bucket["percent"] = round((bucket["amount"] / max_amount) * 100, 2)
        else:
            bucket["percent"] = 0

    return buckets

def is_valid_phone_number(phone_number):
    """Allow only digits, plus signs, and hyphens."""
    return bool(re.fullmatch(r"[0-9+-]+", phone_number or ""))

def is_valid_airport_code(airport_code):
    """Airport codes must be exactly 3 letters."""
    return bool(re.fullmatch(r"[A-Za-z]{3}", airport_code or ""))

def is_future_date(date_string):
    parsed = parse_date(date_string)
    return parsed is not None and parsed > date.today()

def is_not_future_date(date_string):
    parsed = parse_date(date_string)
    return parsed is not None and parsed <= date.today()

def get_canonical_airline_name(cursor, airline_name):
    """
    Returns the exact airline name as stored in the Airline table.
    This prevents capitalization mismatches like:
    'american airlines' vs 'American Airlines'.
    """
    cursor.execute(
        """
        SELECT name
        FROM Airline
        WHERE LOWER(name) = LOWER(%s)
        """,
        (airline_name,)
    )
    row = cursor.fetchone()

    if not row:
        return None

    return row["name"]

def require_staff():
    if session.get("user_type") != "staff":
        return None
    return session.get("identifier")

def money(value):
    if value is None:
        return 0.0
    if isinstance(value, Decimal):
        return float(value)
    return float(value)    

def get_staff_context():
    """
    Returns staff profile + permissions.
    Also normalizes staff['airline_name'] to the exact canonical name
    stored in the Airline table.
    """
    username = require_staff()
    if not username:
        return None

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT username, airline_name, first_name, last_name
            FROM AirlineStaff
            WHERE username = %s
            """,
            (username,)
        )
        staff = cursor.fetchone()

        if not staff:
            return None

        canonical_airline_name = get_canonical_airline_name(cursor, staff["airline_name"])

        if not canonical_airline_name:
            return None

        staff["airline_name"] = canonical_airline_name

        cursor.execute(
            """
            SELECT permissions
            FROM StaffPermissions
            WHERE LOWER(airline_name) = LOWER(%s)
              AND staff_username = %s
            """,
            (canonical_airline_name, username)
        )
        permission_rows = cursor.fetchall()
        permissions = {row["permissions"] for row in permission_rows if row["permissions"]}

        staff["permissions"] = permissions
        staff["is_admin"] = "Admin" in permissions
        staff["is_operator"] = "Operator" in permissions

        return staff

    finally:
        cursor.close()
        conn.close()

@app.route("/") #when someone visits / run the home func
def home():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"]) #creates the /login route, allowing GET and POST req methods
def login():
    if request.method == "GET":
        session["failed_login_attempts"] = 0
        return render_template("login.html")

    identifier = request.form.get("identifier", "").strip()
    password = request.form.get("password", "")
    user_type = request.form.get("user_type", "").strip()

    if user_type in ("customer", "agent"):
        identifier = identifier.lower()

    if not identifier or not password or not user_type:
        flash("Please fill in all fields.")
        return render_template("login.html")

    failed_attempts = session.get("failed_login_attempts", 0) #tracking variable for number of incorrect logins

    if failed_attempts >= 5:
        flash("Too many failed login attempts. Reload the login page before trying again.")
        return render_template("login.html")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        user = None

        if user_type == "customer":
            sql = """
                SELECT email, password 
                FROM Customer 
                WHERE email = %s 
            """ #the %s prevents SQL injection
            cursor.execute(sql, (identifier,))
            user = cursor.fetchone()

        elif user_type == "agent":
            sql = """
                SELECT email, password
                FROM BookingAgent
                WHERE email = %s
            """
            cursor.execute(sql, (identifier,))
            user = cursor.fetchone()

        elif user_type == "staff":
            sql = """
                SELECT username, password
                FROM AirlineStaff
                WHERE username = %s
            """
            cursor.execute(sql, (identifier,))
            user = cursor.fetchone() #returns the first matching row from the result
            #if user exists, `user` becomes a dictionary {"email":"...", "password": "..."}
            #if no user match, `user` becomes None

        else:
            flash("Invalid user type.")
            return render_template("login.html")

        if user and check_password_hash(user["password"], password):
            session.clear()
            session.permanent = True
            session["failed_login_attempts"] = 0
            session["user_type"] = user_type #stores session role

            if user_type in ("customer", "agent"):
                session["identifier"] = user["email"]
            else:
                session["identifier"] = user["username"]

            flash("Login successful.")

            if user_type == "customer":
                return redirect(url_for("customer_dashboard"))
            elif user_type == "agent":
                return redirect(url_for("agent_dashboard"))
            else:
                return redirect(url_for("staff_dashboard"))

        session["failed_login_attempts"] = session.get("failed_login_attempts", 0) + 1
        attempts_left = max(0, 5 - session["failed_login_attempts"])
        flash(f"Invalid credentials. {attempts_left} attempt(s) remaining.")
        return render_template("login.html")

    finally:
        cursor.close()
        conn.close()


@app.route("/register/customer", methods=["GET", "POST"])
def register_customer(): #customer registration
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        building_number = request.form.get("building_number", "").strip()
        street = request.form.get("street", "").strip()
        city = request.form.get("city", "").strip()
        state = request.form.get("state", "").strip()
        phone_number = request.form.get("phone_number", "").strip()
        passport_number = request.form.get("passport_number", "").strip()
        passport_expiration = request.form.get("passport_expiration", "").strip()
        passport_country = request.form.get("passport_country", "").strip()
        date_of_birth = request.form.get("date_of_birth", "").strip()

        if not all([
            name, email, password, street, city, state,
            phone_number, passport_number, passport_expiration,
            passport_country, date_of_birth
        ]):
            flash("Please fill in all required fields.")
            return redirect(url_for("register_customer"))

        if not is_valid_phone_number(phone_number):
            flash("Phone number may only contain numbers, plus signs, and hyphens.")
            return redirect(url_for("register_customer"))

        if not is_future_date(passport_expiration):
            flash("Passport expiration date must be a valid future date.")
            return redirect(url_for("register_customer"))

        if not is_not_future_date(date_of_birth):
            flash("Date of birth must be a valid date that is not in the future.")
            return redirect(url_for("register_customer"))

        hashed_password = generate_password_hash(password)

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT email FROM Customer WHERE email = %s", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash("A customer with that email already exists.")
                return redirect(url_for("register_customer"))

            # TRANSACTION START:
            # Customer and CustomerPhone must be inserted together.
            conn.begin()

            insert_customer_sql = """
                INSERT INTO Customer
                (email, name, password, building_num, street, city, state,
                 passport_num, passport_exp_date, passport_country, date_of_birth)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """

            cursor.execute(insert_customer_sql, (
                email, name, hashed_password, building_number, street, city, state,
                passport_number, passport_expiration, passport_country, date_of_birth
            ))

            insert_phone_sql = """
                INSERT INTO CustomerPhone (customer_email, phone_num)
                VALUES (%s, %s)
            """

            cursor.execute(insert_phone_sql, (email, phone_number))

            conn.commit()

            flash("Customer registration successful. Please log in.")
            return redirect(url_for("login"))

        except Exception as e:
            safe_rollback(conn)
            flash(f"Customer registration failed. No partial customer record was saved. Error: {e}")
            return redirect(url_for("register_customer"))

        finally:
            cursor.close()
            conn.close()

    return render_template("register_customer.html")


@app.route("/register/agent", methods=["GET", "POST"])
def register_agent():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please fill in all required fields.")
            return redirect(url_for("register_agent"))

        hashed_password = generate_password_hash(password)

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT email FROM BookingAgent WHERE email = %s", (email,))
            existing_email = cursor.fetchone()

            if existing_email:
                flash("A booking agent with that email already exists.")
                return redirect(url_for("register_agent"))

            insert_agent_sql = """
                INSERT INTO BookingAgent (email, password)
                VALUES (%s, %s)
            """

            cursor.execute(insert_agent_sql, (email, hashed_password))

            flash("Booking agent registration successful. Please log in.")
            return redirect(url_for("login"))

        finally:
            cursor.close()
            conn.close()

    return render_template("register_agent.html")


@app.route("/register/staff", methods=["GET", "POST"])
def register_staff():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        airline_name = request.form.get("airline_name", "").strip()
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        date_of_birth = request.form.get("date_of_birth", "").strip()
        permission = request.form.get("permission", "").strip()

        if not all([username, password, airline_name, first_name, last_name, date_of_birth, permission]):
            flash("Please fill in all required fields.")
            return redirect(url_for("register_staff"))

        if not is_not_future_date(date_of_birth):
            flash("Date of birth must be a valid date that is not in the future.")
            return redirect(url_for("register_staff"))

        if permission not in ("Admin", "Operator"):
            flash("Invalid staff permission.")
            return redirect(url_for("register_staff"))

        hashed_password = generate_password_hash(password)

        conn = get_connection()
        cursor = conn.cursor()

        try:
            canonical_airline_name = get_canonical_airline_name(cursor, airline_name)

            if not canonical_airline_name:
                flash("That airline does not exist.")
                return redirect(url_for("register_staff"))

            cursor.execute(
                "SELECT username FROM AirlineStaff WHERE username = %s",
                (username,)
            )
            existing_staff = cursor.fetchone()

            if existing_staff:
                flash("That staff username already exists.")
                return redirect(url_for("register_staff"))

            # TRANSACTION START:
            # AirlineStaff and StaffPermissions must be inserted together.
            conn.begin()

            cursor.execute(
                """
                INSERT INTO AirlineStaff
                (username, password, airline_name, first_name, last_name, date_of_birth)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (username, hashed_password, canonical_airline_name, first_name, last_name, date_of_birth)
            )

            cursor.execute(
                """
                INSERT INTO StaffPermissions
                (airline_name, staff_username, permissions)
                VALUES (%s, %s, %s)
                """,
                (canonical_airline_name, username, permission)
            )

            conn.commit()

            flash("Airline staff registration successful. Please log in.")
            return redirect(url_for("login"))

        except Exception as e:
            safe_rollback(conn)
            flash(f"Airline staff registration failed. No partial staff record was saved. Error: {e}")
            return redirect(url_for("register_staff"))

        finally:
            cursor.close()
            conn.close()

    return render_template("register_staff.html")


@app.route("/search-flights", methods=["GET", "POST"])
def search_flights():
    flights = [] #creates empty to list to hold flight results to show to user
    searched = False

    if request.method == "POST": #the user must have filled out a form on webpage to get search results
        searched = True

        origin = request.form.get("origin", "").strip()
        destination = request.form.get("destination", "").strip()
        flight_date = request.form.get("flight_date", "").strip()

        has_origin = bool(origin)
        has_destination = bool(destination)
        has_date = bool(flight_date)

        # Rule 1:
        # User cannot search with only origin or only destination.
        # If one route endpoint is filled, both must be filled.
        if has_origin != has_destination:
            flash("Must choose arrival and departure airport.")
            return render_template(
                "search_flights.html",
                flights=[],
                searched=True
            )

        # Rule 2:
        # User must search by either:
        #   - both origin and destination
        #   - date only
        #   - both origin/destination plus date
        if not has_origin and not has_destination and not has_date:
            flash("Please enter both arrival and departure airport, or choose a departure date.")
            return render_template(
                "search_flights.html",
                flights=[],
                searched=True
            )

        conn = get_connection()
        cursor = conn.cursor()

        try:
            sql = """
                SELECT
                    f.flight_num,
                    f.airline_name,
                    f.airplane_id,
                    f.departure_airport,
                    dep.city AS departure_city,
                    f.arrival_airport,
                    arr.city AS arrival_city,
                    f.departure_time,
                    f.arrival_time,
                    f.price,
                    f.flight_status
                FROM Flight AS f
                JOIN Airport AS dep
                    ON f.departure_airport = dep.name
                JOIN Airport AS arr
                    ON f.arrival_airport = arr.name
                WHERE f.departure_time > NOW()
            """

            params = []

            # Rule 3:
            # If origin/destination are provided, allow searching by:
            #   - 3-letter airport code, ex. JFK
            #   - full city name, ex. New York
            #
            # LOWER(...) = LOWER(%s) makes the search case-insensitive.
            if has_origin and has_destination:
                sql += """
                    AND (
                        LOWER(f.departure_airport) = LOWER(%s)
                        OR LOWER(dep.city) = LOWER(%s)
                    )
                    AND (
                        LOWER(f.arrival_airport) = LOWER(%s)
                        OR LOWER(arr.city) = LOWER(%s)
                    )
                """
                params.extend([origin, origin, destination, destination])

            # Rule 4:
            # If date is provided, return flights departing on that date.
            # Still excludes already-departed flights because of f.departure_time > NOW().
            if has_date:
                parsed_flight_date = parse_date(flight_date)

                if not parsed_flight_date:
                    flash("Please enter a valid departure date.")
                    return render_template(
                        "search_flights.html",
                        flights=[],
                        searched=True
                    )

                # This prevents searching dates that are entirely in the past.
                if parsed_flight_date < date.today():
                    flash("Cannot search for flights that have already departed.")
                    return render_template(
                        "search_flights.html",
                        flights=[],
                        searched=True
                    )

                sql += """
                    AND DATE(f.departure_time) = %s
                """
                params.append(parsed_flight_date)

            # Rule 5:
            # Return first 10 upcoming matching flights in chronological order.
            sql += """
                ORDER BY f.departure_time ASC
                LIMIT 10
            """

            cursor.execute(sql, tuple(params))
            flights = cursor.fetchall()

            # Attach available seat classes to each flight.
            # This prevents the frontend from showing First/Business/Economy
            # when that airplane does not actually have those classes.
            for flight in flights:
                cursor.execute(
                    """
                    SELECT
                        sc.seat_class,
                        sc.capacity,
                        sc.price_factor,
                        COALESCE(sold_counts.sold, 0) AS sold
                    FROM SeatClass AS sc
                    LEFT JOIN (
                        SELECT
                            seat_class,
                            COUNT(*) AS sold
                        FROM Ticket
                        WHERE flight_num = %s
                        GROUP BY seat_class
                    ) AS sold_counts
                        ON LOWER(sold_counts.seat_class) = LOWER(sc.seat_class)
                    WHERE sc.airplane_id = %s
                    AND sc.capacity > COALESCE(sold_counts.sold, 0)
                    ORDER BY
                        CASE LOWER(sc.seat_class)
                            WHEN 'economy' THEN 1
                            WHEN 'business' THEN 2
                            WHEN 'first' THEN 3
                            ELSE 4
                        END
                    """,
                    (flight["flight_num"], flight["airplane_id"])
                )
                flight["seat_classes"] = cursor.fetchall()

        finally:
            cursor.close()
            conn.close()

    return render_template(
        "search_flights.html",
        flights=flights,
        searched=searched
    )


@app.route("/flight-status", methods=["GET", "POST"])
def flight_status():
    flight = None

    if request.method == "POST":
        airline_name = request.form.get("airline_name", "").strip().title()
        flight_num = request.form.get("flight_num", "").strip().upper()

        if not airline_name or not flight_num:
            flash("Please enter both airline and flight number.")
            return redirect(url_for("flight_status"))

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                SELECT
                    f.flight_num,
                    f.airline_name,
                    f.departure_airport,
                    dep.city AS departure_city,
                    f.arrival_airport,
                    arr.city AS arrival_city,
                    f.departure_time,
                    f.arrival_time,
                    f.flight_status
                FROM Flight AS f
                JOIN Airport AS dep
                    ON f.departure_airport = dep.name
                JOIN Airport AS arr
                    ON f.arrival_airport = arr.name
                WHERE LOWER(f.airline_name) = LOWER(%s)
                  AND UPPER(f.flight_num) = UPPER(%s)
                  AND f.flight_status = 'in-progress'
                """,
                (airline_name, flight_num)
            )

            flight = cursor.fetchone()

            if not flight:
                flash("No in-progress flight found for that airline and flight number.")

        finally:
            cursor.close()
            conn.close()

    return render_template("flight_status.html", flight=flight, #added for display purposes
                           searched=(request.method)=="POST")

@app.route("/agent/flights", methods=["GET", "POST"]) #shows flights that the agent booked for customers
def agent_flights():
    if session.get("user_type") != "agent":
        flash("Unauthorized.")
        return redirect(url_for("login"))

    email = session.get("identifier")

    start_date = request.form.get("start_date")
    end_date = request.form.get("end_date")
    origin = request.form.get("origin")
    destination = request.form.get("destination")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        sql = """
            SELECT f.*, t.customer_email, t.price_charged
            FROM Ticket t
            JOIN Flight f ON t.flight_num = f.flight_num
            WHERE t.agent_email = %s
        """

        params = [email]

        if start_date:
            sql += " AND DATE(f.departure_time) >= %s"
            params.append(start_date)

        if end_date:
            sql += " AND DATE(f.departure_time) <= %s"
            params.append(end_date)

        if origin:
            sql += " AND f.departure_airport = %s"
            params.append(origin)

        if destination:
            sql += " AND f.arrival_airport = %s"
            params.append(destination)

        cursor.execute(sql, tuple(params))
        flights = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return render_template("agent_flights.html", flights=flights)

@app.route("/customer/flights", methods=["GET", "POST"])
def view_customer_flights():
    if session.get("user_type") != "customer":
        flash("Please log in as a customer.")
        return redirect(url_for("login"))

    email = session.get("identifier")

    start_date = request.form.get("start_date")
    end_date = request.form.get("end_date")
    origin = request.form.get("origin")
    destination = request.form.get("destination")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        sql = """
            SELECT 
                f.flight_num,
                f.airline_name,
                f.departure_airport,
                f.arrival_airport,
                f.departure_time,
                f.arrival_time,
                t.price_charged
            FROM Ticket t
            JOIN Flight f ON t.flight_num = f.flight_num
            WHERE t.customer_email = %s
        """

        params = [email]

        if start_date:
            sql += " AND DATE(f.departure_time) >= %s"
            params.append(start_date)

        if end_date:
            sql += " AND DATE(f.departure_time) <= %s"
            params.append(end_date)

        if origin:
            sql += " AND f.departure_airport = %s"
            params.append(origin)

        if destination:
            sql += " AND f.arrival_airport = %s"
            params.append(destination)

        sql += " ORDER BY f.departure_time ASC"

        cursor.execute(sql, tuple(params))
        flights = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return render_template("customer_flights.html", flights=flights)

@app.route("/purchase/<flight_num>", methods=["POST"])
def purchase_ticket(flight_num):
    if session.get("user_type") != "customer":
        flash("Login as a customer to purchase.")
        return redirect(url_for("login"))

    email = session.get("identifier")
    seat_class = request.form.get("seat_class")

    if not seat_class:
        flash("Please select a seat class.")
        return redirect(url_for("search_flights"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # 🔹 Get airplane_id
        cursor.execute("""
            SELECT airplane_id FROM Flight WHERE flight_num = %s
        """, (flight_num,))
        flight = cursor.fetchone()

        if not flight:
            flash("Flight not found.")
            return redirect(url_for("search_flights"))
        
        #prevents the same customer from buying multiple tickets for the same flight
        cursor.execute(
            """
            SELECT ticket_id
            FROM Ticket
            WHERE customer_email = %s AND flight_num = %s
            """,
            (email, flight_num)
        )
        existing_ticket = cursor.fetchone()

        if existing_ticket:
            flash("You already have a ticket for this flight.")
            return redirect(url_for("search_flights"))

        airplane_id = flight["airplane_id"]

        # 🔹 Get seat class capacity + price factor
        cursor.execute("""
            SELECT capacity, price_factor
            FROM SeatClass
            WHERE airplane_id = %s AND seat_class = %s
        """, (airplane_id, seat_class))
        seat_info = cursor.fetchone()

        if not seat_info:
            flash("Invalid seat class.")
            return redirect(url_for("search_flights"))

        capacity = seat_info["capacity"]
        factor = seat_info["price_factor"]

        # 🔹 Count tickets sold for THIS class
        cursor.execute("""
            SELECT COUNT(*) AS sold
            FROM Ticket
            WHERE flight_num = %s AND seat_class = %s
        """, (flight_num, seat_class))
        sold = cursor.fetchone()["sold"]

        if sold >= capacity:
            flash(f"{seat_class.capitalize()} class is full.")
            return redirect(url_for("search_flights"))

        # 🔹 Get base price
        cursor.execute("""
            SELECT price FROM Flight WHERE flight_num = %s
        """, (flight_num,))
        base_price = cursor.fetchone()["price"]

        final_price = base_price * factor

        # 🔹 Generate UNIQUE ticket_id safely
        cursor.execute("SELECT MAX(ticket_id) AS max_id FROM Ticket")
        max_id = cursor.fetchone()["max_id"]

        ticket_id = (max_id or 0) + 1 #ensures no duplicate ticket IDS

        # 🔹 Insert ticket
        cursor.execute("""
            INSERT INTO Ticket
            (ticket_id, flight_num, customer_email, airplane_id, seat_class, price_charged, purchase_date)
            VALUES (%s, %s, %s, %s, %s, %s, CURDATE())
        """, (ticket_id, flight_num, email, airplane_id, seat_class, final_price))

        flash("Ticket purchased successfully!")

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("view_customer_flights"))


@app.route("/agent/book/<flight_num>", methods=["GET"])
def agent_book_flight(flight_num):
    if session.get("user_type") != "agent":
        flash("Please log in as a booking agent.")
        return redirect(url_for("login"))

    agent_email = session.get("identifier")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT
                f.flight_num,
                f.airline_name,
                f.airplane_id,
                f.departure_airport,
                dep.city AS departure_city,
                f.arrival_airport,
                arr.city AS arrival_city,
                f.departure_time,
                f.arrival_time,
                f.price,
                f.flight_status
            FROM Flight AS f
            JOIN Airport AS dep
                ON f.departure_airport = dep.name
            JOIN Airport AS arr
                ON f.arrival_airport = arr.name
            WHERE f.flight_num = %s
            """,
            (flight_num,)
        )
        flight = cursor.fetchone()

        if not flight:
            flash("Flight not found.")
            return redirect(url_for("search_flights"))

        if flight["departure_time"] <= datetime.now():
            flash("Cannot book a flight that has already departed.")
            return redirect(url_for("search_flights"))

        if flight["flight_status"] in ("cancelled", "completed"):
            flash("Cannot book a cancelled or completed flight.")
            return redirect(url_for("search_flights"))

        cursor.execute(
            """
            SELECT agent_email
            FROM AuthorizedFor
            WHERE agent_email = %s
              AND airline_name = %s
            """,
            (agent_email, flight["airline_name"])
        )

        if not cursor.fetchone():
            flash("You are not authorized to book flights for this airline.")
            return redirect(url_for("search_flights"))

        cursor.execute(
            """
            SELECT
                sc.seat_class,
                sc.capacity,
                sc.price_factor,
                COALESCE(sold_counts.sold, 0) AS sold
            FROM SeatClass AS sc
            LEFT JOIN (
                SELECT
                    seat_class,
                    COUNT(*) AS sold
                FROM Ticket
                WHERE flight_num = %s
                GROUP BY seat_class
            ) AS sold_counts
                ON LOWER(sold_counts.seat_class) = LOWER(sc.seat_class)
            WHERE sc.airplane_id = %s
              AND sc.capacity > COALESCE(sold_counts.sold, 0)
            ORDER BY
                CASE LOWER(sc.seat_class)
                    WHEN 'economy' THEN 1
                    WHEN 'business' THEN 2
                    WHEN 'first' THEN 3
                    ELSE 4
                END
            """,
            (flight_num, flight["airplane_id"])
        )
        seat_classes = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "agent_book_flight.html",
        flight=flight,
        seat_classes=seat_classes,
        agent_email=agent_email
    )


@app.route("/agent/purchase/<flight_num>", methods=["POST"]) #creates a specific url for booking agents to purchase a ticket for a specific flight
def agent_purchase(flight_num): #POST means this route only runs when a form submits data, not when someone casually visits the URL
    if session.get("user_type") != "agent": #ensures that user is a booking agent
        flash("Unauthorized.")
        return redirect(url_for("login"))
    #backend blocks someone from accessing the agent purchase route if URL is manually typed in
    #server enforces role permissions

    agent_email = session.get("identifier")
    customer_email = (request.form.get("customer_email") or "").strip().lower() #or "" prevents crashes from missing fields
    seat_class = (request.form.get("seat_class") or "").strip().lower() #None.lower() causes an error, ^ prevents it

    if not customer_email or not seat_class:
        flash("Missing customer email or seat class.")
        return redirect(url_for("agent_book_flight", flight_num=flight_num))

    conn = get_connection()
    cursor = conn.cursor()

    try: #enclose all SQL queries inside try block so that the DB connection still closes with the 'finally' keyword, regardless of what occured in try block
        cursor.execute( #check that customer exists
            """
            SELECT email
            FROM Customer
            WHERE email = %s
            """,
            (customer_email,) #%s placeholder, prevents SQL injection
        )
        if not cursor.fetchone():
            flash("Customer does not exist.")
            return redirect(url_for("agent_book_flight", flight_num=flight_num))

        cursor.execute( #fetches the flight being purchased
            """
            SELECT flight_num, airline_name, airplane_id, price, departure_time
            FROM Flight
            WHERE flight_num = %s
            """,
            (flight_num,)
        )
        flight = cursor.fetchone()

        if not flight: #FIRST checks whether flight even exists to prevent later code like flight['airplane_id'] from executing and crashing
            flash("Flight not found.")
            return redirect(url_for("search_flights"))
        
        # Prevent the same customer from having multiple tickets for the same flight,
        # even if a booking agent is buying on their behalf.
        cursor.execute(
            """
            SELECT ticket_id
            FROM Ticket
            WHERE customer_email = %s
            AND flight_num = %s
            """,
            (customer_email, flight_num)
        )
        existing_ticket = cursor.fetchone()

        if existing_ticket:
            flash("This customer already has a ticket for this flight.")
            return redirect(url_for("search_flights"))

        #enforces business rule on the server side: even if frontend accidentally shows an old flight, backend refuses to sell it
        if flight["departure_time"] <= datetime.now(): #no booking already departed flights
            flash("Cannot book a flight that has already departed.")
            return redirect(url_for("search_flights"))

        cursor.execute( #checks agent authorization for specific airline being booked
            """
            SELECT agent_email
            FROM AuthorizedFor
            WHERE agent_email = %s
              AND airline_name = %s
            """,
            (agent_email, flight["airline_name"])
        )
        if not cursor.fetchone():
            flash("You are not authorized for this airline.")
            return redirect(url_for("search_flights"))

        cursor.execute( #checks if selected seat class exists for the airplane used by this flight
            """
            SELECT capacity, price_factor
            FROM SeatClass
            WHERE airplane_id = %s
              AND LOWER(seat_class) = LOWER(%s)
            """,
            (flight["airplane_id"], seat_class)
        )
        seat_info = cursor.fetchone()

#enforces seat class availability; cannot buy first class if plane only has economy seats
        if not seat_info:
            flash("Invalid seat class for this flight.")
            return redirect(url_for("agent_book_flight", flight_num=flight_num))

        cursor.execute( #counts sold tickets for this flight and seat class
            """
            SELECT COUNT(*) AS sold
            FROM Ticket
            WHERE flight_num = %s
              AND LOWER(seat_class) = LOWER(%s)
            """,
            (flight_num, seat_class)
        )
        sold = int(cursor.fetchone()["sold"] or 0) #number of tickets sold for that exact class

        capacity = int(seat_info["capacity"] or 0) #max number of seats allowed for that class
#the or 0 in both statements prevents problems if the DB unexpectedly returns NULL

        if sold >= capacity: #block purchase if sold tickets are greater than/equal to class capacity
            flash(f"{seat_class.capitalize()} class is full.") #server-side enforcement of business logic
            return redirect(url_for("search_flights"))

        final_price = round(float(flight["price"]) * float(seat_info["price_factor"]), 2) #round(..., 2) keeps it to currency format
        #final price = base flight price * seat class price factor

        #generates ticket ID by finding current largest ticket ID and adding 1
        cursor.execute("SELECT COALESCE(MAX(ticket_id), 0) + 1 AS next_id FROM Ticket")
        ticket_id = cursor.fetchone()["next_id"]
        #if MAX(ticket_id) = NULL, coalesce turns that into 0, then adds a 1 to it

        cursor.execute( #creates a new row in table Ticket
            """
            INSERT INTO Ticket
            (ticket_id, flight_num, customer_email, agent_email,
             airplane_id, seat_class, price_charged, purchase_date)
            VALUES (%s, %s, %s, %s, %s, %s, %s, CURDATE()) 
            """, #CURDATE() returns current date and inserts it into the purchase date column of DB
            (
                ticket_id,
                flight_num,
                customer_email,
                agent_email,
                flight["airplane_id"],
                seat_class,
                final_price
            )
        )

        flash( #shows success message
            f"Ticket booked successfully for {customer_email}. "
            f"Price charged: ${final_price:.2f}. "
            f"Estimated commission: ${final_price * 0.10:.2f}."
        )

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("agent_flights"))

@app.route("/customer/spending", methods=["GET", "POST"])
def customer_spending():
    if session.get("user_type") != "customer":
        flash("Please log in as a customer.")
        return redirect(url_for("login"))

    customer_email = session.get("identifier")
    today = date.today()

    is_custom = False
    start_date = None
    end_date = None

    if request.method == "POST":
        raw_start = request.form.get("start_date", "").strip()
        raw_end = request.form.get("end_date", "").strip()

        start_date = parse_date(raw_start)
        end_date = parse_date(raw_end)

        if not start_date or not end_date:
            flash("Please enter a valid start date and end date.")
            return redirect(url_for("customer_spending"))

        if start_date > end_date:
            flash("Start date cannot be after end date.")
            return redirect(url_for("customer_spending"))

        is_custom = True

    else:
        # Default total: last 12 months
        start_date = add_months(today, -12)
        end_date = today

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Total spending for selected range.
        cursor.execute(
            """
            SELECT COALESCE(SUM(price_charged), 0) AS total_spending
            FROM Ticket
            WHERE customer_email = %s
              AND purchase_date BETWEEN %s AND %s
            """,
            (customer_email, start_date, end_date)
        )
        total_row = cursor.fetchone()
        total_spending = float(total_row["total_spending"] or 0)

        # Chart range:
        # Default = last 6 months.
        # Custom = full selected date range, month by month.
        if is_custom:
            chart_start = start_date
            chart_end = end_date
        else:
            chart_start = first_day_of_month(add_months(today, -5))
            chart_end = today

        cursor.execute(
            """
            SELECT
                DATE_FORMAT(purchase_date, '%%Y-%%m') AS month_key,
                COALESCE(SUM(price_charged), 0) AS amount
            FROM Ticket
            WHERE customer_email = %s
              AND purchase_date BETWEEN %s AND %s
            GROUP BY DATE_FORMAT(purchase_date, '%%Y-%%m')
            ORDER BY month_key
            """,
            (customer_email, chart_start, chart_end)
        )
        monthly_rows = cursor.fetchall()

        monthly_spending = build_month_buckets(chart_start, chart_end, monthly_rows)

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "customer_spending.html",
        total_spending=round(total_spending, 2),
        monthly_spending=monthly_spending,
        chart_labels=[item["label"] for item in monthly_spending],
        chart_values=[item["amount"] for item in monthly_spending],
        start_date=start_date,
        end_date=end_date,
        is_custom=is_custom
    )

@app.route("/logout") #creates a route for logging out  
def logout(): 
    session.clear() #clears all session data; meaning user no longer is considered logged in
    flash("Logged out.")
    return redirect(url_for("home")) #sends user back to home page

@app.route("/customer/dashboard") #creates customer dashboard route
def customer_dashboard():
    if session.get("user_type") != "customer": #checks wheter logged-in user is actually a customer
        #session.get() safely retrieves the value w/o crashing if val DNE
        flash("Please log in as a customer.") #if not customer, take them to login page
        return redirect(url_for("login"))

    return render_template("customer_dashboard.html") #if above checks pass, show customer dashboard page

@app.route("/agent/dashboard")
def agent_dashboard():
    if session.get("user_type") != "agent": #only booking agents can access booking agent dash
        flash("Please log in as a booking agent.")
        return redirect(url_for("login"))

    return render_template("agent_dashboard.html")

@app.route("/agent/analytics")
def agent_analytics():
    if session.get("user_type") != "agent": #customers and staff cannot access booking agent page
        flash("Please log in as a booking agent.")
        return redirect(url_for("login"))

    email = session.get("identifier") #gets the logged-in agent's email from the session

    conn = get_connection() #connects flask to mySQL so python can run SQL queries
    cursor = conn.cursor() #creates a cursor for python to run sql stuff

    try: #calculates the last 30 days stats for the booking agent
        cursor.execute("""
            SELECT 
                COALESCE(SUM(price_charged * 0.10), 0) AS total_commission,
                COALESCE(AVG(price_charged * 0.10), 0) AS avg_commission,
                COUNT(*) AS tickets
            FROM Ticket
            WHERE agent_email = %s
              AND purchase_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        """, (email,))
        stats = cursor.fetchone() #coalesce(...) prevents None vals when agent has no sales

        #finds the top 5 customers by no of tickets bought through this agent in the last 6 months
        cursor.execute("""
            SELECT customer_email, COUNT(*) AS count
            FROM Ticket
            WHERE agent_email = %s
              AND purchase_date >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
            GROUP BY customer_email
            ORDER BY count DESC
            LIMIT 5
        """, (email,))
        top_tickets = cursor.fetchall()

        #find this agent's top 5 customers by commission generated in the last 12 months
        cursor.execute("""
            SELECT customer_email, SUM(price_charged * 0.10) AS total
            FROM Ticket
            WHERE agent_email = %s
              AND purchase_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
            GROUP BY customer_email
            ORDER BY total DESC
            LIMIT 5
        """, (email,)) #the commission is dynamically calculated
        top_commission = cursor.fetchall()

    finally:
        cursor.close()
        conn.close() #closes the DB connection

    return render_template( #sends the analytics data to agent_analytics.html
        "agent_analytics.html",
        stats=stats,
        top_ticket_labels=[x["customer_email"] for x in top_tickets],
        top_ticket_values=[int(x["count"] or 0) for x in top_tickets],
        top_comm_labels=[x["customer_email"] for x in top_commission],
        top_comm_values=[float(x["total"] or 0) for x in top_commission]
    )

@app.route("/staff/dashboard", methods=["GET", "POST"])
def staff_dashboard():
    staff = get_staff_context() 
    '''this method uses the session username to query the DB and fetch staff
    permissions, does not just rely on session['user_type']'''

    if not staff:
        flash("Please log in as airline staff.")
        return redirect(url_for("login"))

    airline_name = staff["airline_name"]

    start_date = None
    end_date = None
    origin = ""
    destination = ""

    if request.method == "POST":
        start_date = parse_date(request.form.get("start_date", "").strip())
        end_date = parse_date(request.form.get("end_date", "").strip())
        origin = request.form.get("origin", "").strip()
        destination = request.form.get("destination", "").strip()

        if request.form.get("start_date") and not start_date:
            flash("Invalid start date.")
            return redirect(url_for("staff_dashboard"))

        if request.form.get("end_date") and not end_date:
            flash("Invalid end date.")
            return redirect(url_for("staff_dashboard"))

        if start_date and end_date and start_date > end_date:
            flash("Start date cannot be after end date.")
            return redirect(url_for("staff_dashboard"))

    conn = get_connection()
    cursor = conn.cursor()

    try: #the default staff view is airline flights in the next 30 days
        sql = """
            SELECT
                f.flight_num,
                f.airline_name,
                f.departure_airport,
                dep.city AS departure_city,
                f.arrival_airport,
                arr.city AS arrival_city,
                f.departure_time,
                f.arrival_time,
                f.price,
                f.flight_status,
                f.airplane_id
            FROM Flight AS f
            JOIN Airport AS dep
                ON dep.name = f.departure_airport
            JOIN Airport AS arr
                ON arr.name = f.arrival_airport
            WHERE LOWER(f.airline_name) = LOWER(%s)
        """

        params = [airline_name]

        if start_date:
            sql += " AND DATE(f.departure_time) >= %s"
            params.append(start_date)
        else:
            sql += " AND f.departure_time >= NOW()"

        if end_date:
            sql += " AND DATE(f.departure_time) <= %s"
            params.append(end_date)
        else:
            sql += " AND f.departure_time < DATE_ADD(NOW(), INTERVAL 30 DAY)"

        if origin:
            sql += """
                AND (
                    f.departure_airport = %s
                    OR dep.city = %s
                )
            """
            params.extend([origin, origin])

        if destination:
            sql += """
                AND (
                    f.arrival_airport = %s
                    OR arr.city = %s
                )
            """
            params.extend([destination, destination])

        sql += " ORDER BY f.departure_time ASC"

        cursor.execute(sql, tuple(params))
        flights = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "staff_dashboard.html",
        staff=staff,
        flights=flights,
        start_date=start_date,
        end_date=end_date,
        origin=origin,
        destination=destination
    )

@app.route("/staff/customer-flights", methods=["GET", "POST"]) #view all flights taken by a specific customer on staff's airline
def staff_customer_flights():
    staff = get_staff_context()

    if not staff:
        flash("Please log in as airline staff.")
        return redirect(url_for("login"))

    customer_email = ""
    flights = []
    searched = False

    if request.method == "POST":
        searched = True
        customer_email = request.form.get("customer_email", "").strip()

        if not customer_email:
            flash("Please enter a customer email.")
            return redirect(url_for("staff_customer_flights"))

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT email, name FROM Customer WHERE email = %s", (customer_email,))
            customer = cursor.fetchone()

            if not customer:
                flash("No customer exists with that email.")
                return render_template(
                    "staff_customer_flights.html",
                    staff=staff,
                    customer_email=customer_email,
                    flights=[],
                    searched=True
                )

            cursor.execute(
                """
                SELECT
                    f.flight_num,
                    f.airline_name,
                    f.departure_airport,
                    f.arrival_airport,
                    f.departure_time,
                    f.arrival_time,
                    f.flight_status,
                    t.ticket_id,
                    t.seat_class,
                    t.price_charged,
                    t.purchase_date
                FROM Ticket AS t
                JOIN Flight AS f
                    ON f.flight_num = t.flight_num
                WHERE t.customer_email = %s
                  AND LOWER(f.airline_name) = LOWER(%s)
                ORDER BY f.departure_time DESC
                """,
                (customer_email, staff["airline_name"])
            )
            flights = cursor.fetchall()

        finally:
            cursor.close()
            conn.close()

    return render_template(
        "staff_customer_flights.html",
        staff=staff,
        customer_email=customer_email,
        flights=flights,
        searched=searched
    )


@app.route("/staff/flight/<flight_num>/passengers") #passenger list
def staff_passenger_list(flight_num):
    staff = get_staff_context()

    if not staff:
        flash("Please log in as airline staff.")
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT flight_num, airline_name, departure_airport, arrival_airport, departure_time
            FROM Flight
            WHERE flight_num = %s
              AND LOWER(airline_name) = LOWER(%s)
            """,
            (flight_num, staff["airline_name"])
        )
        flight = cursor.fetchone()

        if not flight:
            flash("Flight not found for your airline.")
            return redirect(url_for("staff_dashboard"))

        cursor.execute(
            """
            SELECT
                c.email,
                c.name,
                c.passport_num,
                c.passport_country,
                t.ticket_id,
                t.seat_class,
                t.price_charged,
                t.purchase_date,
                t.agent_email
            FROM Ticket AS t
            JOIN Customer AS c
                ON c.email = t.customer_email
            WHERE t.flight_num = %s
            ORDER BY c.name, c.email
            """,
            (flight_num,)
        )
        passengers = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "staff_passengers.html",
        staff=staff,
        flight=flight,
        passengers=passengers
    )

@app.route("/staff/analytics")
def staff_analytics():
    staff = get_staff_context()

    if not staff:
        flash("Please log in as airline staff.")
        return redirect(url_for("login"))

    airline_name = staff["airline_name"]

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Top booking agents this month by tickets.
        cursor.execute(
            """
            SELECT
                t.agent_email,
                COUNT(*) AS tickets_sold,
                COALESCE(SUM(t.price_charged * 0.10), 0) AS commission
            FROM Ticket AS t
            JOIN Flight AS f
                ON f.flight_num = t.flight_num
            WHERE LOWER(f.airline_name) = LOWER(%s)
              AND t.agent_email IS NOT NULL
              AND YEAR(t.purchase_date) = YEAR(CURDATE())
              AND MONTH(t.purchase_date) = MONTH(CURDATE())
            GROUP BY t.agent_email
            ORDER BY tickets_sold DESC
            LIMIT 5
            """,
            (airline_name,)
        )
        top_agents_month_tickets = cursor.fetchall()

        # Top booking agents this year by tickets.
        cursor.execute(
            """
            SELECT
                t.agent_email,
                COUNT(*) AS tickets_sold,
                COALESCE(SUM(t.price_charged * 0.10), 0) AS commission
            FROM Ticket AS t
            JOIN Flight AS f
                ON f.flight_num = t.flight_num
            WHERE LOWER(f.airline_name) = LOWER(%s)
              AND t.agent_email IS NOT NULL
              AND YEAR(t.purchase_date) = YEAR(CURDATE())
            GROUP BY t.agent_email
            ORDER BY tickets_sold DESC
            LIMIT 5
            """,
            (airline_name,)
        )
        top_agents_year_tickets = cursor.fetchall()

        # Top booking agents this month by commission.
        cursor.execute(
            """
            SELECT
                t.agent_email,
                COUNT(*) AS tickets_sold,
                COALESCE(SUM(t.price_charged * 0.10), 0) AS commission
            FROM Ticket AS t
            JOIN Flight AS f
                ON f.flight_num = t.flight_num
            WHERE LOWER(f.airline_name) = LOWER(%s)
              AND t.agent_email IS NOT NULL
              AND YEAR(t.purchase_date) = YEAR(CURDATE())
              AND MONTH(t.purchase_date) = MONTH(CURDATE())
            GROUP BY t.agent_email
            ORDER BY commission DESC
            LIMIT 5
            """,
            (airline_name,)
        )
        top_agents_month_commission = cursor.fetchall()

        # Top booking agents this year by commission.
        cursor.execute(
            """
            SELECT
                t.agent_email,
                COUNT(*) AS tickets_sold,
                COALESCE(SUM(t.price_charged * 0.10), 0) AS commission
            FROM Ticket AS t
            JOIN Flight AS f
                ON f.flight_num = t.flight_num
            WHERE LOWER(f.airline_name) = LOWER(%s)
              AND t.agent_email IS NOT NULL
              AND YEAR(t.purchase_date) = YEAR(CURDATE())
            GROUP BY t.agent_email
            ORDER BY commission DESC
            LIMIT 5
            """,
            (airline_name,)
        )
        top_agents_year_commission = cursor.fetchall()

        # Most frequent customer last year.
        cursor.execute(
            """
            SELECT
                t.customer_email,
                c.name,
                COUNT(*) AS tickets
            FROM Ticket AS t
            JOIN Flight AS f
                ON f.flight_num = t.flight_num
            JOIN Customer AS c
                ON c.email = t.customer_email
            WHERE LOWER(f.airline_name) = LOWER(%s)
              AND t.purchase_date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
            GROUP BY t.customer_email, c.name
            ORDER BY tickets DESC
            LIMIT 1
            """,
            (airline_name,)
        )
        frequent_customer = cursor.fetchone()

        # Tickets sold per month, last 12 months.
        cursor.execute(
            """
            SELECT
                DATE_FORMAT(t.purchase_date, '%%Y-%%m') AS month_key,
                COUNT(*) AS tickets
            FROM Ticket AS t
            JOIN Flight AS f
                ON f.flight_num = t.flight_num
            WHERE LOWER(f.airline_name) = LOWER(%s)
              AND t.purchase_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
            GROUP BY DATE_FORMAT(t.purchase_date, '%%Y-%%m')
            ORDER BY month_key
            """,
            (airline_name,)
        )
        tickets_per_month = cursor.fetchall()

        # Delay vs on-time statistics.
        cursor.execute(
            """
            SELECT
                SUM(CASE WHEN flight_status = 'delayed' THEN 1 ELSE 0 END) AS delayed_count,
                SUM(CASE WHEN flight_status = 'on-time' THEN 1 ELSE 0 END) AS on_time_count,
                COUNT(*) AS total_flights
            FROM Flight
            WHERE LOWER(airline_name) = LOWER(%s)
            """,
            (airline_name,)
        )
        delay_stats = cursor.fetchone()

        # Top destinations last 3 months.
        cursor.execute(
            """
            SELECT
                f.arrival_airport,
                a.city,
                COUNT(*) AS ticket_count
            FROM Ticket AS t
            JOIN Flight AS f
                ON f.flight_num = t.flight_num
            JOIN Airport AS a
                ON a.name = f.arrival_airport
            WHERE LOWER(f.airline_name) = LOWER(%s)
              AND t.purchase_date >= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)
            GROUP BY f.arrival_airport, a.city
            ORDER BY ticket_count DESC
            LIMIT 5
            """,
            (airline_name,)
        )
        top_destinations_3_months = cursor.fetchall()

        # Top destinations last year.
        cursor.execute(
            """
            SELECT
                f.arrival_airport,
                a.city,
                COUNT(*) AS ticket_count
            FROM Ticket AS t
            JOIN Flight AS f
                ON f.flight_num = t.flight_num
            JOIN Airport AS a
                ON a.name = f.arrival_airport
            WHERE LOWER(f.airline_name) = LOWER(%s)
              AND t.purchase_date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
            GROUP BY f.arrival_airport, a.city
            ORDER BY ticket_count DESC
            LIMIT 5
            """,
            (airline_name,)
        )
        top_destinations_year = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "staff_analytics.html",
        staff=staff,
        top_agents_month_tickets=top_agents_month_tickets,
        top_agents_year_tickets=top_agents_year_tickets,
        top_agents_month_commission=top_agents_month_commission,
        top_agents_year_commission=top_agents_year_commission,
        frequent_customer=frequent_customer,
        tickets_per_month=tickets_per_month,
        delay_stats=delay_stats,
        top_destinations_3_months=top_destinations_3_months,
        top_destinations_year=top_destinations_year
    )

@app.route("/staff/admin/add-airport", methods=["GET", "POST"])
def staff_add_airport():
    staff = get_staff_context()

    if not staff:
        flash("Please log in as airline staff.")
        return redirect(url_for("login"))

    if not staff["is_admin"]: #the backend still blocks unauthorized users even if frontend accidently shows an add airport button
        flash("Admin permission required.")
        return redirect(url_for("staff_dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip().upper()
        city = request.form.get("city", "").strip().title()

        if not name or not city:
            return render_template(
                "staff_add_airport_result.html",
                success=False,
                airport_code=name or "Unknown",
                airport_city=city or "Unknown",
                message=f"Could not add {name or 'Unknown'} ({city or 'Unknown'}). Airport code must be exactly 3 letters."
            )

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT name FROM Airport WHERE name = %s", (name,))
            if cursor.fetchone():
                return render_template(
                    "staff_add_airport_result.html",
                    success=False,
                    airport_code=name,
                    airport_city=city,
                    message=f"Could not add {name} ({city})"
                )

            cursor.execute(
                "INSERT INTO Airport (name, city) VALUES (%s, %s)",
                (name, city)
            )

            return render_template(
                "staff_add_airport_result.html",
                success=True,
                airport_code=name,
                airport_city=city,
                message=f"{name} ({city}) added successfully"
            )

        except Exception:
            return render_template(
                "staff_add_airport_result.html",
                success=False,
                airport_code=name,
                airport_city=city,
                message=f"Could not add {name} ({city})"
            )

        finally:
            cursor.close()
            conn.close()

    return render_template("staff_add_airport.html", staff=staff)


@app.route("/staff/admin/add-airplane", methods=["GET", "POST"])
def staff_add_airplane():
    staff = get_staff_context()

    if not staff:
        flash("Please log in as airline staff.")
        return redirect(url_for("login"))

    if not staff["is_admin"]:
        flash("Admin permission required.")
        return redirect(url_for("staff_dashboard"))

    if request.method == "POST":
        airplane_id_raw = request.form.get("airplane_id", "").strip()
        economy_capacity_raw = request.form.get("economy_capacity", "").strip()
        business_capacity_raw = request.form.get("business_capacity", "").strip()
        first_capacity_raw = request.form.get("first_capacity", "").strip()

        try:
            airplane_id = int(airplane_id_raw)
            economy_capacity = int(economy_capacity_raw or 0)
            business_capacity = int(business_capacity_raw or 0)
            first_capacity = int(first_capacity_raw or 0)
        except ValueError:
            flash("Airplane ID and capacities must be valid integers.")
            return redirect(url_for("staff_add_airplane"))

        if airplane_id <= 0:
            flash("Airplane ID must be positive.")
            return redirect(url_for("staff_add_airplane"))

        capacities = {
            "economy": economy_capacity,
            "business": business_capacity,
            "first": first_capacity
        }

        if any(capacity < 0 for capacity in capacities.values()):
            flash("Seat capacities cannot be negative.")
            return redirect(url_for("staff_add_airplane"))

        if all(cap <= 0 for cap in capacities.values()):
            flash("At least one seat class must have positive capacity.")
            return redirect(url_for("staff_add_airplane"))

        total_capacity = sum(cap for cap in capacities.values() if cap > 0)

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT id FROM Airplane WHERE id = %s",
                (airplane_id,)
            )

            if cursor.fetchone():
                flash("Airplane ID already exists.")
                return redirect(url_for("staff_add_airplane"))

            price_factors = {
                "economy": 1.0,
                "business": 1.8,
                "first": 2.5
            }

            # TRANSACTION START:
            # Airplane and all SeatClass rows must be inserted together.
            conn.begin()

            cursor.execute(
                """
                INSERT INTO Airplane (id, airline_name, seat_capacity)
                VALUES (%s, %s, %s)
                """,
                (airplane_id, staff["airline_name"], total_capacity)
            )

            for seat_class, capacity in capacities.items():
                if capacity > 0:
                    cursor.execute(
                        """
                        INSERT INTO SeatClass
                        (airplane_id, seat_class, capacity, price_factor)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (airplane_id, seat_class, capacity, price_factors[seat_class])
                    )

            conn.commit()

            flash("Airplane and seat classes added successfully.")
            return redirect(url_for("staff_dashboard"))

        except Exception as e:
            safe_rollback(conn)
            flash(f"Airplane creation failed. No partial airplane or seat-class data was saved. Error: {e}")
            return redirect(url_for("staff_add_airplane"))

        finally:
            cursor.close()
            conn.close()

    return render_template("staff_add_airplane.html", staff=staff)


@app.route("/staff/admin/create-flight", methods=["GET", "POST"])
def staff_create_flight():
    staff = get_staff_context()

    if not staff:
        flash("Please log in as airline staff.")
        return redirect(url_for("login"))

    if not staff["is_admin"]:
        flash("Admin permission required.")
        return redirect(url_for("staff_dashboard"))

    if request.method == "POST":
        flight_num = request.form.get("flight_num", "").strip().upper()
        airplane_id_raw = request.form.get("airplane_id", "").strip()
        departure_airport = request.form.get("departure_airport", "").strip().upper()
        arrival_airport = request.form.get("arrival_airport", "").strip().upper()
        departure_time = request.form.get("departure_time", "").strip()
        arrival_time = request.form.get("arrival_time", "").strip()
        price_raw = request.form.get("price", "").strip()
        flight_status = request.form.get("flight_status", "upcoming").strip().lower()

        if not all([flight_num, airplane_id_raw, departure_airport, arrival_airport, departure_time, arrival_time, price_raw]):
            flash("Please fill in all required fields.")
            return redirect(url_for("staff_create_flight"))

        if flight_status not in ("on-time", "upcoming", "in-progress", "delayed"):
            flash("Invalid flight status.")
            return redirect(url_for("staff_create_flight"))

        try:
            airplane_id = int(airplane_id_raw)
            price = float(price_raw)
        except ValueError:
            flash("Airplane ID and price must be numeric.")
            return redirect(url_for("staff_create_flight"))

        if price <= 0:
            flash("Price must be positive.")
            return redirect(url_for("staff_create_flight"))

        try:
            dep_dt = datetime.strptime(departure_time, "%Y-%m-%dT%H:%M")
            arr_dt = datetime.strptime(arrival_time, "%Y-%m-%dT%H:%M")
        except ValueError:
            flash("Invalid datetime format.")
            return redirect(url_for("staff_create_flight"))

        if arr_dt <= dep_dt:
            flash("Arrival time must be after departure time.")
            return redirect(url_for("staff_create_flight"))

        if departure_airport == arrival_airport:
            flash("Departure and arrival airports must be different.")
            return redirect(url_for("staff_create_flight"))

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT flight_num FROM Flight WHERE UPPER(flight_num) = UPPER(%s)", (flight_num,))
            if cursor.fetchone():
                flash("Flight number already exists.")
                return redirect(url_for("staff_create_flight"))

            cursor.execute(
                """
                SELECT id
                FROM Airplane
                WHERE id = %s
                  AND LOWER(airline_name) = LOWER(%s)
                """,
                (airplane_id, staff["airline_name"])
            )
            if not cursor.fetchone():
                flash("That airplane does not exist for your airline.")
                return redirect(url_for("staff_create_flight"))

            cursor.execute("SELECT name FROM Airport WHERE UPPER(name) = UPPER(%s)", (departure_airport,))
            if not cursor.fetchone():
                flash("Departure airport does not exist.")
                return redirect(url_for("staff_create_flight"))

            cursor.execute("SELECT name FROM Airport WHERE UPPER(name) = UPPER(%s)", (arrival_airport,))
            if not cursor.fetchone():
                flash("Arrival airport does not exist.")
                return redirect(url_for("staff_create_flight"))

            cursor.execute(
                """
                INSERT INTO Flight
                (flight_num, airplane_id, airline_name, departure_airport, arrival_airport,
                 departure_time, arrival_time, price, flight_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    flight_num,
                    airplane_id,
                    staff["airline_name"],
                    departure_airport,
                    arrival_airport,
                    dep_dt,
                    arr_dt,
                    price,
                    flight_status
                )
            )

            flash("Flight created successfully.")
            return redirect(url_for("staff_dashboard"))

        finally:
            cursor.close()
            conn.close()

    return render_template("staff_create_flight.html", staff=staff)

@app.route("/staff/admin/authorize-agent", methods=["GET", "POST"])
def staff_authorize_agent():
    staff = get_staff_context()

    if not staff:
        flash("Please log in as airline staff.")
        return redirect(url_for("login"))

    if not staff["is_admin"]:
        flash("Admin permission required.")
        return redirect(url_for("staff_dashboard"))

    if request.method == "POST":
        agent_email = request.form.get("agent_email", "").strip().lower()

        if not agent_email:
            flash("Agent email is required.")
            return redirect(url_for("staff_authorize_agent"))

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT email FROM BookingAgent WHERE email = %s", (agent_email,))
            if not cursor.fetchone():
                flash("Booking agent does not exist.")
                return redirect(url_for("staff_authorize_agent"))

            cursor.execute(
                """
                SELECT agent_email
                FROM AuthorizedFor
                WHERE agent_email = %s
                  AND airline_name = %s
                """,
                (agent_email, staff["airline_name"])
            )
            if cursor.fetchone():
                flash("This booking agent is already authorized for your airline.")
                return redirect(url_for("staff_authorize_agent"))

            cursor.execute(
                """
                INSERT INTO AuthorizedFor (agent_email, airline_name)
                VALUES (%s, %s)
                """,
                (agent_email, staff["airline_name"])
            )

            flash("Booking agent authorized successfully.")
            return redirect(url_for("staff_dashboard"))

        finally:
            cursor.close()
            conn.close()

    return render_template("staff_authorize_agent.html", staff=staff)

@app.route("/staff/operator/update-status/<flight_num>", methods=["GET", "POST"])
def staff_update_status(flight_num):
    staff = get_staff_context()

    if not staff:
        flash("Please log in as airline staff.")
        return redirect(url_for("login"))

    if not staff["is_operator"]:
        flash("Operator permission required.")
        return redirect(url_for("staff_dashboard"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT flight_num, airline_name, departure_airport, arrival_airport,
                   departure_time, arrival_time, flight_status
            FROM Flight
            WHERE flight_num = %s
              AND airline_name = %s
            """,
            (flight_num, staff["airline_name"])
        )
        flight = cursor.fetchone()

        if not flight:
            flash("Flight not found for your airline.")
            return redirect(url_for("staff_dashboard"))

        if request.method == "POST":
            new_status = request.form.get("flight_status", "").strip()

            if new_status not in ("on-time", "upcoming", "in-progress", "delayed"):
                flash("Invalid flight status.")
                return redirect(url_for("staff_update_status", flight_num=flight_num))

            cursor.execute(
                """
                UPDATE Flight
                SET flight_status = %s
                WHERE flight_num = %s
                  AND airline_name = %s
                """,
                (new_status, flight_num, staff["airline_name"])
            )

            flash("Flight status updated successfully.")
            return redirect(url_for("staff_dashboard"))

    finally:
        cursor.close()
        conn.close()

    return render_template("staff_update_status.html", staff=staff, flight=flight)


if __name__ == "__main__":
    app.run(debug=True) #starts the server
