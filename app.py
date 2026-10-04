from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

import sqlite3

from datetime import (
    datetime,
    timedelta,
    timezone
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from functools import wraps


# ==================================================
# FLASK CONFIGURATION
# ==================================================

app = Flask(__name__)

app.secret_key = "mca-banking-aiops-project"

DB = "banking.db"

# Account block duration
BLOCK_MINUTES = 5


# ==================================================
# DATABASE
# ==================================================

def get_db():

    conn = sqlite3.connect(DB)

    conn.row_factory = sqlite3.Row

    return conn


def now():

    return datetime.now(
        timezone.utc
    ).replace(
        microsecond=0
    )


# ==================================================
# INITIALIZE DATABASE
# ==================================================

def init_db():

    conn = get_db()

    conn.executescript("""

    CREATE TABLE IF NOT EXISTS users (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        account_no TEXT UNIQUE NOT NULL,

        name TEXT NOT NULL,

        email TEXT NOT NULL,

        password_hash TEXT NOT NULL,

        balance REAL NOT NULL DEFAULT 0,

        failed_attempts INTEGER NOT NULL DEFAULT 0,

        blocked_until TEXT

    );


    CREATE TABLE IF NOT EXISTS transactions (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        account_no TEXT NOT NULL,

        transaction_type TEXT NOT NULL,

        amount REAL NOT NULL,

        description TEXT,

        created_at TEXT NOT NULL

    );


    CREATE TABLE IF NOT EXISTS security_logs (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        account_no TEXT,

        event TEXT NOT NULL,

        status TEXT NOT NULL,

        ai_action TEXT NOT NULL,

        created_at TEXT NOT NULL

    );

    """)


    # ==================================================
    # DEMO ACCOUNT 1
    # ==================================================

    user = conn.execute(
        """
        SELECT id
        FROM users
        WHERE account_no = ?
        """,
        ("1002003001",)
    ).fetchone()


    if not user:

        conn.execute(
            """
            INSERT INTO users
            (
                account_no,
                name,
                email,
                password_hash,
                balance
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "1002003001",
                "Kanimozhi",
                "kanimozhi@example.com",
                generate_password_hash("1234"),
                50000.00
            )
        )


        conn.execute(
            """
            INSERT INTO transactions
            (
                account_no,
                transaction_type,
                amount,
                description,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "1002003001",
                "CREDIT",
                50000,
                "Initial demo balance",
                now().isoformat()
            )
        )

    else:

        # Existing database user:
        # automatically change old name to Kanimozhi

        conn.execute(
            """
            UPDATE users
            SET
                name = ?,
                email = ?
            WHERE account_no = ?
            """,
            (
                "Kanimozhi",
                "kanimozhi@example.com",
                "1002003001"
            )
        )


    # ==================================================
    # DEMO ACCOUNT 2
    # ==================================================

    user2 = conn.execute(
        """
        SELECT id
        FROM users
        WHERE account_no = ?
        """,
        ("1002003002",)
    ).fetchone()


    if not user2:

        conn.execute(
            """
            INSERT INTO users
            (
                account_no,
                name,
                email,
                password_hash,
                balance
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "1002003002",
                "Demo Receiver",
                "receiver@example.com",
                generate_password_hash("1234"),
                10000.00
            )
        )


        conn.execute(
            """
            INSERT INTO transactions
            (
                account_no,
                transaction_type,
                amount,
                description,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "1002003002",
                "CREDIT",
                10000,
                "Initial demo balance",
                now().isoformat()
            )
        )


    conn.commit()

    conn.close()


# ==================================================
# SECURITY LOG
# ==================================================

def log_event(
    account_no,
    event,
    status,
    ai_action
):

    conn = get_db()

    conn.execute(
        """
        INSERT INTO security_logs
        (
            account_no,
            event,
            status,
            ai_action,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            account_no,
            event,
            status,
            ai_action,
            now().isoformat()
        )
    )

    conn.commit()

    conn.close()


# ==================================================
# AIOPS MONITOR
# ==================================================

def aiops_monitor(
    account_no,
    event,
    failed_attempts
):

    if failed_attempts >= 3:

        return (
            "THREAT",
            "Agentic AI: Temporary account block applied"
        )


    elif failed_attempts == 2:

        return (
            "WARNING",
            "AIOps Alert: Repeated failed login detected"
        )


    else:

        return (
            "NORMAL",
            "Monitor activity"
        )


# ==================================================
# AGENTIC AI RESPONSE
# ==================================================

def agentic_response(
    account_no,
    failed_attempts
):

    conn = get_db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE account_no = ?
        """,
        (account_no,)
    ).fetchone()


    if not user:

        conn.close()

        return None


    if failed_attempts >= 3:

        blocked_until = (
            now()
            + timedelta(
                minutes=BLOCK_MINUTES
            )
        )


        conn.execute(
            """
            UPDATE users
            SET blocked_until = ?
            WHERE account_no = ?
            """,
            (
                blocked_until.isoformat(),
                account_no
            )
        )


        conn.commit()

        conn.close()

        return "Temporary block"


    conn.close()

    return "Alert only"


# ==================================================
# CHECK ACCOUNT BLOCK
# ==================================================

def get_block_status(user):

    if not user:

        return False, None


    if not user["blocked_until"]:

        return False, None


    try:

        blocked_until = datetime.fromisoformat(
            user["blocked_until"]
        )

    except ValueError:

        return False, None


    current = now()


    if current < blocked_until:

        return True, blocked_until


    # Block expired

    conn = get_db()

    conn.execute(
        """
        UPDATE users
        SET
            blocked_until = NULL,
            failed_attempts = 0
        WHERE account_no = ?
        """,
        (
            user["account_no"],
        )
    )

    conn.commit()

    conn.close()

    return False, None


# ==================================================
# LOGIN REQUIRED
# ==================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "account_no" not in session:

            flash(
                "Please login to access your bank account.",
                "warning"
            )

            return redirect(
                url_for("login")
            )


        return function(
            *args,
            **kwargs
        )


    return wrapper


# ==================================================
# HOME
# ==================================================

@app.route("/")
def index():

    conn = get_db()

    recent = conn.execute(
        """
        SELECT *
        FROM security_logs
        ORDER BY id DESC
        LIMIT 5
        """
    ).fetchall()

    conn.close()


    return render_template(
        "index.html",
        recent=recent
    )


# ==================================================
# LOGIN
# ==================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        account_no = request.form.get(
            "account_no",
            ""
        ).strip()


        password = request.form.get(
            "password",
            ""
        )


        conn = get_db()


        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE account_no = ?
            """,
            (account_no,)
        ).fetchone()


        # ==================================================
        # UNKNOWN ACCOUNT
        # ==================================================

        if not user:

            conn.close()

            log_event(
                account_no or "UNKNOWN",
                "Unknown account login attempt",
                "WARNING",
                "AIOps Alert: Unknown account activity monitored"
            )


            flash(
                "Invalid account number or password.",
                "danger"
            )


            return render_template(
                "login.html"
            )


        # ==================================================
        # CHECK BLOCK
        # ==================================================

        blocked, blocked_until = get_block_status(
            user
        )


        if blocked:

            conn.close()

            remaining = int(
                (
                    blocked_until - now()
                ).total_seconds()
            )


            minutes = max(
                1,
                (remaining + 59) // 60
            )


            log_event(
                account_no,
                "Login attempted while account was blocked",
                "THREAT",
                "Agentic AI: Block maintained"
            )


            flash(
                f"Account temporarily blocked. "
                f"Try again in about {minutes} minute(s).",
                "danger"
            )


            return render_template(
                "login.html"
            )


        # ==================================================
        # CORRECT PASSWORD
        # ==================================================

        if check_password_hash(
            user["password_hash"],
            password
        ):

            conn.execute(
                """
                UPDATE users
                SET
                    failed_attempts = 0,
                    blocked_until = NULL
                WHERE account_no = ?
                """,
                (
                    account_no,
                )
            )


            conn.commit()

            conn.close()


            log_event(
                account_no,
                "Successful Login",
                "NORMAL",
                "Agentic AI: Login approved"
            )


            session["account_no"] = account_no

            session["name"] = user["name"]


            return redirect(
                url_for("dashboard")
            )


        # ==================================================
        # INVALID PASSWORD
        # ==================================================

        failed = (
            user["failed_attempts"]
            + 1
        )


        conn.execute(
            """
            UPDATE users
            SET failed_attempts = ?
            WHERE account_no = ?
            """,
            (
                failed,
                account_no
            )
        )


        conn.commit()

        conn.close()


        status, action = aiops_monitor(
            account_no,
            "Failed Login",
            failed
        )


        # ==================================================
        # AGENTIC AI DECISION
        # ==================================================

        if failed >= 3:

            agentic_response(
                account_no,
                failed
            )


            status = "THREAT"


            action = (
                "Agentic AI: "
                "Temporary account block applied"
            )


        elif failed == 2:

            action = (
                "AIOps Alert: 2nd invalid attempt - "
                "user warning generated"
            )


        else:

            action = "Monitor activity"


        log_event(
            account_no,
            f"Failed Login Attempt #{failed}",
            status,
            action
        )


        # ==================================================
        # USER MESSAGE
        # ==================================================

        if failed == 1:

            flash(
                "Invalid password. "
                "Activity is being monitored.",
                "warning"
            )


        elif failed == 2:

            flash(
                "ALERT: 2 invalid login attempts detected.",
                "warning"
            )


        else:

            flash(
                "THREAT: Too many invalid attempts. "
                "Account temporarily blocked by Agentic AI.",
                "danger"
            )


        return render_template(
            "login.html"
        )


    return render_template(
        "login.html"
    )


# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    account_no = session.get(
        "account_no"
    )


    if account_no:

        log_event(
            account_no,
            "Logout",
            "NORMAL",
            "Agentic AI: Session ended"
        )


    session.clear()


    return redirect(
        url_for("index")
    )


# ==================================================
# BANK DASHBOARD
# ==================================================

@app.route("/dashboard")
@login_required
def dashboard():

    account_no = session["account_no"]


    conn = get_db()


    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE account_no = ?
        """,
        (
            account_no,
        )
    ).fetchone()


    transactions = conn.execute(
        """
        SELECT *
        FROM transactions
        WHERE account_no = ?
        ORDER BY id DESC
        LIMIT 10
        """,
        (
            account_no,
        )
    ).fetchall()


    conn.close()


    return render_template(
        "dashboard.html",
        user=user,
        transactions=transactions
    )


# ==================================================
# WITHDRAW
# ==================================================

@app.route(
    "/withdraw",
    methods=["POST"]
)
@login_required
def withdraw():

    account_no = session["account_no"]


    try:

        amount = float(
            request.form.get(
                "amount",
                0
            )
        )

    except ValueError:

        amount = 0


    if amount <= 0:

        flash(
            "Enter a valid withdrawal amount.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )


    conn = get_db()


    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE account_no = ?
        """,
        (
            account_no,
        )
    ).fetchone()


    if not user:

        conn.close()

        flash(
            "Account not found.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )


    # ==================================================
    # INSUFFICIENT BALANCE
    # ==================================================

    if amount > user["balance"]:

        conn.close()


        log_event(
            account_no,
            "Withdrawal denied - insufficient balance",
            "WARNING",
            "AIOps: Transaction anomaly monitored"
        )


        flash(
            "Insufficient balance.",
            "danger"
        )


        return redirect(
            url_for("dashboard")
        )


    new_balance = (
        user["balance"]
        - amount
    )


    conn.execute(
        """
        UPDATE users
        SET balance = ?
        WHERE account_no = ?
        """,
        (
            new_balance,
            account_no
        )
    )


    conn.execute(
        """
        INSERT INTO transactions
        (
            account_no,
            transaction_type,
            amount,
            description,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            account_no,
            "DEBIT",
            amount,
            "Cash withdrawal",
            now().isoformat()
        )
    )


    conn.commit()

    conn.close()


    log_event(
        account_no,
        f"Withdrawal ₹{amount:.2f}",
        "NORMAL",
        "Agentic AI: Transaction allowed"
    )


    flash(
        f"₹{amount:.2f} withdrawn successfully.",
        "success"
    )


    return redirect(
        url_for("dashboard")
    )


# ==================================================
# DEPOSIT
# ==================================================

@app.route(
    "/deposit",
    methods=["POST"]
)
@login_required
def deposit():

    account_no = session["account_no"]


    try:

        amount = float(
            request.form.get(
                "amount",
                0
            )
        )

    except ValueError:

        amount = 0


    if amount <= 0:

        flash(
            "Enter a valid deposit amount.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )


    conn = get_db()


    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE account_no = ?
        """,
        (
            account_no,
        )
    ).fetchone()


    if not user:

        conn.close()

        flash(
            "Account not found.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )


    new_balance = (
        user["balance"]
        + amount
    )


    conn.execute(
        """
        UPDATE users
        SET balance = ?
        WHERE account_no = ?
        """,
        (
            new_balance,
            account_no
        )
    )


    conn.execute(
        """
        INSERT INTO transactions
        (
            account_no,
            transaction_type,
            amount,
            description,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            account_no,
            "CREDIT",
            amount,
            "Cash deposit",
            now().isoformat()
        )
    )


    conn.commit()

    conn.close()


    log_event(
        account_no,
        f"Deposit ₹{amount:.2f}",
        "NORMAL",
        "Agentic AI: Transaction allowed"
    )


    flash(
        f"₹{amount:.2f} deposited successfully.",
        "success"
    )


    return redirect(
        url_for("dashboard")
    )


# ==================================================
# MONEY TRANSFER
# ==================================================

@app.route(
    "/transfer",
    methods=["POST"]
)
@login_required
def transfer():

    sender_account = session["account_no"]


    receiver_account = request.form.get(
        "receiver_account",
        ""
    ).strip()


    try:

        amount = float(
            request.form.get(
                "amount",
                0
            )
        )

    except ValueError:

        amount = 0


    # ==================================================
    # VALIDATION
    # ==================================================

    if not receiver_account:

        flash(
            "Enter receiver account number.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )


    if amount <= 0:

        flash(
            "Enter a valid transfer amount.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )


    if sender_account == receiver_account:

        flash(
            "You cannot transfer money to the same account.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )


    conn = get_db()


    # ==================================================
    # GET SENDER
    # ==================================================

    sender = conn.execute(
        """
        SELECT *
        FROM users
        WHERE account_no = ?
        """,
        (
            sender_account,
        )
    ).fetchone()


    # ==================================================
    # GET RECEIVER
    # ==================================================

    receiver = conn.execute(
        """
        SELECT *
        FROM users
        WHERE account_no = ?
        """,
        (
            receiver_account,
        )
    ).fetchone()


    # ==================================================
    # RECEIVER NOT FOUND
    # ==================================================

    if not receiver:

        conn.close()


        log_event(
            sender_account,
            "Transfer attempt to unknown account",
            "WARNING",
            "AIOps: Unknown destination monitored"
        )


        flash(
            "Receiver account not found.",
            "danger"
        )


        return redirect(
            url_for("dashboard")
        )


    # ==================================================
    # INSUFFICIENT BALANCE
    # ==================================================

    if amount > sender["balance"]:

        conn.close()


        log_event(
            sender_account,
            "Transfer denied - insufficient balance",
            "WARNING",
            "AIOps: Transaction anomaly monitored"
        )


        flash(
            "Insufficient balance.",
            "danger"
        )


        return redirect(
            url_for("dashboard")
        )


    # ==================================================
    # UPDATE BALANCES
    # ==================================================

    sender_balance = (
        sender["balance"]
        - amount
    )


    receiver_balance = (
        receiver["balance"]
        + amount
    )


    conn.execute(
        """
        UPDATE users
        SET balance = ?
        WHERE account_no = ?
        """,
        (
            sender_balance,
            sender_account
        )
    )


    conn.execute(
        """
        UPDATE users
        SET balance = ?
        WHERE account_no = ?
        """,
        (
            receiver_balance,
            receiver_account
        )
    )


    # ==================================================
    # SENDER TRANSACTION
    # ==================================================

    conn.execute(
        """
        INSERT INTO transactions
        (
            account_no,
            transaction_type,
            amount,
            description,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            sender_account,
            "DEBIT",
            amount,
            f"Transfer to {receiver_account}",
            now().isoformat()
        )
    )


    # ==================================================
    # RECEIVER TRANSACTION
    # ==================================================

    conn.execute(
        """
        INSERT INTO transactions
        (
            account_no,
            transaction_type,
            amount,
            description,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            receiver_account,
            "CREDIT",
            amount,
            f"Transfer from {sender_account}",
            now().isoformat()
        )
    )


    conn.commit()

    conn.close()


    log_event(
        sender_account,
        f"Money transfer ₹{amount:.2f}",
        "NORMAL",
        "Agentic AI: Transaction allowed"
    )


    flash(
        f"₹{amount:.2f} transferred successfully.",
        "success"
    )


    return redirect(
        url_for("dashboard")
    )


# ==================================================
# RISK SCORE
# ==================================================

def calculate_risk(account_no):

    conn = get_db()


    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE account_no = ?
        """,
        (
            account_no,
        )
    ).fetchone()


    if not user:

        conn.close()

        return 0, "LOW"


    failed = user["failed_attempts"]


    threats = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM security_logs
        WHERE account_no = ?
        AND status = 'THREAT'
        """,
        (
            account_no,
        )
    ).fetchone()["c"]


    warnings = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM security_logs
        WHERE account_no = ?
        AND status = 'WARNING'
        """,
        (
            account_no,
        )
    ).fetchone()["c"]


    conn.close()


    # ==================================================
    # RISK FORMULA
    # ==================================================

    score = (
        failed * 20
        + threats * 10
        + warnings * 5
    )


    score = min(
        score,
        100
    )


    if score >= 70:

        level = "HIGH"


    elif score >= 30:

        level = "MEDIUM"


    else:

        level = "LOW"


    return score, level


# ==================================================
# SECURITY DASHBOARD
# ==================================================

@app.route("/security")
@login_required
def security():

    account_no = session["account_no"]


    conn = get_db()


    # ==================================================
    # SECURITY LOGS
    # ==================================================

    logs = conn.execute(
        """
        SELECT *
        FROM security_logs
        WHERE account_no = ?
        ORDER BY id DESC
        LIMIT 30
        """,
        (
            account_no,
        )
    ).fetchall()


    # ==================================================
    # SECURITY STATISTICS
    # ==================================================

    total = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM security_logs
        WHERE account_no = ?
        """,
        (
            account_no,
        )
    ).fetchone()["c"]


    warnings = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM security_logs
        WHERE account_no = ?
        AND status = 'WARNING'
        """,
        (
            account_no,
        )
    ).fetchone()["c"]


    threats = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM security_logs
        WHERE account_no = ?
        AND status = 'THREAT'
        """,
        (
            account_no,
        )
    ).fetchone()["c"]


    normal = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM security_logs
        WHERE account_no = ?
        AND status = 'NORMAL'
        """,
        (
            account_no,
        )
    ).fetchone()["c"]


    conn.close()


    stats = {

        "total": total,

        "warnings": warnings,

        "threats": threats,

        "normal": normal

    }


    # ==================================================
    # RISK SCORE
    # ==================================================

    risk_score, risk_level = calculate_risk(
        account_no
    )


    return render_template(
        "security.html",

        logs=logs,

        stats=stats,

        risk_score=risk_score,

        risk_level=risk_level
    )


# ==================================================
# RESET DEMO
# ==================================================

@app.route("/reset-demo")
def reset_demo():

    conn = get_db()


    # Reset security state

    conn.execute(
        """
        UPDATE users
        SET
            failed_attempts = 0,
            blocked_until = NULL
        WHERE account_no = ?
        """,
        (
            "1002003001",
        )
    )


    # Reset name also

    conn.execute(
        """
        UPDATE users
        SET
            name = ?,
            email = ?
        WHERE account_no = ?
        """,
        (
            "Kanimozhi",
            "kanimozhi@example.com",
            "1002003001"
        )
    )


    conn.commit()

    conn.close()


    flash(
        "Demo account security state reset.",
        "success"
    )


    return redirect(
        url_for("login")
    )


# ==================================================
# INITIALIZE DATABASE
# ==================================================

# Important for Render / Gunicorn also.
# Database will be created when application starts.

init_db()


# ==================================================
# RUN APPLICATION
# ==================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )