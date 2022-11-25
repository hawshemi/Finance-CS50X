import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


# Evoid redondemcy by using is_provided function
def is_provided(field):
    if not request.form.get(field):
        return apology(f"Must provide {field}", 400)


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Query database for transaction
    rows = db.execute("""
        SELECT symbol, SUM(shares) as totalShares
        FROM transactions
        WHERE user_id = :user_id
        GROUP BY symbol
        HAVING totalShares > 0;
    """, user_id=session["user_id"])

    holdings = []
    grand_total = 0
    # Loop through the data to get all of the user' info
    for row in rows:
        stock = lookup(row["symbol"])
        holdings.append({
            "symbol": stock["symbol"],
            "name": stock["name"],
            "shares": row["totalShares"],
            "price": usd(stock["price"]),
            "total": usd(stock["price"] * row["totalShares"])

        })
        # Get the grand total
        grand_total += stock["price"] * row["totalShares"]

    # Query database to get cash from user' table
    rows = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session["user_id"])
    cash = rows[0]["cash"]
    grand_total += cash

    return render_template("index.html", holdings=holdings, cash=usd(cash),  grand_total=usd(grand_total))


@app.route("/balance", methods=["GET", "POST"])
@login_required
def balance():
    if request.method == "POST":
        # Assign input to variable
        input_amount = int(request.form['cash'])

        # Ensure cash amount was submitted
        if input_amount == None:
            return apology("must provide amount of cash to add or remove", 403)

        # Query database to update cash
        db.execute("""
            UPDATE users
            SET cash = cash + :amount
            WHERE id=:user_id
        """, amount = input_amount,
        user_id = session["user_id"])

        if input_amount > 0:
            # Flash info for the user
            flash(f"You have added {usd(input_amount)} to your account")
        elif input_amount < 0:
            flash(f"You have subtracted {usd(abs(input_amount))} from your account")
        else:
            return apology("you entered zero", 403)

        # Redirect to homepage
        return redirect("/")

    else:
        return render_template("balance.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Ensure stock symbol and number of shares are provided
        find_missing_errors = is_provided("symbol") or is_provided("shares")
        if find_missing_errors:
            return find_missing_errors
        elif not request.form.get("shares").isdigit():
            return apology("invalid number of shares")

        # Search for the symbol
        symbol = request.form.get("symbol").upper()
        shares = int(request.form.get("shares"))
        stock = lookup(symbol)
        if stock == None:
            return apology("invalid symbol")

        # Query database for user' cash and update cash
        rows = db.execute("SELECT Cash FROM users WHERE id=:id", id=session["user_id"])
        cash = rows[0]["cash"]

        updated_cash = cash - shares * stock['price']
        if updated_cash < 0:
            return apology("can't afford")
        db.execute("UPDATE users SET cash=:updated_cash WHERE id=:id",
                    updated_cash=updated_cash,
                    id=session["user_id"])

        # Query database for user' transaction
        db.execute("""
            INSERT INTO transactions
                (user_id, symbol, shares, price)
            VALUES (:user_id, :symbol, :shares, :price)

        """,
            user_id = session["user_id"],
            symbol = stock["symbol"],
            shares = shares,
            price = stock["price"]
        )
        flash("Bought Successfully.")

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Query database for displying everything
    transactions = db.execute("""
        SELECT symbol, shares, price, transacted
        FROM transactions
        WHERE user_id=:user_id
    """, user_id=session["user_id"])

    for i in range(len(transactions)):
        transactions[i]["price"] = usd(transactions[i]["price"])
    return render_template("history.html", transactions=transactions)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username and password was submitted
        result_check = is_provided("username") or is_provided("password")
        if result_check is not None:
            return result_check

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        result_check = is_provided("symbol")
        if result_check is not None:
            return result_check
        symbol = request.form.get("symbol").upper()
        # Search for the stock in the data
        stock = lookup(symbol)
        if stock is None:
            return apology("invalid symbol", 400)
        return render_template("quoted.html", stock={
            'name': stock['name'],
            'symbol': stock['symbol'],
            'price': usd(stock['price'])
        })


    else:
        return render_template("quote.html")


# Validation Function
def validate(password):
    import re # regular expression
    if len(password) < 8:
        return apology("Password should be at least 8 characters or longer")
    elif not re.search("[0-9]", password):
        return apology("Password must contain at least one digit")
    elif not re.search("[A-Z]", password):
        return apology("Password must contain at least one uppercase letter")
    elif not re.search("[@_!#$%&^*()<>?~+-/\{}:]",password):
        return apology("password must contain at least one special character")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensure username password and confiemation was provided
        result_check = is_provided("username") or is_provided("password") or is_provided("confirmation")

        if result_check != None:
            return result_check

        # Validate the user' password
        validation_errors = validate(request.form.get("password"))
        if validation_errors:
            return validation_errors


        # Ensure password and confirmation match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match")

        # Query database for username
        try:
            prim_key = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                    username=request.form.get("username"),
                    hash=generate_password_hash(request.form.get("password")))
        except:
            return apology("username already exixt", 400)

        if prim_key is None:
            return apology("registration error", 403)

        # Remember which user has logged in
        session["user_id"] = prim_key

        flash("Registered!")
        return redirect("/")



    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # Ensure stock symbol and number of shares are provided
        find_missing_errors = is_provided("symbol") or is_provided("shares")
        if find_missing_errors:
            return find_missing_errors
        elif not request.form.get("shares").isdigit():
            return apology("invalid number of shares")

        # Search for the symbol
        symbol = request.form["symbol"].upper()
        shares = int(request.form.get("shares"))
        stock = lookup(symbol)
        if stock is None:
            return apology("invalid symbol")

        #v Query databse and math for sell transactions
        rows = db.execute("""
            SELECT symbol, SUM(shares) as totalShares
            FROM transactions
            WHERE user_id=:user_id
            GROUP BY symbol
            HAVING totalShares > 0;
        """, user_id=session["user_id"])
        for row in rows:
            if row["symbol"] == symbol:
                if shares > row["totalShares"]:
                    return apology("too many shares")


        # Query database for user' cash and update cash
        rows = db.execute("SELECT Cash FROM users WHERE id=:id", id=session["user_id"])
        cash = rows[0]["cash"]

        updated_cash = cash + shares * stock['price']

        if updated_cash < 0:
            return apology("can't afford")
        db.execute("UPDATE users SET cash=:updated_cash WHERE id=:id",
                    updated_cash=updated_cash,
                    id=session["user_id"])

        # Query database for user' transaction
        db.execute("""
            INSERT INTO transactions
                (user_id, symbol, shares, price)
            VALUES (:user_id, :symbol, :shares, :price)

        """,
            user_id = session["user_id"],
            symbol = stock["symbol"],
            shares = -1 * shares,
            price = stock["price"]
        )
        flash("Sold Successfully.")

        return redirect("/")
    else:
        # Query database to handle or Provid the user' number of stocks
        rows = db.execute("""
            SELECT symbol
            FROM transactions
            WHERE user_id=:user_id
            GROUP BY symbol
            HAVING SUM(shares) > 0;
        """, user_id=session["user_id"])
        return render_template("sell.html", symbols=[row["symbol"] for row in rows])


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
