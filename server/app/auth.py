from flask import Blueprint, Response, abort, request, session, g, redirect, url_for
import functools

from werkzeug.security import generate_password_hash, check_password_hash

from app.db import get_db

bp = Blueprint("auth", __name__, url_prefix="/")


# index page
# read
@bp.get("/")
def index():
    if g.user is None:
        return "Log in or register\n"
    else:
        return f"Hello, {g.user['username']}\n"


# create
@bp.post("/register")
def register():
    error = None
    details = request.get_json()
    if "username" in details:
        username = details["username"]
    else:
        error = "username required\n"
    if "password" in details:
        password = details["password"]
    else:
        error = "password required\n"

    db = get_db()

    if error is None:
        try:
            db.execute(
                "INSERT INTO user (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            db.commit()
        except db.IntegrityError:
            error = f"User {username} is already registered\n"
        else:
            return "Successfully Registered"

    abort(Response(error, 406))


# authorise
@bp.post("/login")
def login():
    error = None
    details = request.get_json()
    if "username" in details:
        username = details["username"]
    else:
        error = "username required\n"
    if "password" in details:
        password = details["password"]
    else:
        error = "password required\n"

    if error is None:
        db = get_db()
        user = db.execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()
        if user is None:
            error = f"User {username} does not exist.\n"
        elif not check_password_hash(user["password"], password):
            error = "Incorrect password\n"

        if error is None:
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("auth.index"))
        abort(Response(error, 403))
    abort(Response(error, 406))


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
    else:
        g.user = (
            get_db().execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
        )


@bp.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.index"))


# wrapper
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            abort(Response("Login Required", 403))
        return view(*args, **kwargs)

    return wrapped_view


# update
@bp.put("/updateUsername")
@login_required
def update_username():
    detail = request.get_json()
    if "username" in detail:
        user = detail["username"]
    else:
        abort(Response("New Username required"), 406)
    db = get_db()
    try:
        db.execute("UPDATE user SET username = ? WHERE id = ?", (user, g.user["id"]))
        db.commit()
    except db.IntegrityError:
        error = f"Username {user} is already taken."
        abort(Response(error), 406)
    return "Username Updated"


@bp.put("/updatePassword")
@login_required
def update_user_info():
    error = None
    details = request.get_json()
    if "old_password" in details:
        old_password = details["old_password"]
    else:
        error = "Old Password required\n"

    if "password" in details:
        password = details["password"]
    else:
        error = "Password required"

    if error is None:
        user = g.user
        if not check_password_hash(user["password"], old_password):
            error = "Wrong original password"

        db = get_db()

        if error is None:
            db.execute(
                "UPDATE user SET password = ? WHERE id = ?",
                (generate_password_hash(password), user["id"]),
            )
            db.commit()
            session.clear()
            return "Password Updated\n"
        abort(Response(error, 403))
    abort(Response(error, 406))


@bp.delete("/removeAccount")
@login_required
def delete_logg():
    error = None
    detail = request.get_json()
    if "password" in detail:
        password = detail["password"]
    else:
        error = "Password required\n"

    if error is None:
        user = g.user
        if not check_password_hash(user["password"], password):
            error = "Wrong password"

        if error is None:
            db = get_db()
            db.execute("DELETE FROM user WHERE id = ?", (g.user["id"],))
            db.commit()
            session.clear()
            return "Account removed\n"
        abort(Response(error, 403))
    abort(Response(error, 406))
