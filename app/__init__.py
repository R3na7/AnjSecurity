from __future__ import annotations

from typing import Any, Dict, List

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from app.config import get_config
from app.models import PasswordRestriction, Question, Test, TheoryArticle, User, db
from app.services.auth_service import AuthService, login_manager
from app.services.encryption_service import EncryptionService
from app.services.localization import TRANSLATIONS


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(get_config())

    db.init_app(app)
    login_manager.init_app(app)

    encryption_service = EncryptionService()
    auth_service = AuthService(encryption_service)

    @app.before_request
    def ensure_language() -> None:
        if "lang" not in session:
            session["lang"] = "ru"

    @app.context_processor
    def inject_globals() -> Dict[str, Any]:
        lang = session.get("lang", "ru")
        return {
            "t": lambda key: TRANSLATIONS.gettext(key, lang),
            "lang": lang,
            "algorithms": list(encryption_service.all_algorithms()),
            "PasswordRestriction": PasswordRestriction,
        }

    def get_lang() -> str:
        return session.get("lang", "ru")

    @app.route("/")
    def home() -> str:
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return render_template("home.html")

    @app.route("/set-language/<lang>")
    def set_language(lang: str) -> Any:
        session["lang"] = "en" if lang == "en" else "ru"
        return redirect(request.referrer or url_for("home"))

    @app.route("/register", methods=["GET", "POST"])
    def register() -> str:
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            algorithm = request.form.get("algorithm", "")
            algorithm_key_raw = request.form.get("algorithm_key", "").strip()
            if not username or not password or not algorithm:
                flash("All fields are required.", "danger")
            elif User.query.filter_by(username=username).first():
                flash("Username already exists.", "danger")
            else:
                try:
                    algorithm_obj = encryption_service.get_algorithm(algorithm)
                except KeyError:
                    flash("Unknown algorithm selected.", "danger")
                else:
                    key_to_store = algorithm_key_raw if algorithm_obj.requires_key else None
                    if algorithm_obj.requires_key and not algorithm_key_raw:
                        flash(
                            TRANSLATIONS.gettext("encryption_key_required", get_lang()),
                            "danger",
                        )
                    else:
                        user = User(
                            username=username,
                            encryption_algorithm=algorithm,
                            encryption_key=key_to_store,
                        )
                        if not auth_service.plaintext_meets_restriction(user, password):
                            flash(
                                TRANSLATIONS.gettext(
                                    "password_policy_failed", get_lang()
                                ),
                                "warning",
                            )
                        else:
                            try:
                                auth_service.register_user(
                                    username,
                                    password,
                                    algorithm,
                                    is_admin=False,
                                    encryption_key=key_to_store,
                                )
                            except ValueError as exc:
                                flash(str(exc), "danger")
                            else:
                                flash(
                                    "Registration successful. Please log in.",
                                    "success",
                                )
                                return redirect(url_for("login"))
        return render_template("register.html", algorithms=encryption_service.all_algorithms())

    @app.route("/login", methods=["GET", "POST"])
    def login() -> str:
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = auth_service.authenticate(username, password)
            if not user:
                flash("Invalid credentials or account blocked.", "danger")
            else:
                login_user(user)
                policy = auth_service.ensure_policy().restriction
                if user.must_reset_password and policy is not None:
                    flash(TRANSLATIONS.gettext("password_reset_required", get_lang()), "warning")
                    return redirect(url_for("change_password"))
                return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout() -> Any:
        logout_user()
        flash("You have been logged out.", "info")
        return redirect(url_for("home"))

    @app.route("/dashboard")
    @login_required
    def dashboard() -> str:
        return render_template("dashboard.html")

    @app.route("/theory")
    @login_required
    def theory_list() -> str:
        lang = get_lang()
        articles = TheoryArticle.query.order_by(TheoryArticle.created_at.desc()).all()
        return render_template("theory_list.html", articles=articles, lang=lang)

    @app.route("/theory/add", methods=["GET", "POST"])
    @login_required
    def add_theory() -> Any:
        if not current_user.is_admin:
            flash("Access denied.", "danger")
            return redirect(url_for("theory_list"))
        if request.method == "POST":
            title_en = request.form.get("title_en", "").strip()
            title_ru = request.form.get("title_ru", "").strip()
            content_en = request.form.get("content_en", "").strip()
            content_ru = request.form.get("content_ru", "").strip()
            if not all([title_en, title_ru, content_en, content_ru]):
                flash("All fields are required.", "danger")
            else:
                article = TheoryArticle(
                    title_en=title_en,
                    title_ru=title_ru,
                    content_en=content_en,
                    content_ru=content_ru,
                )
                db.session.add(article)
                db.session.commit()
                flash("Theory article added.", "success")
                return redirect(url_for("theory_list"))
        return render_template("theory_form.html")

    @app.route("/tests")
    @login_required
    def test_list() -> str:
        tests = Test.query.all()
        return render_template("test_list.html", tests=tests, lang=get_lang())

    def parse_choices(prefix: str) -> List[str]:
        choices: List[str] = []
        index = 1
        while True:
            value = request.form.get(f"{prefix}_choice_{index}")
            if value is None:
                break
            if value.strip():
                choices.append(value.strip())
            index += 1
        return choices

    @app.route("/tests/add", methods=["GET", "POST"])
    @login_required
    def add_test() -> Any:
        if not current_user.is_admin:
            flash("Access denied.", "danger")
            return redirect(url_for("test_list"))
        if request.method == "POST":
            title_en = request.form.get("title_en", "").strip()
            title_ru = request.form.get("title_ru", "").strip()
            description_en = request.form.get("description_en", "").strip()
            description_ru = request.form.get("description_ru", "").strip()
            question_text_en = request.form.get("question_text_en", "").strip()
            question_text_ru = request.form.get("question_text_ru", "").strip()
            choices_en = parse_choices("en")
            choices_ru = parse_choices("ru")
            correct_index_raw = request.form.get("correct_index", "0")
            try:
                correct_index = int(correct_index_raw)
            except ValueError:
                correct_index = -1
            if not all([title_en, title_ru, description_en, description_ru, question_text_en, question_text_ru]):
                flash("All fields are required.", "danger")
            elif len(choices_en) < 2 or len(choices_ru) < 2:
                flash("At least two answer options are required.", "danger")
            elif correct_index >= len(choices_en) or correct_index < 0:
                flash("Correct answer index is invalid.", "danger")
            else:
                test = Test(
                    title_en=title_en,
                    title_ru=title_ru,
                    description_en=description_en,
                    description_ru=description_ru,
                )
                db.session.add(test)
                db.session.flush()
                question = Question(
                    test_id=test.id,
                    text_en=question_text_en,
                    text_ru=question_text_ru,
                    choices_en="\n".join(choices_en),
                    choices_ru="\n".join(choices_ru),
                    correct_index=correct_index,
                )
                db.session.add(question)
                db.session.commit()
                flash("Test added.", "success")
                return redirect(url_for("test_list"))
        return render_template("admin_test_form.html")

    @app.route("/tests/<int:test_id>", methods=["GET", "POST"])
    @login_required
    def take_test(test_id: int) -> Any:
        test = Test.query.get_or_404(test_id)
        lang = get_lang()
        if request.method == "POST":
            score = 0
            total = len(test.questions)
            for question in test.questions:
                answer = request.form.get(f"question_{question.id}")
                if answer is not None and int(answer) == question.correct_index:
                    score += 1
            flash(f"Result: {score}/{total}", "info")
            return redirect(url_for("test_list"))
        return render_template("test_detail.html", test=test, lang=lang)

    @app.route("/admin/users")
    @login_required
    def admin_users() -> Any:
        if not current_user.is_admin:
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))
        users = User.query.order_by(User.username).all()
        return render_template("admin_users.html", users=users)

    @app.route("/admin/users/create", methods=["POST"])
    @login_required
    def admin_create_user() -> Any:
        if not current_user.is_admin:
            flash("Access denied.", "danger")
            return redirect(url_for("admin_users"))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        algorithm = request.form.get("algorithm", "")
        algorithm_key_raw = request.form.get("algorithm_key", "").strip()
        if not username or not password or not algorithm:
            flash("All fields are required.", "danger")
        elif User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
        else:
            try:
                algorithm_obj = encryption_service.get_algorithm(algorithm)
            except KeyError:
                flash("Unknown algorithm selected.", "danger")
            else:
                key_to_store = algorithm_key_raw if algorithm_obj.requires_key else None
                if algorithm_obj.requires_key and not algorithm_key_raw:
                    flash(
                        TRANSLATIONS.gettext("encryption_key_required", get_lang()),
                        "danger",
                    )
                else:
                    user = User(
                        username=username,
                        encryption_algorithm=algorithm,
                        encryption_key=key_to_store,
                    )
                    if not auth_service.plaintext_meets_restriction(user, password):
                        flash(
                            TRANSLATIONS.gettext("password_policy_failed", get_lang()),
                            "warning",
                        )
                    else:
                        try:
                            auth_service.register_user(
                                username,
                                password,
                                algorithm,
                                encryption_key=key_to_store,
                            )
                        except ValueError as exc:
                            flash(str(exc), "danger")
                        else:
                            flash("User created.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
    @login_required
    def admin_toggle_user(user_id: int) -> Any:
        if not current_user.is_admin:
            flash("Access denied.", "danger")
            return redirect(url_for("admin_users"))
        user = User.query.get_or_404(user_id)
        if user.is_admin:
            flash("Cannot block another admin.", "danger")
        else:
            user.is_blocked = not user.is_blocked
            db.session.commit()
            flash("User status updated.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/admin/password-policy", methods=["GET", "POST"])
    @login_required
    def admin_password_policy() -> Any:
        if not current_user.is_admin:
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))
        policy = auth_service.ensure_policy()
        if request.method == "POST":
            restriction_value = request.form.get("restriction")
            if restriction_value:
                restriction = PasswordRestriction(restriction_value)
            else:
                restriction = None
            auth_service.set_policy(restriction)
            flash("Password policy updated.", "success")
            return redirect(url_for("admin_password_policy"))
        return render_template("admin_password_policy.html", policy=policy)

    @app.route("/change-password", methods=["GET", "POST"])
    @login_required
    def change_password() -> Any:
        if request.method == "POST":
            new_password = request.form.get("password", "")
            new_key_raw = request.form.get("algorithm_key", "")
            algorithm_obj = encryption_service.get_algorithm(
                current_user.encryption_algorithm
            )
            if not auth_service.plaintext_meets_restriction(current_user, new_password):
                flash(TRANSLATIONS.gettext("password_policy_failed", get_lang()), "danger")
            else:
                key_to_store = (
                    new_key_raw.strip()
                    if new_key_raw.strip()
                    else current_user.encryption_key
                )
                if algorithm_obj.requires_key and not key_to_store:
                    flash(
                        TRANSLATIONS.gettext("encryption_key_required", get_lang()),
                        "danger",
                    )
                else:
                    try:
                        auth_service.change_password(
                            current_user,
                            new_password,
                            new_key_raw.strip() if new_key_raw.strip() else None,
                        )
                    except ValueError as exc:
                        flash(str(exc), "danger")
                    else:
                        flash("Password updated.", "success")
                        return redirect(url_for("dashboard"))
        algorithm = encryption_service.get_algorithm(current_user.encryption_algorithm)
        return render_template("change_password.html", algorithm=algorithm)

    with app.app_context():
        db.create_all()
        if User.query.filter_by(is_admin=True).count() == 0:
            auth_service.register_user("admin", "Admin123+", "hash", is_admin=True)

    return app
