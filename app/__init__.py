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
                if user.must_reset_password:
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
        if not current_user.can_view_theory():
            flash(TRANSLATIONS.gettext("theory_access_revoked", get_lang()), "danger")
            return redirect(url_for("dashboard"))
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
        if not current_user.can_take_tests():
            flash(TRANSLATIONS.gettext("tests_access_revoked", get_lang()), "danger")
            return redirect(url_for("dashboard"))
        lang = get_lang()
        tests = [
            test
            for test in Test.query.all()
            if test.questions
            and (
                (lang == "ru" and any(q.text_ru for q in test.questions))
                or (lang == "en" and any(q.text_en for q in test.questions))
            )
        ]
        return render_template("test_list.html", tests=tests, lang=lang)

    def parse_choices(prefix: str) -> List[str]:
        choices: List[str] = []
        index = 1
        while True:
            value = request.form.get(f"{prefix}_{index}")
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
        lang = get_lang()
        if request.method == "POST":
            question_text = request.form.get("question_text", "").strip()
            choices = parse_choices("choice")
            correct_index_raw = request.form.get("correct_index", "0")
            try:
                correct_index = int(correct_index_raw)
            except ValueError:
                correct_index = -1
            if not question_text:
                flash("All fields are required.", "danger")
            elif len(choices) < 2:
                flash("At least two answer options are required.", "danger")
            elif correct_index >= len(choices) or correct_index < 0:
                flash("Correct answer index is invalid.", "danger")
            else:
                test = Test()
                db.session.add(test)
                db.session.flush()
                question_kwargs = {
                    "test_id": test.id,
                    "correct_index": correct_index,
                }
                if lang == "ru":
                    test.title_ru = question_text[:255]
                    test.description_ru = ""
                    question_kwargs["text_ru"] = question_text
                    question_kwargs["choices_ru"] = "\n".join(choices)
                else:
                    test.title_en = question_text[:255]
                    test.description_en = ""
                    question_kwargs["text_en"] = question_text
                    question_kwargs["choices_en"] = "\n".join(choices)
                question = Question(**question_kwargs)
                db.session.add(question)
                db.session.commit()
                flash("Test added.", "success")
                return redirect(url_for("test_list"))
        return render_template("admin_test_form.html", lang=lang)

    @app.route("/tests/<int:test_id>", methods=["GET", "POST"])
    @login_required
    def take_test(test_id: int) -> Any:
        if not current_user.can_take_tests():
            flash(TRANSLATIONS.gettext("tests_access_revoked", get_lang()), "danger")
            return redirect(url_for("dashboard"))
        test = Test.query.get_or_404(test_id)
        lang = get_lang()
        if lang == "ru" and not any(q.text_ru for q in test.questions):
            flash(TRANSLATIONS.gettext("test_unavailable_language", lang), "warning")
            return redirect(url_for("test_list"))
        if lang == "en" and not any(q.text_en for q in test.questions):
            flash(TRANSLATIONS.gettext("test_unavailable_language", lang), "warning")
            return redirect(url_for("test_list"))
        for question in test.questions:
            choices = question.get_choices(lang)
            if not choices:
                flash(TRANSLATIONS.gettext("test_unavailable_language", lang), "warning")
                return redirect(url_for("test_list"))
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

    @app.route("/admin/users/<int:user_id>/permissions", methods=["POST"])
    @login_required
    def admin_toggle_permissions(user_id: int) -> Any:
        if not current_user.is_admin:
            flash("Access denied.", "danger")
            return redirect(url_for("admin_users"))
        user = User.query.get_or_404(user_id)
        if user.is_admin:
            flash("Cannot change permissions for another admin.", "danger")
            return redirect(url_for("admin_users"))
        action = request.form.get("action")
        if action == "toggle_theory":
            user.can_access_theory = not user.can_access_theory
            message_key = "permission_theory_restored" if user.can_access_theory else "permission_theory_revoked"
        elif action == "toggle_tests":
            user.can_access_tests = not user.can_access_tests
            message_key = "permission_tests_restored" if user.can_access_tests else "permission_tests_revoked"
        else:
            flash("Unknown action.", "danger")
            return redirect(url_for("admin_users"))
        db.session.commit()
        flash(TRANSLATIONS.gettext(message_key, get_lang()), "success")
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
            restriction = (
                PasswordRestriction(restriction_value)
                if restriction_value
                else None
            )
            admin_require_letter = bool(request.form.get("admin_require_letter"))
            admin_require_digit = bool(request.form.get("admin_require_digit"))
            admin_require_arithmetic = bool(request.form.get("admin_require_arithmetic"))
            auth_service.update_policy(
                restriction,
                admin_require_letter,
                admin_require_digit,
                admin_require_arithmetic,
            )
            flash(TRANSLATIONS.gettext("password_policy_updated", get_lang()), "success")
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
            auth_service.register_user(
                "admin",
                "",
                "hash",
                is_admin=True,
                must_reset=True,
            )
        if TheoryArticle.query.count() == 0:
            articles_seed = [
                {
                    "title_en": "Caesar Shift",
                    "title_ru": "Шифр Цезаря",
                    "content_en": "The Caesar cipher shifts every letter by a fixed offset. With shift 3 the word `HELLO` becomes `KHOOR`. To decrypt you subtract the same shift and return to the original message.",
                    "content_ru": "Шифр Цезаря сдвигает каждую букву на фиксированное число. Например, при сдвиге 3 слово `ПРИВЕТ` превращается в `ТУЛЕИХ`. Для расшифровки символы сдвигаются обратно на то же число.",
                },
                {
                    "title_en": "Vigenere Cipher",
                    "title_ru": "Шифр Виженера",
                    "content_en": "The Vigenere cipher repeats a keyword to choose different shifts for each letter. With key `KEY` the text `HELLO` turns into `RIJVS`. Decryption subtracts the same sequence of shifts to restore the message.",
                    "content_ru": "Шифр Виженера использует повторяющийся ключ для выбора сдвига каждой буквы. С ключом `КОД` текст `МИР` превращается в последовательность смещённых символов. При дешифровке вычитают значения ключа.",
                },
                {
                    "title_en": "XOR Stream",
                    "title_ru": "Потоковый XOR",
                    "content_en": "The XOR cipher combines plaintext bytes with key bytes using exclusive OR. For example, `HELLO` XOR `KEY` produces a new byte sequence. Applying the same key again restores the original string.",
                    "content_ru": "Потоковый XOR объединяет байты текста и ключа операцией исключающего ИЛИ. Например, `DATA` XOR `KEY` даёт шифртекст, а повторное применение ключа восстанавливает оригинал.",
                },
                {
                    "title_en": "Reversed Base64",
                    "title_ru": "Перевёрнутый Base64",
                    "content_en": "The method reverses the plaintext and then encodes it with Base64. Encrypting `HELLO` yields the Base64 encoding of `OLLEH`. Decryption decodes from Base64 and reverses the string again.",
                    "content_ru": "Метод переворачивает текст и кодирует его в Base64. Например, `ПРИВЕТ` превращается в Base64 от строки `ТЕВИРП`. Расшифровка включает декодирование и обратный переворот.",
                },
                {
                    "title_en": "SHA-256 Digest",
                    "title_ru": "Хэш SHA-256",
                    "content_en": "SHA-256 produces an irreversible hash. For `password` it returns the string `5e8848...`. Verification recomputes the hash and compares it with the stored value.",
                    "content_ru": "SHA-256 создаёт необратимый хэш фиксированной длины. Например, для `пароль` формируется значение `1bc29b...`. Проверка требует заново вычислить хэш и сравнить с сохранённым.",
                },
                {
                    "title_en": "Affine Cipher",
                    "title_ru": "Аффинный шифр",
                    "content_en": "The affine cipher multiplies and shifts character codes using `E(x) = (ax + b) mod m`. With `a=5` and `b=8` the letter `A` becomes `I`. The inverse function with the modular inverse recovers the text.",
                    "content_ru": "Аффинный шифр умножает и сдвигает коды символов по формуле `E(x) = (ax + b) mod m`. Например, при `a=5` и `b=8` буква `А` превращается в `И`. Обратная функция возвращает исходные символы.",
                },
                {
                    "title_en": "RSA Mini",
                    "title_ru": "Упрощённый RSA",
                    "content_en": "RSA uses a public/private key pair. In a compact example the public key `(n=3233, e=17)` encrypts the letter `H` into `3000`. The private key `(d=2753)` raises the number back and restores `H`.",
                    "content_ru": "RSA использует пару открытого и закрытого ключей. В мини-примере ключ `(n=3233, e=17)` превращает `Д` в число, а закрытый ключ `(d=2753)` возводит его в степень и восстанавливает символ.",
                },
                {
                    "title_en": "ElGamal Mini",
                    "title_ru": "Упрощённый Эль-Гамаль",
                    "content_en": "ElGamal operates in modular arithmetic. Every byte becomes a pair `(r, t)` generated with a random exponent. Decryption multiplies `t` by the modular inverse of `r` to recover the original byte.",
                    "content_ru": "Эль-Гамаль основан на модульной арифметике. Для каждого байта вычисляется пара `(r, t)` с секретным параметром. При расшифровке используется модульный обратный, чтобы вернуть исходный байт.",
                },
            ]
            for payload in articles_seed:
                article = TheoryArticle(**payload)
                db.session.add(article)
            db.session.commit()

    return app
