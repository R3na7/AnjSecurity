from __future__ import annotations

import time
from typing import Any, Dict, List

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from app.config import get_config
from app.models import (
    PasswordRestriction,
    Question,
    Test,
    TestResult,
    TheoryArticle,
    User,
    db,
)
from app.services.auth_service import AuthService, login_manager
from app.services.encryption_service import EncryptionService
from app.services.localization import TRANSLATIONS


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(get_config())

    db.init_app(app)
    login_manager.init_app(app)

    encryption_service = EncryptionService()
    auth_service = AuthService()

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
            "algorithm_categories": encryption_service.categories(),
            "PasswordRestriction": PasswordRestriction,
        }

    def get_algorithm_or_404(slug: str, category: str | None = None):
        try:
            algorithm = encryption_service.get_algorithm(slug)
        except KeyError:
            abort(404)
        if category and algorithm.info.category != category:
            abort(404)
        return algorithm

    def validate_category(category: str) -> str:
        if category not in {"symmetric", "asymmetric"}:
            abort(404)
        return category

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
            if not username or not password:
                flash("All fields are required.", "danger")
            elif User.query.filter_by(username=username).first():
                flash("Username already exists.", "danger")
            else:
                user = User(username=username)
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
                            is_admin=False,
                        )
                    except ValueError as exc:
                        flash(str(exc), "danger")
                    else:
                        flash(
                            "Registration successful. Please log in.",
                            "success",
                        )
                        return redirect(url_for("login"))
        return render_template("register.html")

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

    @app.route("/algorithms")
    def algorithms_root() -> Any:
        return redirect(url_for("algorithm_category", category="symmetric"))

    @app.route("/algorithms/<category>")
    def algorithm_category(category: str) -> str:
        category = validate_category(category)
        algorithms = encryption_service.algorithms_by_category(category)
        return render_template(
            "algorithm_category.html",
            category=category,
            algorithms=algorithms,
        )

    @app.route("/algorithms/<category>/<slug>")
    def algorithm_detail(category: str, slug: str) -> str:
        category = validate_category(category)
        algorithm = get_algorithm_or_404(slug, category)
        return render_template(
            "algorithm_detail.html",
            category=category,
            algorithm=algorithm,
        )

    @app.route("/algorithms/<category>/<slug>/theory", methods=["GET", "POST"])
    @login_required
    def theory_list(category: str, slug: str) -> str:
        category = validate_category(category)
        algorithm = get_algorithm_or_404(slug, category)
        if not current_user.can_view_theory():
            flash(TRANSLATIONS.gettext("theory_access_revoked", get_lang()), "danger")
            return redirect(url_for("dashboard"))
        lang = get_lang()
        articles = (
            TheoryArticle.query.filter_by(algorithm_slug=algorithm.info.slug)
            .order_by(TheoryArticle.created_at.desc())
            .all()
        )
        practice_material = encryption_service.get_practice_material(algorithm.info.slug)
        practice_result: str | None = None
        practice_error: str | None = None
        practice_form = {"text": "", "key": "", "operation": "encrypt"}
        active_tab = request.args.get("tab", "materials")
        if request.method == "POST":
            active_tab = "practice"
            practice_form["text"] = request.form.get("practice_text", "")
            practice_form["key"] = request.form.get("practice_key", "").strip()
            practice_form["operation"] = request.form.get("practice_operation", "encrypt")
            try:
                key_value = practice_form["key"] if algorithm.requires_key else None
                if algorithm.requires_key and not key_value:
                    raise ValueError(TRANSLATIONS.gettext("encryption_key_required", lang))
                wants_decrypt = practice_form["operation"] == "decrypt"
                if wants_decrypt and algorithm.supports_decrypt:
                    practice_result = algorithm.decrypt(practice_form["text"], key_value)
                else:
                    practice_result = algorithm.encrypt(practice_form["text"], key_value)
            except Exception as exc:  # noqa: BLE001
                practice_error = str(exc)
        return render_template(
            "theory_list.html",
            algorithm=algorithm,
            category=category,
            articles=articles,
            lang=lang,
            practice_material=practice_material,
            practice_result=practice_result,
            practice_error=practice_error,
            practice_form=practice_form,
            active_tab=active_tab,
        )

    @app.route("/algorithms/<category>/<slug>/theory/add", methods=["GET", "POST"])
    @login_required
    def add_theory(category: str, slug: str) -> Any:
        category = validate_category(category)
        algorithm = get_algorithm_or_404(slug, category)
        if not current_user.is_admin:
            flash("Access denied.", "danger")
            return redirect(url_for("theory_list", category=category, slug=algorithm.info.slug))
        if request.method == "POST":
            title_en = request.form.get("title_en", "").strip()
            title_ru = request.form.get("title_ru", "").strip()
            content_en = request.form.get("content_en", "").strip()
            content_ru = request.form.get("content_ru", "").strip()
            if not all([title_en, title_ru, content_en, content_ru]):
                flash("All fields are required.", "danger")
            else:
                article = TheoryArticle(
                    algorithm_slug=algorithm.info.slug,
                    title_en=title_en,
                    title_ru=title_ru,
                    content_en=content_en,
                    content_ru=content_ru,
                )
                db.session.add(article)
                db.session.commit()
                flash("Theory article added.", "success")
                return redirect(
                    url_for("theory_list", category=category, slug=algorithm.info.slug)
                )
        return render_template(
            "theory_form.html",
            algorithm=algorithm,
            category=category,
        )

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

    @app.route("/algorithms/<category>/<slug>/tests")
    @login_required
    def test_list(category: str, slug: str) -> str:
        category = validate_category(category)
        algorithm = get_algorithm_or_404(slug, category)
        if not current_user.can_take_tests():
            flash(TRANSLATIONS.gettext("tests_access_revoked", get_lang()), "danger")
            return redirect(url_for("dashboard"))
        lang = get_lang()
        tests_data = []
        tests = Test.query.filter_by(algorithm_slug=algorithm.info.slug).all()
        for test in tests:
            has_language = any(
                (
                    (lang == "ru" and question.text_ru)
                    or (lang == "en" and question.text_en)
                )
                for question in test.questions
            )
            if not has_language:
                continue
            attempts_used = (
                TestResult.query.filter_by(user_id=current_user.id, test_id=test.id)
                .count()
            )
            latest_result = (
                TestResult.query.filter_by(user_id=current_user.id, test_id=test.id)
                .order_by(TestResult.submitted_at.desc())
                .first()
            )
            tests_data.append(
                {
                    "test": test,
                    "attempts_used": attempts_used,
                    "attempts_left": max(0, 3 - attempts_used),
                    "latest_result": latest_result,
                }
            )
        return render_template(
            "test_list.html",
            algorithm=algorithm,
            category=category,
            tests_data=tests_data,
            lang=lang,
        )

    @app.route("/algorithms/<category>/<slug>/tests/new", methods=["GET", "POST"])
    @login_required
    def create_test(category: str, slug: str) -> Any:
        category = validate_category(category)
        algorithm = get_algorithm_or_404(slug, category)
        if not current_user.is_admin:
            flash("Access denied.", "danger")
            return redirect(url_for("test_list", category=category, slug=algorithm.info.slug))
        lang = get_lang()
        if request.method == "POST":
            title_value = request.form.get("title", "").strip()
            total_points_raw = request.form.get("total_points", "0")
            time_limit_raw = request.form.get("time_limit", "0")
            try:
                total_points = int(total_points_raw)
            except ValueError:
                total_points = 0
            try:
                time_limit_minutes = int(time_limit_raw)
            except ValueError:
                time_limit_minutes = 0
            if total_points <= 0 or time_limit_minutes <= 0:
                flash(
                    "Количество баллов и лимит времени должны быть положительными числами."
                    if lang == "ru"
                    else "Total points and time limit must be positive numbers.",
                    "danger",
                )
            else:
                test = Test(
                    algorithm_slug=algorithm.info.slug,
                    total_points=total_points,
                    time_limit_seconds=time_limit_minutes * 60,
                )
                if lang == "ru":
                    test.title_ru = title_value
                else:
                    test.title_en = title_value
                db.session.add(test)
                db.session.commit()
                flash(
                    "Тест создан. Добавьте вопросы." if lang == "ru" else "Test created. Add questions now.",
                    "success",
                )
                return redirect(
                    url_for(
                        "add_test_question",
                        category=category,
                        slug=algorithm.info.slug,
                        test_id=test.id,
                    )
                )
        return render_template(
            "admin_test_create.html",
            algorithm=algorithm,
            category=category,
            lang=lang,
        )

    @app.route(
        "/algorithms/<category>/<slug>/tests/<int:test_id>/questions/new",
        methods=["GET", "POST"],
    )
    @login_required
    def add_test_question(category: str, slug: str, test_id: int) -> Any:
        category = validate_category(category)
        algorithm = get_algorithm_or_404(slug, category)
        if not current_user.is_admin:
            flash("Access denied.", "danger")
            return redirect(url_for("test_list", category=category, slug=algorithm.info.slug))
        test = Test.query.get_or_404(test_id)
        if test.algorithm_slug != algorithm.info.slug:
            abort(404)
        lang = get_lang()
        if request.method == "POST":
            question_text = request.form.get("question_text", "").strip()
            choices = parse_choices("choice")
            correct_choice_position = request.form.get("correct_choice")
            if not question_text or len(choices) < 2:
                flash(
                    "Нужен текст вопроса и минимум два варианта ответа."
                    if lang == "ru"
                    else "Question text and at least two answers are required.",
                    "danger",
                )
            else:
                try:
                    correct_position = int(correct_choice_position)
                except (TypeError, ValueError):
                    correct_position = -1
                correct_index = correct_position - 1
                if correct_index < 0 or correct_index >= len(choices):
                    flash(
                        "Выберите номер правильного ответа из списка вариантов."
                        if lang == "ru"
                        else "Select the correct answer from the provided options.",
                        "danger",
                    )
                else:
                    question_kwargs = {
                        "test_id": test.id,
                        "correct_index": correct_index,
                    }
                    if lang == "ru":
                        question_kwargs["text_ru"] = question_text
                        question_kwargs["choices_ru"] = "\n".join(choices)
                    else:
                        question_kwargs["text_en"] = question_text
                        question_kwargs["choices_en"] = "\n".join(choices)
                    question = Question(**question_kwargs)
                    db.session.add(question)
                    db.session.commit()
                    flash("Вопрос добавлен." if lang == "ru" else "Question added.", "success")
                    if request.form.get("add_another"):
                        return redirect(
                            url_for(
                                "add_test_question",
                                category=category,
                                slug=algorithm.info.slug,
                                test_id=test.id,
                            )
                        )
                    return redirect(
                        url_for(
                            "test_list",
                            category=category,
                            slug=algorithm.info.slug,
                        )
                    )
        return render_template(
            "admin_question_form.html",
            algorithm=algorithm,
            category=category,
            test=test,
            lang=lang,
        )

    @app.route(
        "/algorithms/<category>/<slug>/tests/<int:test_id>",
        methods=["GET", "POST"],
    )
    @login_required
    def take_test(category: str, slug: str, test_id: int) -> Any:
        category = validate_category(category)
        algorithm = get_algorithm_or_404(slug, category)
        if not current_user.can_take_tests():
            flash(TRANSLATIONS.gettext("tests_access_revoked", get_lang()), "danger")
            return redirect(url_for("dashboard"))
        test = Test.query.get_or_404(test_id)
        if test.algorithm_slug != algorithm.info.slug:
            abort(404)
        lang = get_lang()
        questions = [
            question
            for question in test.questions
            if (lang == "ru" and question.text_ru) or (lang == "en" and question.text_en)
        ]
        if not questions:
            flash(TRANSLATIONS.gettext("test_unavailable_language", lang), "warning")
            return redirect(url_for("test_list", category=category, slug=algorithm.info.slug))
        for question in questions:
            if not question.get_choices(lang):
                flash(TRANSLATIONS.gettext("test_unavailable_language", lang), "warning")
                return redirect(
                    url_for("test_list", category=category, slug=algorithm.info.slug)
                )
        attempts_used = (
            TestResult.query.filter_by(user_id=current_user.id, test_id=test.id)
            .count()
        )
        if attempts_used >= 3:
            flash(TRANSLATIONS.gettext("test_attempts_exhausted", get_lang()), "warning")
            return redirect(url_for("test_list", category=category, slug=algorithm.info.slug))
        session_key = f"test_{test.id}_start"
        if request.method == "GET":
            session[session_key] = time.time()
        if request.method == "POST":
            started_at = session.pop(session_key, None)
            timed_out = False
            if started_at is None:
                timed_out = True
            else:
                timed_out = time.time() - started_at > test.time_limit_seconds
            answers_details: List[dict[str, Any]] = []
            correct_count = 0
            for question in questions:
                choices = question.get_choices(lang)
                answer_value = request.form.get(f"question_{question.id}")
                selected_index = None
                if answer_value is not None:
                    try:
                        selected_index = int(answer_value)
                    except ValueError:
                        selected_index = None
                is_correct = selected_index == question.correct_index
                if is_correct:
                    correct_count += 1
                selected_text = (
                    choices[selected_index] if selected_index is not None and 0 <= selected_index < len(choices) else None
                )
                answers_details.append(
                    {
                        "question": question.get_text(lang),
                        "selected": selected_text,
                        "correct": question.get_correct_choice(lang),
                        "is_correct": bool(is_correct),
                    }
                )
            total_questions = len(questions)
            score_fraction = (correct_count / total_questions) if total_questions else 0
            score_points = int(round(score_fraction * test.total_points))
            if timed_out:
                score_points = min(score_points, test.total_points)
            score_points = max(0, min(score_points, test.total_points))
            attempt_number = attempts_used + 1
            result = TestResult(
                test_id=test.id,
                user_id=current_user.id,
                score_points=score_points,
                max_points=test.total_points,
                correct_answers=correct_count,
                incorrect_answers=total_questions - correct_count,
                attempt_number=attempt_number,
            )
            result.save_answers(answers_details)
            db.session.add(result)
            db.session.commit()
            return render_template(
                "test_result.html",
                algorithm=algorithm,
                category=category,
                test=test,
                lang=lang,
                answers=answers_details,
                score_points=score_points,
                max_points=test.total_points,
                attempt_number=attempt_number,
                attempts_left=max(0, 3 - attempt_number),
                timed_out=timed_out,
            )
        return render_template(
            "test_detail.html",
            algorithm=algorithm,
            category=category,
            test=test,
            lang=lang,
            questions=questions,
        )

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
        if not username or not password:
            flash("All fields are required.", "danger")
        elif User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
        else:
            user = User(username=username)
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
                        is_admin=False,
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
            if not auth_service.plaintext_meets_restriction(current_user, new_password):
                flash(TRANSLATIONS.gettext("password_policy_failed", get_lang()), "danger")
            else:
                try:
                    auth_service.change_password(
                        current_user,
                        new_password,
                    )
                except ValueError as exc:
                    flash(str(exc), "danger")
                else:
                    flash("Password updated.", "success")
                    return redirect(url_for("dashboard"))
        return render_template("change_password.html")

    with app.app_context():
        db.create_all()
        if User.query.filter_by(is_admin=True).count() == 0:
            auth_service.register_user(
                "admin",
                "",
                is_admin=True,
                must_reset=True,
            )
    return app
