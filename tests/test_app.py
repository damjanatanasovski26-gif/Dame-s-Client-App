import os
import tempfile
import unittest
from datetime import date
from io import BytesIO
from unittest.mock import Mock, patch

from werkzeug.security import generate_password_hash

from app import app, db, Client, FoodItem, FoodLogEntry, Measurement, Payment, SessionLog, User, parse_label_text, scan_label_file_text, seed_reference_foods


class TrainerAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fd, cls.db_path = tempfile.mkstemp(prefix="trainer_test_", suffix=".db")
        os.close(fd)

        app.config.update(
            TESTING=True,
            SQLALCHEMY_DATABASE_URI=f"sqlite:///{cls.db_path}",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            CSRF_ENABLED=False,
        )

    @classmethod
    def tearDownClass(cls):
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
        if os.path.exists(cls.db_path):
            os.remove(cls.db_path)

    def setUp(self):
        self.client = app.test_client()
        with app.app_context():
            db.drop_all()
            db.create_all()

    def tearDown(self):
        with app.app_context():
            db.session.remove()

    def _create_client(self, name="Client A", weekly_sessions=3):
        with app.app_context():
            c = Client(name=name, weekly_sessions=weekly_sessions)
            db.session.add(c)
            db.session.commit()
            return c.id

    def _create_user(self, username, password, role="client", client_id=None):
        with app.app_context():
            u = User(
                username=username,
                password_hash=generate_password_hash(password),
                role=role,
                client_id=client_id,
            )
            db.session.add(u)
            db.session.commit()
            return u.id

    def _login(self, username, password):
        return self.client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=True,
        )

    def test_client_payments_tab_redirects_to_info(self):
        client_id = self._create_client(name="Alice")
        self._create_user("alice_user", "pass123", role="client", client_id=client_id)

        self._login("alice_user", "pass123")
        resp = self.client.get(f"/client/{client_id}?tab=payments", follow_redirects=False)

        self.assertEqual(resp.status_code, 302)
        location = resp.headers.get("Location", "")
        self.assertIn(f"/client/{client_id}", location)
        self.assertIn("tab=info", location)

    def test_admin_can_create_client_login(self):
        client_id = self._create_client(name="Bob")
        self._create_user("admin", "admin123", role="admin")

        self._login("admin", "admin123")
        self.client.post(
            f"/client/{client_id}/create-login",
            data={"username": "bob_client", "password": "temp123"},
            follow_redirects=True,
        )

        with app.app_context():
            created = User.query.filter_by(username="bob_client").first()
            self.assertIsNotNone(created)
            self.assertEqual(created.role, "client")
            self.assertEqual(created.client_id, client_id)

    def test_session_limit_blocks_extra_session(self):
        client_id = self._create_client(name="Charlie", weekly_sessions=3)
        self._create_user("admin", "admin123", role="admin")
        self._login("admin", "admin123")

        for i in range(3):
            resp = self.client.post(
                f"/client/{client_id}/sessions/add",
                data={"note": f"session {i + 1}"},
                follow_redirects=True,
            )
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Session logged", resp.data)

        blocked = self.client.post(
            f"/client/{client_id}/sessions/add",
            data={"note": "session 4"},
            follow_redirects=True,
        )
        self.assertEqual(blocked.status_code, 200)
        self.assertIn(b"Weekly limit reached", blocked.data)

        with app.app_context():
            self.assertEqual(SessionLog.query.filter_by(client_id=client_id).count(), 3)

    def test_admin_cannot_delete_record_using_wrong_client_path(self):
        client_a = self._create_client(name="A")
        client_b = self._create_client(name="B")
        self._create_user("admin", "admin123", role="admin")
        self._login("admin", "admin123")

        with app.app_context():
            m = Measurement(client_id=client_a)
            s = SessionLog(client_id=client_a, note="test")
            p = Payment(
                client_id=client_a,
                start_date=date(2026, 1, 1),
                months=1,
                sessions_per_week=3,
                monthly_price=5000,
                amount_paid=5000,
            )
            db.session.add_all([m, s, p])
            db.session.commit()
            m_id, s_id, p_id = m.id, s.id, p.id

        r1 = self.client.post(f"/client/{client_b}/stats/delete/{m_id}", data={}, follow_redirects=False)
        r2 = self.client.post(f"/client/{client_b}/sessions/delete/{s_id}", data={}, follow_redirects=False)
        r3 = self.client.post(f"/client/{client_b}/payments/delete/{p_id}", data={}, follow_redirects=False)

        self.assertEqual(r1.status_code, 404)
        self.assertEqual(r2.status_code, 404)
        self.assertEqual(r3.status_code, 404)

    def test_client_cannot_open_other_client_profile(self):
        first_client_id = self._create_client(name="Dora")
        second_client_id = self._create_client(name="Evan")
        self._create_user("dora_user", "pass123", role="client", client_id=first_client_id)

        self._login("dora_user", "pass123")
        resp = self.client.get(f"/client/{second_client_id}", follow_redirects=False)

        self.assertEqual(resp.status_code, 403)

    def test_deactivated_user_cannot_login(self):
        client_id = self._create_client(name="Frank")
        self._create_user("frank_user", "pass123", role="disabled", client_id=client_id)

        resp = self.client.post(
            "/login",
            data={"username": "frank_user", "password": "pass123"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Account is deactivated", resp.data)

    def test_csrf_blocks_post_without_token_when_enabled(self):
        app.config["CSRF_ENABLED"] = True
        try:
            resp = self.client.post(
                "/login",
                data={"username": "x", "password": "y"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn(b"Invalid CSRF token", resp.data)
        finally:
            app.config["CSRF_ENABLED"] = False

    def test_login_is_locked_after_repeated_failures(self):
        self._create_user("admin", "admin123", role="admin")
        app.config["LOGIN_MAX_ATTEMPTS"] = 3
        app.config["LOGIN_WINDOW_SECONDS"] = 300
        app.config["LOGIN_LOCK_SECONDS"] = 600

        for _ in range(3):
            resp = self.client.post(
                "/login",
                data={"username": "admin", "password": "wrong-password"},
                follow_redirects=True,
            )
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Invalid username or password", resp.data)

        blocked = self.client.post(
            "/login",
            data={"username": "admin", "password": "wrong-password"},
            follow_redirects=True,
        )
        self.assertEqual(blocked.status_code, 200)
        self.assertIn(b"Too many attempts", blocked.data)

    def test_client_can_add_food_and_log_it(self):
        client_id = self._create_client(name="Nina")
        self._create_user("nina_user", "pass123", role="client", client_id=client_id)

        self._login("nina_user", "pass123")
        self.client.post(
            f"/client/{client_id}/nutrition/foods/add",
            data={
                "name": "Greek Yogurt",
                "brand": "Test Brand",
                "calories_per_100g": "63",
                "protein_per_100g": "10.2",
                "carbs_per_100g": "3.6",
                "fat_per_100g": "0.4",
                "nutrition_date": "2026-03-21",
            },
            follow_redirects=True,
        )

        with app.app_context():
            food = FoodItem.query.filter_by(client_id=client_id, name="Greek Yogurt").first()
            self.assertIsNotNone(food)
            food_id = food.id

        resp = self.client.post(
            f"/client/{client_id}/nutrition/logs/add",
            data={
                "food_id": str(food_id),
                "meal_type": "breakfast",
                "quantity_grams": "200",
                "logged_for": "2026-03-21",
                "note": "post training",
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Food logged", resp.data)
        self.assertIn(b"Greek Yogurt", resp.data)
        self.assertIn(b"126", resp.data)

        with app.app_context():
            log = FoodLogEntry.query.filter_by(client_id=client_id).first()
            self.assertIsNotNone(log)
            self.assertEqual(log.meal_type, "breakfast")
            self.assertEqual(log.logged_for.isoformat(), "2026-03-21")
            self.assertAlmostEqual(log.calories, 126.0)
            self.assertAlmostEqual(log.protein, 20.4)

    def test_calorie_target_updates_on_nutrition_tab(self):
        client_id = self._create_client(name="Omar")
        self._create_user("admin", "admin123", role="admin")
        self._login("admin", "admin123")

        resp = self.client.post(
            f"/client/{client_id}/nutrition/target",
            data={"daily_calorie_target": "2400", "nutrition_date": "2026-03-21"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Daily calorie target updated", resp.data)
        self.assertIn(b"2400 target", resp.data)

        with app.app_context():
            client = db.session.get(Client, client_id)
            self.assertEqual(client.daily_calorie_target, 2400)

    def test_ajax_calorie_target_returns_integer_macro_goals(self):
        client_id = self._create_client(name="Tara")
        self._create_user("tara_user", "pass123", role="client", client_id=client_id)
        self._login("tara_user", "pass123")

        resp = self.client.post(
            f"/client/{client_id}/nutrition/update-target-ajax",
            data={"daily_calorie_target": "2400", "nutrition_date": "2026-03-21"},
        )

        self.assertEqual(resp.status_code, 200)
        summary = resp.get_json()["nutrition_summary"]
        self.assertEqual(summary["protein_goal"], 210)
        self.assertEqual(summary["carbs_goal"], 240)
        self.assertEqual(summary["fat_goal"], 67)
        self.assertIsInstance(summary["protein_goal"], int)

    def test_can_import_food_from_search_results_stored_in_session(self):
        client_id = self._create_client(name="Iva")
        self._create_user("admin", "admin123", role="admin")
        self._login("admin", "admin123")

        with self.client.session_transaction() as sess:
            sess[f"nutrition_search_results_{client_id}"] = [{
                "name": "Skyr",
                "brand": "Imported",
                "source": "openfoodfacts",
                "source_ref": "12345",
                "barcode": "5310000000000",
                "calories_per_100g": 63.0,
                "protein_per_100g": 11.0,
                "carbs_per_100g": 3.8,
                "fat_per_100g": 0.2,
            }]

        resp = self.client.post(
            f"/client/{client_id}/nutrition/import",
            data={"result_index": "0", "nutrition_date": "2026-03-21"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Food imported into the shared library", resp.data)

        with app.app_context():
            food = FoodItem.query.filter_by(source="openfoodfacts", source_ref="12345").first()
            self.assertIsNotNone(food)
            self.assertEqual(food.barcode, "5310000000000")

    def test_parse_label_text_extracts_macros_from_english_label(self):
        parsed = parse_label_text(
            "Energy 250 kcal\nFat 10 g\nCarbohydrates 20 g\nProtein 8 g"
        )
        self.assertEqual(parsed["calories"], 250.0)
        self.assertEqual(parsed["fat"], 10.0)
        self.assertEqual(parsed["carbs"], 20.0)
        self.assertEqual(parsed["protein"], 8.0)

    def test_parse_label_text_extracts_macros_from_macedonian_label(self):
        parsed = parse_label_text(
            "\u0415\u043d\u0435\u0440\u0433\u0438\u0458\u0430 310 kcal\n"
            "\u041c\u0430\u0441\u0442\u0438 12 g\n"
            "\u0408\u0430\u0433\u043b\u0435\u0445\u0438\u0434\u0440\u0430\u0442\u0438 42 g\n"
            "\u041f\u0440\u043e\u0442\u0435\u0438\u043d\u0438 9 g"
        )
        self.assertEqual(parsed["calories"], 310.0)
        self.assertEqual(parsed["fat"], 12.0)
        self.assertEqual(parsed["carbs"], 42.0)
        self.assertEqual(parsed["protein"], 9.0)

    def test_parse_label_text_extracts_macros_from_albanian_label(self):
        parsed = parse_label_text(
            "Vlera energjetike 180 kcal\n"
            "Yndyrna 4,5 g\n"
            "Karbohidrate 22 g\n"
            "Proteina 7 g"
        )
        self.assertEqual(parsed["calories"], 180.0)
        self.assertEqual(parsed["fat"], 4.5)
        self.assertEqual(parsed["carbs"], 22.0)
        self.assertEqual(parsed["protein"], 7.0)

    def test_parse_label_text_tolerates_common_ocr_noise(self):
        parsed = parse_label_text(
            "Enep.BpeuHoci/Energy 1 33kcal659K\n"
            "Mactu | Fat Bg\n"
            "Заситени масти / Saturated fat 2g\n"
            "Protein 2g\n"
        )
        self.assertEqual(parsed["calories"], 133.0)
        self.assertEqual(parsed["fat"], 6.0)
        self.assertEqual(parsed["protein"], 2.0)

    def test_parse_label_text_pairs_columnar_google_vision_label_values(self):
        parsed = parse_label_text(
            "PER 100 g\n"
            "Energy\n"
            "Fat\n"
            "of which\n"
            "- Saturates\n"
            "Carbohydrate\n"
            "of which\n"
            "- Sugars\n"
            "Protein\n"
            "Salt\n"
            "1583 kJ/\n"
            "373 kcal\n"
            "2,4 g\n"
            "1,6 g\n"
            "9,9 g\n"
            "5,3 g\n"
            "78 g\n"
            "0,5 g"
        )
        self.assertEqual(parsed["calories"], 373.0)
        self.assertEqual(parsed["fat"], 2.4)
        self.assertEqual(parsed["carbs"], 9.9)
        self.assertEqual(parsed["protein"], 78.0)

    def test_seed_library_replaces_old_prepared_seed_items_with_raw_ingredients(self):
        with app.app_context():
            db.session.add(FoodItem(
                client_id=None,
                name="Ajvar",
                brand="Regional Starter",
                source="seed",
                source_ref="ajvar",
                calories_per_100g=122,
                protein_per_100g=1.5,
                carbs_per_100g=8.7,
                fat_per_100g=8.8,
            ))
            db.session.commit()
            seed_reference_foods()

            self.assertIsNone(FoodItem.query.filter_by(source="seed", source_ref="ajvar").first())
            self.assertIsNotNone(FoodItem.query.filter_by(source="seed", source_ref="chicken-breast-raw").first())

    def test_food_log_can_match_by_search_name_when_hidden_id_is_missing(self):
        client_id = self._create_client(name="Sara")
        self._create_user("sara_user", "pass123", role="client", client_id=client_id)
        with app.app_context():
            db.session.add(FoodItem(
                client_id=client_id,
                name="Chicken Breast",
                brand="Local",
                source="manual",
                calories_per_100g=165,
                protein_per_100g=31,
                carbs_per_100g=0,
                fat_per_100g=3.6,
            ))
            db.session.commit()

        self._login("sara_user", "pass123")
        resp = self.client.post(
            f"/client/{client_id}/nutrition/logs/add",
            data={
                "food_name": "Chicken Breast - Local",
                "meal_type": "lunch",
                "quantity_grams": "100",
                "logged_for": "2026-03-21",
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Food logged", resp.data)

    def test_ajax_food_log_returns_serialized_summary(self):
        client_id = self._create_client(name="Mila")
        self._create_user("mila_user", "pass123", role="client", client_id=client_id)
        with app.app_context():
            db.session.add(FoodItem(
                client_id=client_id,
                name="Skyr",
                brand="Plain",
                source="manual",
                calories_per_100g=63,
                protein_per_100g=11,
                carbs_per_100g=3.8,
                fat_per_100g=0.2,
            ))
            db.session.commit()
            food_id = FoodItem.query.filter_by(client_id=client_id, name="Skyr").first().id

        self._login("mila_user", "pass123")
        resp = self.client.post(
            f"/client/{client_id}/nutrition/log-food-ajax",
            data={
                "food_id": str(food_id),
                "meal_type": "breakfast",
                "quantity_grams": "200",
                "logged_for": "2026-03-21",
                "note": "morning",
            },
        )

        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertTrue(payload["success"])
        meal = payload["nutrition_summary"]["meal_sections"][0]
        self.assertEqual(meal["label"], "Breakfast")
        self.assertEqual(meal["items"][0]["food_name"], "Skyr (Plain)")
        self.assertEqual(meal["items"][0]["note"], "morning")

    def test_custom_food_save_clears_label_draft_session(self):
        client_id = self._create_client(name="Elena")
        self._create_user("elena_user", "pass123", role="client", client_id=client_id)
        self._login("elena_user", "pass123")

        with self.client.session_transaction() as sess:
            sess[f"nutrition_label_draft_{client_id}"] = {
                "name": "Scanned Protein",
                "brand": "Draft Brand",
                "serving_label": "Scanned from label",
                "calories_per_100g": "99",
                "protein_per_100g": "12",
                "carbs_per_100g": "4",
                "fat_per_100g": "1",
            }

        resp = self.client.post(
            f"/client/{client_id}/nutrition/foods/add",
            data={
                "name": "Saved Protein",
                "brand": "Fresh Brand",
                "serving_label": "100g",
                "calories_per_100g": "120",
                "protein_per_100g": "20",
                "carbs_per_100g": "5",
                "fat_per_100g": "2",
                "nutrition_date": "2026-03-21",
            },
            follow_redirects=True,
        )

        self.assertEqual(resp.status_code, 200)
        with self.client.session_transaction() as sess:
            self.assertNotIn(f"nutrition_label_draft_{client_id}", sess)
        self.assertNotIn(b'value="Scanned Protein"', resp.data)

    @patch("app.label_scan_enabled", return_value=True)
    @patch("app.scan_label_file_text", return_value="Energy 99 kcal\nFat 2 g")
    def test_label_scan_populates_manual_draft_when_partial_data_is_found(self, _ocr_mock, _enabled_mock):
        client_id = self._create_client(name="Lena")
        self._create_user("lena_user", "pass123", role="client", client_id=client_id)
        self._login("lena_user", "pass123")

        resp = self.client.post(
            f"/client/{client_id}/nutrition/scan-label",
            data={
                "label_name": "Scanned Yogurt",
                "nutrition_date": "2026-03-21",
                "label_photo": (BytesIO(
                    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
                    b"\x00\x00\x00\x0cIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfeA\xa5\x1d\xb6\x00\x00\x00\x00IEND\xaeB`\x82"
                ), "label.png"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Review the custom food form below", resp.data)
        self.assertIn(b"Scanned Yogurt", resp.data)
        self.assertIn(b"99.0", resp.data)

    @patch("app.urlopen")
    def test_google_vision_ocr_is_used_when_api_key_is_configured(self, urlopen_mock):
        old_api_key = app.config.get("GOOGLE_VISION_API_KEY")
        old_hints = app.config.get("GOOGLE_VISION_LANGUAGE_HINTS")
        app.config["GOOGLE_VISION_API_KEY"] = "test-key"
        app.config["GOOGLE_VISION_LANGUAGE_HINTS"] = "en,mk,sq"
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=Mock(read=Mock(return_value=(
            b'{"responses":[{"fullTextAnnotation":{"text":"Energy 123 kcal\\nProtein 8 g"}}]}'
        ))))
        response_ctx.__exit__ = Mock(return_value=None)
        urlopen_mock.return_value = response_ctx

        fd, image_path = tempfile.mkstemp(prefix="label_", suffix=".png")
        os.close(fd)
        try:
            with open(image_path, "wb") as fh:
                fh.write(b"fake-image")

            text = scan_label_file_text(image_path)
        finally:
            if os.path.exists(image_path):
                os.remove(image_path)
            app.config["GOOGLE_VISION_API_KEY"] = old_api_key
            app.config["GOOGLE_VISION_LANGUAGE_HINTS"] = old_hints

        self.assertIn("Energy 123 kcal", text)
        request = urlopen_mock.call_args.args[0]
        self.assertIn("vision.googleapis.com", request.full_url)
        self.assertIn("key=test-key", request.full_url)
        body = request.data.decode("utf-8")
        self.assertIn("DOCUMENT_TEXT_DETECTION", body)
        self.assertIn('"languageHints": ["en", "mk", "sq"]', body)


if __name__ == "__main__":
    unittest.main()
