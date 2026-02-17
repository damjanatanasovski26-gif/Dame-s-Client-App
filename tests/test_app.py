import os
import tempfile
import unittest
from datetime import date

from werkzeug.security import generate_password_hash

from app import app, db, Client, Measurement, Payment, SessionLog, User


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


if __name__ == "__main__":
    unittest.main()
