import unittest
import sqlite3
import os
from app import app, init_db, get_db_connection

class TestAuthAndDashboards(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        init_db()

    def test_schema_migration_and_seeded_accounts(self):
        """Verify users table has email_verified column and pre-seeded accounts can log in."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users)")
        cols = [c[1] for c in cursor.fetchall()]
        self.assertIn('email_verified', cols)
        self.assertIn('verification_token', cols)
        self.assertIn('token_expiry', cols)

        # Check seeded accounts
        seeded = [
            ("citizen@crms.gov.in", "Citizen@123", "/dashboard/citizen"),
            ("police@crms.gov.in", "Police@123", "/dashboard/police"),
            ("court@crms.gov.in", "Court@123", "/dashboard/court"),
            ("magistrate@crms.gov.in", "Magistrate@123", "/dashboard/district-magistrate"),
        ]
        for email, password, expected_redirect in seeded:
            user = conn.execute("SELECT * FROM users WHERE lower(email) = ?", (email.lower(),)).fetchone()
            self.assertIsNotNone(user, f"Account {email} should exist")
            self.assertEqual(user['email_verified'], 1, f"Account {email} should be verified")

            # Test login
            resp = self.client.post('/login', data={'email': email, 'password': password}, follow_redirects=False)
            self.assertEqual(resp.status_code, 302, f"Login for {email} should redirect")
            self.assertEqual(resp.location, expected_redirect, f"Login for {email} should redirect to {expected_redirect}")
        conn.close()

    def test_signup_validation(self):
        """Test sign-up validation rules."""
        # Missing fields
        resp = self.client.post('/signup', data={'full_name': '', 'email': 'test@example.com'})
        self.assertIn(b'All fields are required', resp.data)

        # Invalid role
        resp = self.client.post('/signup', data={
            'full_name': 'Test User',
            'email': 'test@example.com',
            'role': 'SuperAdmin',
            'password': 'password123',
            'confirm_password': 'password123'
        })
        self.assertIn(b'Invalid role selected', resp.data)

        # Short password
        resp = self.client.post('/signup', data={
            'full_name': 'Test User',
            'email': 'test@example.com',
            'role': 'Citizen',
            'password': '123',
            'confirm_password': '123'
        })
        self.assertIn(b'at least 6 characters', resp.data)

        # Password mismatch
        resp = self.client.post('/signup', data={
            'full_name': 'Test User',
            'email': 'test@example.com',
            'role': 'Citizen',
            'password': 'password123',
            'confirm_password': 'mismatch123'
        })
        self.assertIn(b'Passwords do not match', resp.data)

    def test_signup_verification_and_login_flow(self):
        """Test complete sign-up, OTP verification, and login cycle."""
        test_email = "newcitizen_test@example.com"

        # Ensure no leftover user
        conn = get_db_connection()
        conn.execute("DELETE FROM users WHERE lower(email) = ?", (test_email.lower(),))
        conn.commit()
        conn.close()

        # 1. Sign up – should redirect to OTP verification page
        resp = self.client.post('/signup', data={
            'full_name': 'Pooja Verma',
            'email': test_email,
            'role': 'Citizen',
            'password': 'PoojaPassword123',
            'confirm_password': 'PoojaPassword123'
        }, follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/verify-otp', resp.location)

        # 2. Retrieve OTP from DB
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE lower(email) = ?", (test_email.lower(),)).fetchone()
        self.assertIsNotNone(user)
        self.assertEqual(user['email_verified'], 0)
        self.assertIsNotNone(user['otp_code'])
        otp = user['otp_code']
        conn.close()

        # 3. Submit OTP for verification
        verify_resp = self.client.post('/verify-otp', data={
            'email': test_email,
            'otp': otp
        }, follow_redirects=False)
        self.assertEqual(verify_resp.status_code, 302)
        self.assertIn('/login', verify_resp.location)

        # 4. Login should now succeed and redirect to citizen dashboard
        login_resp = self.client.post('/login', data={
            'email': test_email,
            'password': 'PoojaPassword123'
        }, follow_redirects=False)
        self.assertEqual(login_resp.status_code, 302)
        self.assertEqual(login_resp.location, '/dashboard/citizen')

        # Clean up test user
        conn = get_db_connection()
        conn.execute("DELETE FROM users WHERE lower(email) = ?", (test_email.lower(),))
        conn.commit()
        conn.close()

    def test_dashboards_render_properly(self):
        """Test that all 4 dashboards and /dataset-overview render with status 200."""
        # 1. Citizen dashboard
        with self.client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['role'] = 'Citizen'
            sess['full_name'] = 'Citizen Portal Account'
            sess['email'] = 'citizen@crms.gov.in'
        resp = self.client.get('/dashboard/citizen')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Citizen Services Portal', resp.data)

        # 2. Police dashboard
        with self.client.session_transaction() as sess:
            sess['user_id'] = 2
            sess['role'] = 'Police'
            sess['full_name'] = 'Police Station Account'
            sess['email'] = 'police@crms.gov.in'
        resp = self.client.get('/dashboard/police')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Police Operations Dashboard', resp.data)

        # 3. Court dashboard
        with self.client.session_transaction() as sess:
            sess['user_id'] = 3
            sess['role'] = 'Court'
            sess['full_name'] = 'District Court Account'
            sess['email'] = 'court@crms.gov.in'
        resp = self.client.get('/dashboard/court')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'District Court Case Proceedings Dashboard', resp.data)

        # 4. District Magistrate dashboard
        with self.client.session_transaction() as sess:
            sess['user_id'] = 4
            sess['role'] = 'District Magistrate'
            sess['full_name'] = 'District Magistrate Account'
            sess['email'] = 'magistrate@crms.gov.in'
        resp = self.client.get('/dashboard/district-magistrate')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'District Magistrate Command Console', resp.data)

        # 5. Dataset Overview
        resp = self.client.get('/dataset-overview')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'National Crime Management Portal', resp.data)

    def test_root_redirects_per_role(self):
        """Test that root '/' dynamically routes each authenticated role to their dedicated dashboard."""
        roles_and_targets = [
            ('Citizen', '/dashboard/citizen'),
            ('Police', '/dashboard/police'),
            ('Court', '/dashboard/court'),
            ('District Magistrate', '/dashboard/district-magistrate'),
        ]
        for role, target in roles_and_targets:
            with self.client.session_transaction() as sess:
                sess['user_id'] = 99
                sess['role'] = role
                sess['full_name'] = f'{role} User'
                sess['email'] = f'{role.lower()}@test.com'
            resp = self.client.get('/', follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.location, target)

    def test_role_access_restrictions(self):
        """Verify role protection gates unauthorized access with HTTP 403."""
        # Citizen trying to access Police Dashboard
        with self.client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['role'] = 'Citizen'
            sess['full_name'] = 'Citizen User'
            sess['email'] = 'citizen@test.com'
        resp = self.client.get('/dashboard/police')
        self.assertEqual(resp.status_code, 403)
        self.assertIn(b'does not have', resp.data)
        self.assertIn(b'permission', resp.data)

        # Court trying to access District Magistrate Dashboard
        with self.client.session_transaction() as sess:
            sess['user_id'] = 3
            sess['role'] = 'Court'
            sess['full_name'] = 'Court Officer'
            sess['email'] = 'court@test.com'
        resp = self.client.get('/dashboard/district-magistrate')
        self.assertEqual(resp.status_code, 403)

    def test_all_existing_routes_accessible(self):
        """Ensure all preexisting analytical and operational routes remain healthy."""
        routes = [
            '/dataset-overview',
            '/analytics',
            '/women-children-analytics',
            '/property-arrest-analytics',
            '/police-stations',
            '/police-station-map',
            '/fir-management',
            '/criminal-records',
            '/case-files',
            '/crime-patterns',
            '/crime-statistics',
        ]
        with self.client.session_transaction() as sess:
            sess['user_id'] = 4
            sess['role'] = 'District Magistrate'
            sess['full_name'] = 'Executive User'
            sess['email'] = 'dm@test.com'
        for route in routes:
            resp = self.client.get(route)
            self.assertEqual(resp.status_code, 200, f"Route {route} should return 200 OK")

if __name__ == '__main__':
    unittest.main()
