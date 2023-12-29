"""User model tests."""

# run these tests like:
#
#    python -m unittest test_user_model.py


import os
from unittest import TestCase

from models import db, User, Message, Follows
from flask_bcrypt import Bcrypt
from sqlalchemy import exc

# BEFORE we import our app, let's set an environmental variable
# to use a different database for tests (we need to do this
# before we import our app, since that will have already
# connected to the database

os.environ['DATABASE_URL'] = "postgresql:///warbler-test"


# Now we can import app

from app import app

# Create our tables (we do this here, so we only create the tables
# once for all tests --- in each test, we'll delete the data
# and create fresh new clean test data

db.create_all()


class UserModelTestCase(TestCase):
    """Test views for messages."""

    def setUp(self):
        """Create test client, add sample data."""

        User.query.delete()
        Message.query.delete()
        Follows.query.delete()

        self.client = app.test_client()

    def tearDown(self):
        res = super().tearDown()
        db.session.rollback()
        return res

    def test_user_model(self):
        """Does basic model work?"""

        u = User(
            email="test@test.com",
            username="testuser",
            password="HASHED_PASSWORD"
        )

        db.session.add(u)
        db.session.commit()

        # User should have no messages & no followers
        self.assertEqual(len(u.messages), 0)
        self.assertEqual(len(u.followers), 0)

    def test_repr(self):
        user = User(username='testuser', email='test@example.com')
        expected_repr = f"<User #{user.id}: {user.username}, {user.email}>"
        self.assertEqual(repr(user), expected_repr)

    def test_is_following(self):
        u1 = User(username='testuser1', email='test1@example.com')
        u2 = User(username='testuser2', email='test2@example.com')

        u1.following.append(u2)

        self.assertTrue(u1.is_following(u2))
        self.assertFalse(u2.is_following(u1))

    def test_is_followed_by(self):
        u1 = User(username='testuser1', email='test1@example.com')
        u2 = User(username='testuser2', email='test2@example.com')

        u1.following.append(u2)
        u2.followers.append(u1)

        self.assertTrue(u2.is_followed_by(u1))

    def test_signup_with_valid_credentials(self):
        # Provide valid credentials for the new user
        username = 'testuser'
        email = 'testuser@example.com'
        password = 'password123'

        # Call the User.signup() method to create a new user
        new_user = User.signup(username, email, password, None)
        db.session.commit()

        # Assert that the new user is not None, indicating successful signup
        self.assertIsNotNone(new_user)

        # Assert that the new user's username and email match the provided credentials
        self.assertEqual(new_user.username, username)
        self.assertEqual(new_user.email, email)

        # Get an instance of Bcrypt
        bcrypt = Bcrypt()

        # Assert that the new user's password is properly hashed and not equal to the original password
        self.assertNotEqual(new_user.password, password)
        self.assertTrue(bcrypt.check_password_hash(new_user.password, password))

    def test_invalid_username_signup(self):
        invalid = User.signup(None, "test@test.com", "password", None)
        uid = 123456789
        invalid.id = uid
        with self.assertRaises(exc.IntegrityError) as context:
            db.session.commit()

    def test_invalid_email_signup(self):
        invalid = User.signup("testtest", None, "password", None)
        uid = 123789
        invalid.id = uid
        with self.assertRaises(exc.IntegrityError) as context:
            db.session.commit()
    
    def test_invalid_password_signup(self):
        with self.assertRaises(ValueError) as context:
            User.signup("testtest", "email@email.com", "", None)
        
        with self.assertRaises(ValueError) as context:
            User.signup("testtest", "email@email.com", None, None)

    def test_authenticate_with_valid_credentials(self):
        # Create a new user with valid credentials
        username = 'testuser'
        email = 'testuser@example.com'
        password = 'password123'
        user = User.signup(username, email, password, None)
        db.session.commit()

        # Call the User.authenticate() method with the valid credentials
        authenticated_user = User.authenticate(username, password)

        # Assert that the authenticated user is not False, indicating successful authentication
        self.assertNotEqual(authenticated_user, False)

        # Assert that the authenticated user is the same as the original user
        self.assertEqual(authenticated_user.username, user.username)

    def test_authenticate_with_invalid_username(self):
        # Call the User.authenticate() method with an invalid username
        authenticated_user = User.authenticate('invalidusername', 'password123')

        # Assert that the authenticated user is False, indicating failed authentication
        self.assertEqual(authenticated_user, False)

    def test_authenticate_with_invalid_password(self):
        # Create a new user with valid credentials
        username = 'testuser'
        email = 'testuser@example.com'
        password = 'password123'
        User.signup(username, email, password, None)
        db.session.commit()

        # Call the User.authenticate() method with an invalid password
        authenticated_user = User.authenticate(username, 'invalidpassword')

        # Assert that the authenticated user is False, indicating failed authentication
        self.assertEqual(authenticated_user, False)

        