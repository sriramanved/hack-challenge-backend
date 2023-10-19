from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
import bcrypt
import datetime
import hashlib
import os

db = SQLAlchemy()

users_frat_memberships_association_table = db.Table(
    "users_frat_memberships_association_table",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id")),
    db.Column("fraternity_id", db.Integer, db.ForeignKey("fraternity.id"))
)

users_frat_subscriptions_association_table = db.Table(
    "users_frat_subscriptions_association_table",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id")),
    db.Column("fraternity_id", db.Integer, db.ForeignKey("fraternity.id"))
)

events_frats_association_table = db.Table(
    "events_frats_association_table",
    db.Column("event_id", db.Integer, db.ForeignKey("event.id")),
    db.Column("fraternity_id", db.Integer, db.ForeignKey("fraternity.id"))
)

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    netid = db.Column(db.String(7), nullable=False, unqiue=True)
    password_digest = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    fraternity_memberships = db.relationship(
        "Fraternity", secondary=users_frat_memberships_association_table, back_populates="members")
    subscriptions = db.relationship(
        "Fraternity", secondary=users_frat_subscriptions_association_table, back_populates="subscribers")
    
    # Session information
    session_token = db.Column(db.String(100), nullable=False, unique=True)
    session_expiration = db.Column(db.DateTime, nullable=False)
    update_token = db.Column(db.String(100), nullable=False, unique=True)


    def __init__(self, **kwargs):
        """
        Initializes a User object
        """
        self.name = kwargs.get("name")
        self.netid = kwargs.get("netid")
        self.email = kwargs.get("email")
        self.password_digest = bcrypt.hashpw(kwargs.get("password").encode("utf8"), bcrypt.gensalt(rounds=13))
        self.renew_session()

    def _urlsafe_base_64(self):
        """
        Randomly generates hashed token (used for session/update tokens)
        """
        return hashlib.sha1(os.urandom(64)).hexdigest()

    def renew_session(self):
        """
        Renews the user's session, i.e.,
        1. Creates a new session token
        2. Sets the expiration time of the session to be a day from now
        3. Creates a new update token
        """
        self.session_token = self._urlsafe_base_64()
        self.session_expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        self.update_token = self._urlsafe_base_64()

    def verify_password(self, password):
        """
        Checks if the password is correct
        """
        return bcrypt.checkpw(password.encode("utf8"), self.password_digest)

    def verify_session_token(self, session_token):
        """
        Checks if the session token is correct
        """
        return session_token == self.session_token and datetime.datetime.now() < self.session_expiration
    
    def verify_update_token(self, update_token):
        """
        Checks if the update token is correct
        """
        return update_token == self.update_token

    def serialize(self):
        sent = [i.simple_serialize()
                for i in Invitation.query.filter_by(sender_id=self.id)]
        received = [i.simple_serialize()
                    for i in Invitation.query.filter_by(receiver_id=self.id)]

        return {
            "id": self.id,
            "name": self.name,
            "netid": self.netid,
            "email": self.email,
            "fraternity_memberships": [f.simple_serialize() for f in self.fraternity_memberships],
            "sent_invitations": sent,
            "received_invitations": received,
            "subscriptions": [f.simple_serialize() for f in self.subscriptions]
        }

    def simple_serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "netid": self.netid,
            "email": self.email,
        }

class Fraternity(db.Model):
    __tablename__ = "fraternity"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    members = db.relationship(
        "User", secondary=users_frat_memberships_association_table, back_populates="fraternity_memberships")
    subscribers = db.relationship(
        "User", secondary=users_frat_subscriptions_association_table, back_populates="subscriptions")
    hosting_events = db.relationship(
        "Event", secondary=events_frats_association_table, back_populates="hosting_fraternities")

    def __init__(self, **kwargs):
        """
        Initializes a Fraternity object
        """

        self.name = kwargs.get("name", "")
        self.description = kwargs.get("description", "")

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "members": [u.simple_serialize() for u in self.members],
            "subscribers": [u.simple_serialize() for u in self.subscribers],
            "events": [e.simple_serialize() for e in self.hosting_events]
        }

    def simple_serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
        }

class Event(db.Model):
    __tablename__ = "event"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    is_public = db.Column(db.Boolean, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    hosting_fraternities = db.relationship(
        "Fraternity", secondary=events_frats_association_table, back_populates="hosting_events")

    def __init__(self, **kwargs):
        """
        Initializes an Event object
        """
        self.name = kwargs.get("name")
        self.description = kwargs.get("description")
        self.start_date = kwargs.get("start_date")
        self.end_date = kwargs.get("end_date")
        self.is_public = kwargs.get("is_public")
        self.location = kwargs.get("location")

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "start_date": self.start_date.isoformat(),
            "end_date": self.end_date.isoformat(),
            "is_public": self.is_public,
            "location": self.location,
            "hosting_fraternities": [f.simple_serialize() for f in self.hosting_fraternities],
            "invitations": [i.simple_serialize() for i in Invitation.query.filter_by(event_id=self.id)]
        }

    def simple_serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description, 
            "start_date": self.start_date.isoformat(), # ISO 8601 format
            "end_date": self.end_date.isoformat(),
            "is_public": self.is_public,
            "location": self.location,
        }

class Invitation(db.Model):
    __tablename__ = "invitation"
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    fraternity_id = db.Column(db.Integer, db.ForeignKey(
        'fraternity.id'), nullable=False)
    is_accepted = db.Column(db.Boolean, default=None)

    def __init__(self, **kwargs):
        """
        Initializes an Invitation object
        """

        self.sender_id = kwargs.get("sender_id")
        self.receiver_id = kwargs.get("receiver_id")
        self.event_id = kwargs.get("event_id")
        self.fraternity_id = kwargs.get("fraternity_id")
        self.is_accepted = kwargs.get("is_accepted")

    def serialize(self):
        return {
            "id": self.id,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "event_id": self.event_id,
            "fraternity_id": self.fraternity_id,
            "is_accepted": self.is_accepted
        }

    def simple_serialize(self):
        return {
            "id": self.id,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "event_id": self.event_id,
            "fraternity_id": self.fraternity_id,
            "is_accepted": self.is_accepted
        }


class InviteAllotment(db.Model):
    __tablename__ = "invite_allotment"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    num_invites = db.Column(db.Integer, nullable=False)

    def __init__(self, **kwargs):
        self.user_id = kwargs.get("user_id")
        self.event_id = kwargs.get("event_id")
        self.num_invites = kwargs.get("num_invites")

    def serialize(self):
        return {
            "user_id": self.id,
            "event_id": self.event_id,
            "num_invites": self.num_invites,
        }

    def simple_serialize(self):
        return {
            "user_id": self.id,
            "event_id": self.event_id,
            "num_invites": self.num_invites,
        }
