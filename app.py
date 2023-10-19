import json

from flask import Flask, request, Response
import qrcode
from datetime import datetime
import bcrypt
from db import db, User, Fraternity, Event, Invitation, InviteAllotment
import user_dao

db_filename = "auth.db" # CHANGE NAME
app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///%s" % db_filename
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

db.init_app(app)
with app.app_context():
    db.create_all()

def success_response(data, code=200):
    return json.dumps(data), code

def failure_response(message, code=404):
    return json.dumps({"error": message}), code

# -- AUTHENTICATION ROUTES ------------------------------------------------------
def extract_token(request):
    """
    Extracts the token from the Authorization header of the request
    """
    auth_header = request.headers.get("Authorization")
    if auth_header is None:
        return False, failure_response("Missing authorization header", 400)
    bearer_token = auth_header.replace("Bearer ", "").strip()
    if bearer_token is None or not bearer_token:
        return False, failure_response("Invalid authorization header", 400)
    return True, bearer_token

@app.route('/login/', methods=['POST'])
def login():
    """
    Logs in a user and returns the user object as a JSON object
    """
    body = json.loads(request.data)
    email = body.get("email")
    password = body.get("password")
    
    if (email is None) or (password is None):
        return failure_response("Email or password not provided", 400)
    
    success, user = user_dao.verify_credentials(email, password)

    if not success:
        return failure_response("Incorrect email or password", 401)
    
    user.renew_session()
    
    return success_response({
        "session_token": user.session_token,
        "session_expiration": str(user.session_expiration),
        "update_token": user.update_token
    })

@app.route('/register/', methods=['POST'])
def register_account():
    """
    Endpoint for registering a new account
    """
    body = json.loads(request.data)
    name = body.get("name")
    email = body.get("email")
    password = body.get("password")

    if not email or not password or not name or not netid:
        return failure_response("Missing required fields", 400)
    
    if not email.endswith("@cornell.edu"):
        return failure_response("Your email must be a Cornell email", 400)
    
    netid = email.split("@")[0]
    
    success, user = user_dao.create_user(name, netid, email, password)

    if not success:
        return failure_response("User already exists", 400)
    
    return success_response(
        {
            "session_token": user.session_token,
            "session_expiration": str(user.session_expiration),
            "update_token": user.update_token
        }
    )

@app.route('/session/', methods=['POST'])
def update_session():
    """
    Endpoint for updating a user's session token
    """
    success, update_token = extract_token(request)

    success_user, user = user_dao.renew_session(update_token)

    if not success_user:
        return failure_response("Invalid update token", 400)
    
    return success_response(
        {
            "session_token": user.session_token,
            "session_expiration": str(user.session_expiration),
            "update_token": user.update_token
        }
    )

@app.route('/secret/', methods=['POST'])
def secret_message():
    """
    Endpoint for verifying a session token and returning a secret message

    We will use the same logic for any endpoint that needs authentication
    """
    success, session_token = extract_token(request)
    if not success:
        return failure_response("Could not extract session token", 400)
    
    user = user_dao.get_user_by_session_token(session_token)
    if user is None or not user.verify_session_token(session_token):
        return failure_response("Invalid session token")
    
    # handle the logic of the route here
    # e.g., edit user profile, create a post, etc.
    
    return success_response({"message": "You have successfully implemented sessions!"})

@app.route('/logout/', methods=['POST'])
def logout():
    """
    Endpoint for logging a user out
    """
    success, session_token = extract_token(request)

    if not success:
        return failure_response("Could not extract session token", 400)
    
    user = user_dao.get_user_by_session_token(session_token)

    if user is None or not user.verify_session_token(session_token):
        return failure_response("Invalid session token")
    
    user.session_token = ""
    user.session_expiration = datetime.now()
    user.update_token = ""

    db.session.commit()

    return success_response({"message": "You have been successfully logged out"})



# -- USER ROUTES ------------------------------------------------------
@app.route('/user/<int:user_id>/', methods=['GET'])
def get_user(user_id):
    """
    Returns a single user with the given ID as a JSON object
    """
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return failure_response("User not found", 404)
    return success_response(user.serialize())

@app.route('/user/<int:user_id>/edit/', methods=['POST'])
def edit_user(user_id):
    """
    Edits a single user with the given ID, and returns the edited user as a JSON object
    """
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return failure_response("User not found", 404)

    body = json.loads(request.data)
    name = body.get("name")
    email = body.get("email")
    password = body.get("password")

    if not email.endswith("@cornell.edu"):
        return failure_response("Your email must be a Cornell email", 400)

    if not name is None:
        user.name = name
    if not email is None:
        netid = email.split("@")[0]
        user.netid = netid
        user.email = email
    if not password is None:
        user.password = bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt(rounds=13))

    db.session.commit()
    return success_response(user.serialize())

@app.route('/user/<int:user_id>/delete/', methods=['DELETE'])
def delete_user(user_id):
    """
    Deletes a single user with the given ID, and returns the deleted user as a JSON object
    """
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return failure_response("User not found", 404)
    db.session.delete(user)
    db.session.commit()
    return success_response(user.serialize())

# -- FRATERNITY ROUTES ------------------------------------------------------

@app.route('/fraternity/', methods=['GET'])
def get_fraternities():
    """
    Returns a list of all fraternities in the database as JSON objects 
    """
    fraternities = Fraternity.query.all()
    return success_response([f.serialize() for f in fraternities])

@app.route('/fraternity/<int:fraternity_id>/events/', methods=['GET'])
def get_fraternity_events(fraternity_id):
    """
    Returns a list of all events for the fraternity with the given ID as JSON objects
    """
    fraternity = Fraternity.query.get(fraternity_id)
    if fraternity is None:
        return failure_response("Fraternity not found")
    events = fraternity.hosting_events
    return success_response([e.serialize() for e in events])

@app.route('/fraternity/<int:fraternity_id>/members/', methods=['GET'])
def get_fraternity_members(fraternity_id):
    """
    Returns a list of all members for the fraternity with the given ID as JSON objects
    """
    fraternity = Fraternity.query.get(fraternity_id)
    if fraternity is None:
        return failure_response("Fraternity not found")
    members = fraternity.members
    return success_response([m.serialize() for m in members])

@app.route('/fraternity/<int:fraternity_id>/subscribers/', methods=['GET'])
def get_fraternity_subscribers(fraternity_id):
    """
    Returns a list of all users who have starred the fraternity with the given ID as JSON objects
    """
    fraternity = Fraternity.query.get(fraternity_id)
    if fraternity is None:
        return failure_response("Fraternity not found")
    subscribers = fraternity.subscribers
    return success_response([s.serialize() for s in subscribers])

@app.route('/fraternity/<int:fraternity_id>/', methods=['GET'])
def get_fraternity(fraternity_id):
    """
    Returns a single fraternity with the given ID as a JSON object
    """
    fraternity = Fraternity.query.get(fraternity_id)
    if fraternity is None:
        return failure_response("Fraternity not found")
    return success_response(fraternity.serialize())

@app.route('/fraternity/create/', methods=['POST'])
def create_fraternity():
    """
    Creates a new fraternity with the given name and description, and returns the new fraternity as a JSON object
    """
    # Assuming you have a logged-in user with an ID of user_id
    body = json.loads(request.data)
    user_id = body.get('user_id')
    name = body.get('name')
    description = body.get('description')

    fraternity = Fraternity(user_id=user_id, name=name, description=description)
    db.session.add(fraternity)
    db.session.commit()
    return success_response(fraternity.serialize(), 201)

@app.route('/fraternity/<int:fraternity_id>/subscribe/', methods=['POST'])
def subscribe_to_fraternity(fraternity_id):
    """
    Subscribes the logged-in user to the fraternity with the given ID, and returns the new subscription as a JSON object
    """
    # Assuming you have a logged-in user with an ID of user_id
    body = json.loads(request.data)
    id = body.get('user_id')
    if id is None:
        return failure_response("User not found")
    user = User.query.filter_by(id=id).first()
    fraternity = Fraternity.query.filter_by(id=fraternity_id).first()
    if fraternity is None:
        return failure_response("Fraternity not found")
    fraternity.subscribers.append(user)
    user.subscriptions.append(fraternity)

    db.session.commit()
    return success_response(user.serialize(), 201)

@app.route('/fraternity/<int:fraternity_id>/unsubscribe/', methods=['POST'])
def unsubscribe_to_fraternity(fraternity_id):
    """
    Unsubscribes the logged-in user to the fraternity with the given ID, and returns the new subscription as a JSON object
    """
    # Assuming you have a logged-in user with an ID of user_id
    body = json.loads(request.data)
    id = body.get('user_id')
    if id is None:
        return failure_response("User not found")
    user = User.query.filter_by(id=id).first()
    fraternity = Fraternity.query.filter_by(id=fraternity_id).first()
    if fraternity is None:
        return failure_response("Fraternity not found")
    fraternity.subscribers.remove(user)
    user.subscriptions.remove(fraternity)

    db.session.commit()
    return success_response(user.serialize(), 201)

@app.route('/fraternity/<int:fraternity_id>/add-member/', methods=['POST'])
def add_fraternity_member(fraternity_id):
    """
    Adds a user to the fraternity with the given ID
    """
    fraternity = Fraternity.query.get(fraternity_id)
    if fraternity is None:
        return failure_response("Fraternity not found")
    body = json.loads(request.data)
    user_id = body.get("user_id")
    user = User.query.filterby(id=user_id).first()
    if user is None:
        return failure_response("User not found")
    fraternity.members.append(user)
    user.fraternity_memberships.append(fraternity)
    db.session.commit()
    return success_response(fraternity.serialize())

@app.route('/fraternity/<int:fraternity_id>/remove-member/', methods=['POST'])
def remove_fraternity_member(fraternity_id):
    """
    Removes a user from the fraternity with the given ID
    """
    fraternity = Fraternity.query.get(fraternity_id)
    if fraternity is None:
        return failure_response("Fraternity not found")
    body = json.loads(request.data)
    user_id = body.get("user_id")
    user = User.query.filterby(id=user_id).first()
    if user is None:
        return failure_response("User not found")
    fraternity.members.remove(user)
    user.fraternity_memberships.remove(fraternity)
    db.session.commit()
    return success_response(fraternity.serialize())

@app.route('/fraternity/<int:fraternity_id>/edit/', methods=['PUT'])
def edit_fraternity(fraternity_id):
    """
    Edits the fraternity with the given ID, and returns the edited fraternity as a JSON object
    """
    body = json.loads(request.data)
    fraternity = Fraternity.query.get(fraternity_id)
    if fraternity is None:
        return failure_response("Fraternity not found")

    name = body.get('name')
    description = body.get('description')

    if name:
        fraternity.name = name
    if description:
        fraternity.description = description

    db.session.commit()
    return success_response(fraternity.serialize())

@app.route('/fraternity/<int:fraternity_id>/delete/', methods=['DELETE'])
def delete_fraternity(fraternity_id):
    """
    Deletes the fraternity with the given ID, and returns a success message as a JSON object 
    """
    fraternity = Fraternity.query.get(fraternity_id)
    if fraternity is None:
        return failure_response("Fraternity not found")
    db.session.delete(fraternity)
    db.session.commit()
    return success_response({"message": "Fraternity deleted"})

# -- EVENT ROUTES ------------------------------------------------------
@app.route('/events/', methods=['GET'])
def get_events():
    """
    Returns a list of all events in the database as JSON objects
    """
    events = Event.query.all()
    return success_response([e.serialize() for e in events])

@app.route('/event/<int:event_id>/', methods=['GET'])
def get_event(event_id):
    """
    Returns a single event with the given ID as a JSON object 
    """
    event = Event.query.filter_by(id=event_id).first()
    if event is None:
        return failure_response("Event not found")
    return success_response(event.serialize())

@app.route('/event/is-public/', methods=['GET'])
def get_public_events():
    """
    Returns a list of all public events in the database as JSON objects
    """
    events = Event.query.filter_by(is_public=True).all()
    return success_response([e.serialize() for e in events])

@app.route('/event/<int:user_id>/attending/', methods=['GET'])
def get_attending_events(user_id):
    """
    Returns a list of all events that the logged-in user is attending as JSON objects when is_accepted is True for a specific invite
    """
    if user_id is None:
        return failure_response("User not found")
    invitations = Invitation.query.filter_by(receiver_id=user_id, is_accepted=True).all()
    events = []
    for invitation in invitations:
        event = Event.query.filter_by(id=invitation.event_id).first()
        events.append(event)
    return success_response([e.serialize() for e in events])

@app.route('/event/create/', methods=['POST'])
def create_event():
    """
    Creates a new event with the given name, description, date, and location, and returns the new event as a JSON object
    """
    # Assuming you have a logged-in user with an ID of fraternity_id
    body = json.loads(request.data)
    fraternity_id = body.get('fraternity_id')
    name = body.get('name')
    description = body.get('description')
    date = body.get("date")
    start_time = body.get("start_time")
    end_time = body.get("end_time")
    is_public = body.get("is_public")
    location = body.get('location')
    
    start_time_str = datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%S") # Convert string to datetime object using ISO 8601 format
    end_time_str = datetime.strptime(end_time, "%Y-%m-%dT%H:%M:%S")
    
    if (fraternity_id is None) or (name is None) or (description is None) or (date is None) or (start_time is None) or (end_time is None) or (is_public is None) (location is None):
        return failure_response("Fraternity ID, name, description, date, start time, end time, public, or location not provided", 400)

    event = Event(fraternity_id=fraternity_id, name=name, description=description, date=date, start_time=start_time_str, end_time=end_time_str, is_public=is_public, location=location)
    db.session.add(event)
    db.session.commit()
    return success_response(event.serialize(), 201)

@app.route('/event/<int:event_id>/edit/', methods=['PUT'])
def edit_event(event_id):
    """
    Edits the event with the given ID, and returns the edited event as a JSON object
    """
    body = json.loads(request.data)
    event = Event.query.get(event_id)
    if event is None:
        return failure_response("Event not found")
    name = body.get('name')
    description = body.get('description')
    date = body.get("date")
    start_time = body.get("start_time")
    end_time = body.get("end_time")
    location = request.form.get('location')
    is_public = body.get('is_public')
    
    start_time_str = datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%S")
    end_time_str = datetime.strptime(end_time, "%Y-%m-%dT%H:%M:%S")

    if name:
        event.name = name
    if description:
        event.description = description
    if date:
        event.date = date
    if start_time:
        event.start_time = start_time_str
    if end_time:
        event.end_time = end_time_str
    if location:
        event.location = location
    if is_public:
        event.is_public = is_public

    db.session.commit()
    return success_response(event.serialize())

@app.route('/event/<int:event_id>/delete/', methods=['DELETE'])
def delete_event(event_id):
    """
    Deletes the event with the given ID, and returns a success message as a JSON object
    """
    event = Event.query.filter_by(id=event_id).first()
    if event is None:
        return failure_response("Event not found")
    db.session.delete(event)
    db.session.commit()
    return success_response(event.serialize())

# -- INVITATION ROUTES ------------------------------------------------------

@app.route('/invitations/', methods=['GET'])
def get_invitations():
    """
    Returns a list of all invitations in the database as JSON objects
    """
    invitations = Invitation.query.all()
    return success_response([i.serialize() for i in invitations])

@app.route('/invitation/<int:user_id>/sent-invitations', methods=['GET'])
def get_sent_invitations(user_id):
    """
    Returns a list of all invitations sent by the logged-in user as JSON objects
    """
    if user_id is None:
        return failure_response("User not found")
    invitations = Invitation.query.filter_by(sender_id=user_id).all()
    return success_response([i.serialize() for i in invitations])

@app.route('/invitation/<int:user_id>/received-invitations', methods=['GET'])
def get_received_invitations(user_id):
    """
    Returns a list of all invitations received by the logged-in user as JSON objects
    """
    if user_id is None:
        return failure_response("User not found")
    invitations = Invitation.query.filter_by(receiver_id=user_id).all()
    return success_response([i.serialize() for i in invitations])

@app.route('/invitation/create/', methods=['POST'])
def create_invitation():
    """
    Creates a new invitation with the given user ID and event ID, and returns the new invitation as a JSON object
    """
    body = json.loads(request.data)
    sender_id = body.get('sender_id')
    receiver_id = body.get('receiver_id')
    event_id = body.get('event_id')
    fraternity_id = body.get('fraternity_id')
    is_accepted = body.get('is_accepted')

    if sender_id is None or receiver_id is None or event_id is None or fraternity_id is None:
        return failure_response("sender_id, receiver_id, event_id, fraternity_id must all be provided")

    invitation = Invitation(
        sender_id = sender_id,
        receiver_id = receiver_id,
        event_id = event_id,
        fraternity_id = fraternity_id,
        is_accepted = is_accepted
    )

    db.session.add(invitation)
    db.session.commit()
    return success_response(invitation.serialize(), 201)

@app.route('/invitation/qr/<string:data>')
def generate_qr(data):
    # create QR code object
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    # add data to QR code object
    qr.add_data(data)
    qr.make(fit=True)

    # create QR code image as PNG
    img = qr.make_image(fill_color="black", back_color="white")

    # create a response containing the image data
    response = Response()
    response.headers['Content-Type'] = 'image/png'
    img.save(response.stream, 'PNG')
    return response

@app.route('/invitation/<int:invitation_id>/accept/', methods=['PUT'])
def accept_invitation(invitation_id):
    """
    Accepts the invitation with the given ID, and returns the accepted invitation as a JSON object
    """
    invitation = Invitation.query.get(invitation_id)
    if invitation is None:
        return failure_response("Invitation not found")
    invitation.is_accepted = True
    db.session.commit()
    return success_response(invitation.serialize())

@app.route('/invitation/<int:invitation_id>/reject/', methods=['PUT'])
def reject_invitation(invitation_id):
    """
    Rejects the invitation with the given ID, and returns the rejected invitation as a JSON object
    """
    invitation = Invitation.query.get(invitation_id)
    if invitation is None:
        return failure_response("Invitation not found")
    invitation.is_accepted = False
    db.session.commit()
    return success_response(invitation.serialize())

@app.route('/invitation/<int:invitation_id>/edit/', methods=['PUT'])
def edit_invite(invitation_id):
    """
    Edits the invite with the given ID, and returns the edited invite as a JSON object
    """
    body = json.loads(request.data)
    invitation = Invitation.query.get(invitation_id)
    if invitation is None:
        return failure_response("Invite not found")
    sender_id = body.get('sender_id')
    receiver_id = body.get('receiver_id')
    event_id = body.get("event_id")
    fraternity_id = body.get("fraternity_id")
    is_accepted = body.get("is_accepted")
    
    if sender_id:
        invitation.sender_id = sender_id
    if receiver_id:
        invitation.receiver_id = receiver_id
    if event_id:
        invitation.event_id = event_id
    if fraternity_id:
        invitation.fraternity_id = fraternity_id
    if is_accepted:
        invitation.is_accepted = is_accepted

    db.session.commit()
    return success_response(invitation.serialize())

@app.route('/invitation/<int:invitation_id>/delete/', methods=['DELETE'])
def delete_invitation(invitation_id):
    """
    Deletes the invitation with the given ID, and returns a success message as a JSON object
    """
    invitation = Invitation.query.get(invitation_id)
    if invitation is None:
        return failure_response("Invitation not found")
    db.session.delete(invitation)
    db.session.commit()
    return success_response({"message": "Invitation deleted"})

# -- INVITE ALLOTMENT ROUTES ----------------------------------------------------
@app.route('/invite_allotment/', methods=['POST'])
def create_invite_allotment():
    body = json.loads(request.data)
    user_id = body.get("user_id")
    event_id = body.get("event_id")
    num_invites = body.get("num_invites")

    if user_id is None or event_id is None or num_invites is None:
        return failure_response("The user's id, the event's id, and the number of invites must all be provided")
    
    invite_allotment = InviteAllotment(
        user_id = user_id,
        event_id = event_id,
        num_invites = num_invites
    )

    db.session.add(invite_allotment)
    db.session.commit()
    return success_response(invite_allotment.serialize(), 201)

@app.route('/invite_allotment/user/<int:user_id>/event/<int_event_id>', methods=['GET']) # should this route be changed?
def get_num_invites_for_event(user_id, event_id):
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return failure_response("User not found", 404)
    event = Event.query.filter_by(id=event_id).first()
    if event is None:
        return failure_response("Event not found", 404)
    invite_allotment = InviteAllotment.query.filter_by(user_id=user_id, event_id=event_id).first()
    if invite_allotment is None:
        return failure_response("User and event combination not found!")
    return json.dumps(invite_allotment.serialize())

@app.route('/invite_allotment/<int:user_id>/event/<int_event_id>/edit/', methods=['PUT']) # should this route be changed?
def edit_invite_allotment(user_id, event_id):
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return failure_response("User not found", 404)
    event = Event.query.filter_by(id=event_id).first()
    if event is None:
        return failure_response("Event not found", 404)
    body = json.loads(request.data)
    invite_allotment = InviteAllotment.query.filter_by(user_id=user_id, event_id=event_id).first()
    if invite_allotment is None:
        return failure_response("Invite allotment not found")
    
    invite_allotment.num_invites = body.get("num_invites")
    
    db.session.commit()
    return success_response(invite_allotment.serialize())


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=True)
