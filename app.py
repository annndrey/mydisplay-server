#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import logging
import traceback
import werkzeug.exceptions
from logging.handlers import RotatingFileHandler
import csv
import datetime
from sqlalchemy import func, or_
from flask import Flask, jsonify, request, make_response, g, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_restful import Resource, Api, reqparse, abort, fields, marshal_with
from flask_httpauth import HTTPBasicAuth
from flask_marshmallow import Marshmallow
from marshmallow import  fields
from marshmallow_enum import EnumField

from flasgger import Swagger

from models import db, User, ActivityType, StatusFlag, Postcode, Contact, Property, Activity, Appraisal, ContactNote, ActivityNote, AppraisalNote, street_suffixes


app = Flask(__name__)

handler = RotatingFileHandler('foo.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.DEBUG)
app.logger.addHandler(handler)

logging.getLogger('werkzeug').setLevel(logging.DEBUG)
logging.getLogger('werkzeug').addHandler(handler)

ma = Marshmallow(app)
auth = HTTPBasicAuth()

app.config.from_envvar('APPSETTINGS')
app.config['PROPAGATE_EXCEPTIONS'] = True
db.init_app(app)
migrate = Migrate(app, db)
api=Api(app)

swtemplate = {
  "info": {
    "title": "MyDisplay API",
    "description": "API for MyDisplay, %s" % ("DEV" if app.config["DEVELOPMENT"] is True else "PROD"),
    "version": "0.0.1"
  },
  'jsonEditor': 'true'

}


swagger = Swagger(app, template=swtemplate)


@app.errorhandler(500)
def internal_server_error(error):
    app.logger.error('Server Error: %s ', (error))
    return werkzeug.exceptions.InternalServerError(), 500

@app.errorhandler(Exception)
def unhandled_exception(e):
    app.logger.error('Unhandled Exception: %s ', (e))
    return werkzeug.exceptions.InternalServerError(), 500

@auth.verify_password
def verify_password(username_or_token, password):

    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(login = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    """
    API to obtain auth token
    ---
    summary: "Returns an auth token for user"
    parameters:
      - name: "username"
        in: "query"
        description: "The user name for login"
        required: true
        type: "string"
      - name: "password"
        in: "query"
        description: "The password for login in clear text"
        required: true
        type: "string"
    responses:
      200:
        description: Authorisation parameters
        example:
          token: eyJleHAiOjE1MjYzNzk0NjYsImFsZyI6IkhTMjU2IiwiaWF0IjoxNTI2Mzc4ODY2fQ.eyJpZCI6NH0._8dsz8nCyMcloKT-u1SZ1QtCwPl3kKQ698cWowh4OQc
      403:
        description: Not authorized
        """

    token = g.user.generate_auth_token()
    return jsonify({ 'token': "%s" % token })


# schemas
class AppraisalSchema(ma.ModelSchema):
    class Meta:
        model = Appraisal


class ActivityNoteSchema(ma.ModelSchema):
    class Meta:
        model = ActivityNote
        

class AppraisalNoteSchema(ma.ModelSchema):
    class Meta:
        model = AppraisalNote


class ContactNoteSchema(ma.ModelSchema):
    class Meta:
        model = ContactNote


class ActivitySchema(ma.ModelSchema):
    class Meta:
        model = Activity
        include_fk = True
        exclude=('contact_id', )

    # activity = EnumField(ActivityType, by_value=True)
    notes = ma.Nested(ActivityNoteSchema, many=True)
    timestamp = ma.Function(lambda obj: str(obj.timestamp))

class UserSchema(ma.ModelSchema):
    class Meta:
        model = User


class ContactSchema(ma.ModelSchema):
    class Meta:
        model = Contact
        include_fk = True
        exclude = ('property', 'appraisal')

    postcode = ma.Function(lambda obj: obj.postcode.postcode)
    suburb = ma.Function(lambda obj: obj.postcode.suburb)
    activities = ma.Nested(ActivitySchema, many=True)
    notes = ma.Nested(ContactNoteSchema, many=True, only=["text"])


class AppraisalSchema(ma.ModelSchema):
    class Meta:
        model = Appraisal
        include_fk = True

    contacts = ma.Nested(ContactSchema, many=True)
    notes = ma.Nested(AppraisalNoteSchema, many=True)


class PropertySchema(ma.ModelSchema):
    statusflag = EnumField(StatusFlag, by_value=True)

    class Meta:
        model = Property
        include_fk = True
        partial=False
    postcode = ma.Function(lambda obj: obj.postcode_.postcode)
    duedate = ma.Method('duedate_data')
    #activity = ma.Function(lambda obj: (obj.contacts[-1].activities[-1].activity) if len(obj.contacts) > 0 else json.dumps(None))
    activity = ma.Method('activity_data')

    suburb = ma.Function(lambda obj: obj.postcode_.suburb)
    contacts = ma.Nested(ContactSchema, many=True)
    
    def activity_data(self, obj):
        if len(obj.contacts) > 0:
            if len(obj.contacts[-1].activities) > 0:
                return obj.contacts[-1].activities[-1].activity

        return None

    def duedate_data(self, obj):
        if len(obj.contacts) > 0:
            if len(obj.contacts[-1].activities) > 0:

                if obj.contacts[-1].activities[-1].duedate is not None:
                    return "{0}".format(obj.contacts[-1].activities[-1].duedate)
        return None

# model resources
class Users(Resource):
    user_schema = UserSchema()
    users_schema = UserSchema(many=True)

    @auth.login_required
    def get(self, userid=None):
        """
        A list of database users
       ---
       parameters:
         - in: path
           name: userid
           type: int
           required: false
       responses:
         200:
           description: A single user if id is given and a list of users if no id provided
           schema:
             id: User
             properties:
               username:
                 type: string
                 description: The login of the user
                 default: newuser
               password:
                 type: string
                 description: The password of the user
                 default: newpassword
               note:
                 type: string
                 description: Some note on the user
                 default: Empty note

        """
        if userid is None:
            users = User.query.all()
            return self.users_schema.dump(users).data, 200

        else:
            user = User.query.filter_by(id = userid).first()
            if user is not None:
                return self.user_schema.dump(user).data, 200
            else:
                abort(404)


    @auth.login_required
    def post(self):
        """
    Creation of a new database user
    ---
    parameters:
      - name: body
        in: body
        schema:
          $ref: "#/definitions/User"
    definitions:
      User:
        type: object
        required:
          - username
          - password
        properties:
          username:
            type: str
            required: true
          password:
            type: str
            required: true
          note:
            type: str
    responses:
      200:
        description: A list of database users
        schema:
          $ref: '#/definitions/User'
        example:
          username: newuser
          password: newpassword
          note: test
      400:
        description: No data provided
      405:
        description: Existing user
      422:
        description: Username or password missing

        """

        if request.json is None:
            abort(400, message="No data provided")

        username = request.json.get('username')
        password = request.json.get('password')
        note = request.json.get('note')

        if username is None or password is None:
            abort(422, message="Username or password missing") # missing arguments

        if User.query.filter_by(login = username).first() is not None:
            abort(405, message="Existing user") # existing user

        user = User(login = username)
        user.hash_password(password)
        if app.config['DEBUG']:
            user.note = "test"
        else:
            if note:
                user.note = note

        db.session.add(user)
        db.session.commit()

        return self.user_schema.dump(user).data, 201


    @auth.login_required
    def patch(self, userid):
        """
    Creation of a new database user
    ---
    parameters:
      - name: body
        in: body
        schema:
          $ref: "#/definitions/User"
    definitions:
      User:
        type: object
        required:
          - username
          - password
        properties:
          username:
            type: str
            required: true
          password:
            type: str
            required: true
          note:
            type: str
    responses:
      200:
        description: A list of database users
        schema:
          $ref: '#/definitions/User'
        example:
          username: newuser
          password: newpassword
          note: test
      400:
        description: No data provided

        """

        if not userid:
            abort(404)
        request.get_json()
        if request.json is None:
            abort(400, message="No data provided")

        username = request.json.get('username')
        password = request.json.get('password')
        note = request.json.get('note')
        
        user = User.query.filter_by(id = userid).first()
        if user is not None:
            if username:
                user.login = username
            if password:
                user.hash_password(password)
            if note:
                user.note = note
                
            db.session.add(user)
            db.session.commit()
            return self.user_schema.dump(user).data, 201
        else:
            abort(404, message="No id specified")


    @auth.login_required
    def delete(self,  userid=None):
        """
    Delete user
    ---
    summary: "Delete user by id"
    parameters:
      - name: "userid"
        in: "path"
        description: "User id to delete"
        required: true
        type: "string"
    responses:
      200:
        description: User successfully deleted
      404:
        description: No user found for a given id or missing userid argument
        """

        if userid:
            user = User.query.filter_by(id = userid).first()
            if user is not None:
                db.session.delete(user)
                db.session.commit()
                return make_response("user successfully deleted ", 204)
            else:
                abort(404)
        abort(404, message="No id specified")


class PropertiesContacts(Resource):
    # TODO add patch here? No, we can simple delete a relation 
    contact_schema = ContactSchema(exclude=['property', 'property_id'])
    property_schema = PropertySchema()
    contacts_schema = ContactSchema(exclude=['property', 'property_id'], many=True)

    @auth.login_required
    def get(self, propertyid=None, contactid=None):
        """
        A list of all contacts/one contact if contactid is provided
       ---
       parameters:
         - in: path
           name: contactid
           type: int
           required: false
         - in: path
           name: propertyid
           type: int
           required: true
       responses:
         200:
           description: A single contact object or a list of objects
           schema:
             id: PropertyContact
         400:
           description: No corresponding contacts found
        """

        if propertyid is None:
            abort(400, message="No property id provided")

        if contactid is None:
            prop = Property.query.filter_by(id = propertyid).first()
            if prop is not None:
                res = self.contacts_schema.dump(prop.contacts)
                return res.data, 200
        else:
            contact = Contact.query.join(Property).filter(Property.id == propertyid).filter(Contact.id==contactid).first()
            if contact is not None:
                return self.contact_schema.dump(contact).data, 200
            else:
                abort(404)

    @auth.login_required
    def post(self, propertyid, contactid):
        """
    Creation of a new contact
    ---
    parameters:
      - name: propertyid
        type: int
        required: true
        in: path
      - name: body
        in: body
        schema:
          $ref: "#/definitions/PropertyContact"
    definitions:
      PropertyContact:
        type: object
        required:
          - firstname
          - lastname
          - landline
          - mobile
          - email
          - streetLocation
          - street
          - suburb
          - statusflag
          - postcode
        properties:
          firstname:
            type: str
            required: false
            example: John
          lastname:
            type: str
            required: false
            example: Smith
          landline:
            type: str
            required: false
            example: 02 2235 3434
          mobile:
            type: str
            required: false
            example: 0415 123 123
          email:
            type: str
            required: false
            example: john@example.com
          streetLocation:
            type: str
            required: true
            example: "3-34"
          street:
            type: str
            required: true
            example: "Faraway st"
          suburb:
            type: str
            required: true
            example: "DAWES POINT"
          postcode:
            type: str
            required: true
            example: "2000"
          property_id:
            type: int
            required: false
            example: 3
          appraisal_id:
            type: int
            required: false
            example: 5
    responses:
      201:
        description: New contact created
        schema:
          $ref: '#/definitions/Contact'
        example:
          postcode: 2000
          street: Faraway st
          streetLocation: '3-34'
          suburb: 'SYDNEY'
          firstname: John
          lastname: Smith
          email: john@txample.com
          landline: 02 2235 3434
          mobile: 0415 123 123
      400:
        description: No data provided for some mandatory fields

        """

        if not propertyid:
            abort(404)
        prop = Property.query.filter_by(id = propertyid).first()
        if prop is not None:
            if not contactid:
                contact_id = json.loads(request.json.get("contact_id"))
            else:
                contact_id = contactid

            contact = Contact.query.filter_by(id = contact_id).first()
            if contact is not None:
                contact.property_id = prop.id
                contact.property_linked_status = True
                db.session.add(contact)
                db.session.commit()
                return self.contact_schema.dump(contact).data, 201
            else:
                abort(404)
       
    @auth.login_required
    def delete(self, propertyid, contactid):
        """
    Delete contact
    ---
    summary: "Delete contact by id"
    parameters:
      - name: "contactid"
        in: "path"
        description: "Contact id to delete"
        required: true
        type: "string"
      - name: "propertyid"
        in: "path"
        description: "Related property id"
        required: true
        type: "string"
    responses:
      200:
        description: Contact successfully deleted
      404:
        description: No contact found for a given id or missing contactid argument
        """

        if not propertyid and not contactid:
            abort(404)
        # unlink contact from the property
        prop = Property.query.filter_by(id = propertyid).first()
        contact = Contact.query.join(Property).filter(Property.id == propertyid).filter(Contact.id==contactid).first()
        if prop is not None and contact is not None:
            contact.property_id = None
            contact.property_linked_status = None
                        
            db.session.add(contact)
            db.session.commit()
            return make_response("Relation deleted", 204)
        else:
            abort(404)

            

class AppraisalsNotes(Resource):
    note_schema = AppraisalNoteSchema()
    notes_schema = AppraisalNoteSchema(many=True)

    @auth.login_required
    def get(self, appraisalid=None, noteid=None):
        """
        A list of appraisal notes
       ---
       parameters:
         - in: path
           name: appraisalid
           type: int
           required: true
         - in: path
           name: noteid
           type: int
           required: false
       responses:
         200:
           description: A single note object or a list of objects
           schema:
             id: AppraisalNote
         400:
           description: No appraisalid specified
        """

        if appraisalid is None:
            abort(404, message="No appraisal id provided")

        if noteid is None:
            appraisal = Appraisal.query.filter_by(id = appraisalid).first()
            if appraisal is not None:
                return self.notes_schema.dump(appraisal.notes).data, 200
        else:
            note = Appraisal.query.join(Note).filter(Appraisal.id == appraisalid).filter(Note.id==noteid).first()
            if note is not None:
                return self.note_schema.dump(note).data, 200
            else:
                abort(404)

    @auth.login_required
    def post(self, appraisalid):
        """
    Creation of a new appraisal note
    ---
    parameters:
      - name: body
        in: body
        schema:
          $ref: "#/definitions/AppraisalNote"
    definitions:
      AppraisalNote:
        type: object
        properties:
          appraisal_id:
            type: int
            required: true
            example: 3
          text:
            type: str
            required: false
            example: Appraisal note
    responses:
      201:
        description: New note created
        schema:
          $ref: '#/definitions/AppraisalNote'
        example:
          timestamp: 2018-05-18 10:33:58
          appraisal_id: 2 
          text: Something important 
      400:
        description: No appraisal id provided

        """

        # get appraisalid
        # create new related note
        if not appraisalid:
            abort(404)

        appraisal = Appraisal.query.filter_by(id = appraisalid).first()
        if appraisal is not None:
            resp = {}
            request.get_json()
            text = request.json.get('text')
            newnote = AppraisalNote()
            newnote.appraisal_id = appraisal.id
            newnote.text = text
            db.session.add(newnote)
            db.session.commit()

            return self.note_schema.dump(newnote).data, 201
        else:
            abort(404)


    @auth.login_required
    def patch(self, appraisalid, noteid):
        """
    Edit of an appraisal note
    ---
    parameters:
      - name: body
        in: body
        schema:
          $ref: "#/definitions/AppraisalNoteEdit"
    definitions:
      AppraisalNoteEdit:
        type: object
        properties:
          appraisal_id:
            type: int
            required: true
            example: 3
          text:
            type: str
            required: false
            example: Appraisal note
    responses:
      200:
        description: Note edited
        schema:
          $ref: '#/definitions/AppraisalNoteEdit'
        example:
          timestamp: 2018-05-18 10:33:58
          appraisal_id: 2 
          text: Something important 
      400:
        description: No appraisalid and noteid provided

        """

        # get appraisalid
        # change related note attrs
        if not appraisalid and not noteid:
            abort(404)
        note = AppraisalNote.query.join(Appraisal).filter(Appraisal.id == appraisalid).filter(AppraisalNote.id==noteid).first()
        if note is not None:
            resp = {}
            request.get_json()
            text = request.json.get('text')
            appraisal_id = request.json.get('appraisal_id')

            if text is not None:
                note.text = text
                note.appraisal_id = int(appraisal_id)
                db.session.add(note)
                db.session.commit()
            db.session.add(note)
            db.session.commit()

            return self.note_schema.dump(note).data, 201
        else:
            abort(404)


    @auth.login_required
    def delete(self, appraisalid, noteid):
        """
    Delete appraisal note
    ---
    summary: "Delete appraisal note by id"
    parameters:
      - name: "appraisalid"
        in: "path"
        description: "Appraisal id"
        required: true
        type: int
      - name: "noteid"
        in: "path"
        description: "Note id to delete"
        required: true
        type: int
    responses:
      200:
        description: Appraisal note successfully deleted
      404:
        description: No corresponding note found
        """

        # delete related note
        if not appraisalid and not noteid:
            abort(404)
        note = AppraisalNote.query.join(Appraisal).filter(Appraisal.id == appraisalid).filter(AppraisalNote.id==noteid).first()
        if note is not None:
            db.session.delete(note)
            db.session.commit()
            return make_response("Note deleted", 204)

## >> там тпеперь просто текст, больше не используем отдельный заметки для активити
class ActivitiesNotes(Resource):
    note_schema = ActivityNoteSchema()
    notes_schema = ActivityNoteSchema(many=True)

    @auth.login_required
    def get(self, activityid=None, noteid=None):
        # get related note

        if activityid is None:
            abort(400, message="No activity id provided")

        if noteid is None:
            activity = Activity.query.filter_by(id = activityid).first()
            if activity is not None:
                return self.notes_schema.dump(activity.notes).data, 200
        else:
            note = ActivityNote.query.join(Activity).filter(Activity.id == activityid).filter(ActivityNote.id==noteid).first()
            if note is not None:
                return self.note_schema.dump(note).data, 200
            else:
                abort(404)

    @auth.login_required
    def post(self, activityid):
        # get activityid
        # create new related note
        if activityid is None:
            abort(404)

        activity = Activity.query.filter_by(id = activityid).first()
        if activity is not None:
            resp = {}
            request.get_json()
            text = request.json.get('text')
            newnote = ActivityNote()
            newnote.activity_id = activity.id
            newnote.text = text
            db.session.add(newnote)
            db.session.commit()
            
            return self.note_schema.dump(newnote).data, 201
        else:
            abort(404)

    @auth.login_required
    def patch(self, activityid, noteid):
        # get activityid
        # change related note attrs
        if activityid is None or noteid is None:
            abort(404)

        note = ActivityNote.query.join(Activity).filter(Activity.id == activityid).filter(ActivityNote.id==noteid).first()
        if note is not None:
            resp = {}
            request.get_json()
            text = request.json.get('text')
            if text is not None:
                note.text = text
                db.session.add(note)
                db.session.commit()

            return self.note_schema.dump(note).data, 201
        else:
            abort(404)
        
    @auth.login_required
    def delete(self, activityid, noteid):
        # delete related note
        if activityid is None or noteid is None:
            abort(404)
        note = ActivityNote.query.join(Activity).filter(Activity.id == activityid).filter(ActivityNote.id==noteid).first()

        if note is not None:
            db.session.delete(note)
            db.session.commit()
            return make_response("Note deleted", 204)
        else:
            abort(404)


class ContactsNotes(Resource):
    note_schema = ContactNoteSchema()
    notes_schema = ContactNoteSchema()

    @auth.login_required
    def get(self, contactid=None, noteid=None):
        """
        A list of contact notes
       ---
       parameters:
         - in: path
           name: contactid
           type: int
           required: true
         - in: path
           name: noteid
           type: int
           required: false
       responses:
         200:
           description: A single note object or a list of objects
           schema:
             id: ContactNote
         400:
           description: No contactid specified
        """

        if not contactid:
            abort(400, message="No contact id provided")

        if noteid is None:
            contact = Contact.query.filter_by(id = contactid).first()
            if contact is not None:
                return self.notes_schema.dump(contact.notes).data, 200
        else:
            note = ContactNote.query.join(Contact).filter(Contact.id == contactid).filter(ContactNote.id==noteid).first()
            if note is not None:
                return self.note_schema.dump(note).data, 200
            else:
                abort(404)

    @auth.login_required
    def post(self, contactid):
        """
    Creation of a new contact note
    ---
    parameters:
      - name: body
        in: body
        schema:
          $ref: "#/definitions/ContactNote"
    definitions:
      ContactNote:
        type: object
        properties:
          contact_id:
            type: int
            required: true
            example: 3
          text:
            type: str
            required: false
            example: Contact note
    responses:
      201:
        description: New note created
        schema:
          $ref: '#/definitions/ContactNote'
        example:
          timestamp: 2018-05-18 10:33:58
          contact_id: 2 
          text: Something important 
      400:
        description: No contact id provided

        """

        # get contactid
        # create new related note
        if not contactid:
            abort(404)
        contact = Contact.query.filter_by(id = contactid).first()
        if contact is not None:
            resp = {}
            request.get_json()
            text = request.json.get('text')
            newnote = ContactNote()
            newnote.contact_id = contact.id
            newnote.text = text
            db.session.add(newnote)
            db.session.commit()
            return self.note_schema.dump(newnote).data, 201
        else:
            abort(404)

    @auth.login_required
    def patch(self, contactid, noteid):
        """
    Edit of a contact note
    ---
    parameters:
      - name: body
        in: body
        schema:
          $ref: "#/definitions/ContactNoteEdit"
    definitions:
      ContactNoteEdit:
        type: object
        properties:
          contact_id:
            type: int
            required: true
            example: 3
          text:
            type: str
            required: false
            example: Contact note
    responses:
      200:
        description: Note edited
        schema:
          $ref: '#/definitions/ContactNoteEdit'
        example:
          timestamp: 2018-05-18 10:33:58
          contact_id: 2 
          text: Something important 
      400:
        description: No contactid and noteid provided

        """

        # get contactid
        # change related note attrs
        if not contactid or not noteid:
            abort(404)
        note = ContactNote.query.join(Contact).filter(Contact.id == contactid).filter(ContactNote.id==noteid).first()
        if note is not None:
            resp = {}
            request.get_json()
            text = request.json.get('text')
            if text is not None:
                note.text = text
                db.session.add(note)
                db.session.commit()

            return self.note_schema.dump(note).data, 201
        else:
            abort(404)

    @auth.login_required
    def delete(self, contactid, noteid):
        """
    Delete appraisal note
    ---
    summary: "Delete contact note by id"
    parameters:
      - name: "contactid"
        in: "path"
        description: "Contact id"
        required: true
        type: int
      - name: "noteid"
        in: "path"
        description: "Note id to delete"
        required: true
        type: int
    responses:
      200:
        description: Contact note successfully deleted
      404:
        description: No corresponding note found
        """

        # delete related note
        if not contactid and not noteid:
            abort(404)
        note = ContactNote.query.join(Contact).filter(Contact.id == contactid).filter(ContactNote.id==noteid).first()
        if note is not None:
            db.session.delete(note)
            db.session.commit()
            return make_response("Note deleted", 204)
        else:
            abort(404)


class PropertiesAppraisals(Resource):
    appraisal_schema = AppraisalSchema()
    appraisals_schema = AppraisalSchema(many=True)
    @auth.login_required
    def get(self, propertyid=None, appraisalid=None):
        """
        A list of property appraisals
       ---
       parameters:
         - in: path
           name: propertyid
           type: int
           required: true
         - in: path
           name: appraisalid
           type: int
           required: false
       responses:
         200:
           description: A single appraisal object or a list of objects
           schema:
             id: PropertyAppraisal
         400:
           description: No propertyid specified
        """

        if propertyid is None:
            abort(400, message="No property id provided")
        
        if appraisalid is None:
            prop = Property.query.filter_by(id = propertyid).first()
            if prop is not None:
                return self.appraisals_schema.dump(prop.appraisal).data, 200
        else:
            appraisal = Appraisal.query.filter_by(id = appraisalid).first()
            if appraisal is not None:
                return self.appraisal_schema.dump(appraisal).data, 200
            else:
                abort(404)


    @auth.login_required
    def post(self, propertyid=None):
        """
    Creation of a new appraisal note
    ---
    parameters:
      - name: body
        in: body
        schema:
          $ref: "#/definitions/PropertyAppraisal"
    definitions:
      PropertyAppraisal:
        type: object
        properties:
          property_id:
            type: int
            required: true
            example: 3
          notes:
            type: object
            required: false
            schema:
              $ref: "#/definitions/AppraisalNote"
    responses:
      201:
        description: New appraisal created
        schema:
          $ref: '#/definitions/PropertyAppraisal'
        example:
          timestamp: 2018-05-18 10:33:58
          property_id: 2 
          notes: Something important 
      400:
        description: No property id provided

        """

        # new property appraisal
        if not propertyid:
            abort(404)
        prop = Property.query.filter_by(id = propertyid).first()
        if prop is not None:
            resp = {}
            request.get_json()
            text = request.json.get('text')
            # TODO Appraisal note here?
            newappraisal = Appraisal()
            newappraisal.property_id = prop.id
            db.session.add(newappraisal)
            db.session.commit()
            return self.appraisal_schema.dump(newappraisal).data, 201
        
        else:
            abort(404)

    @auth.login_required
    def delete(self, propertyid=None, appraisalid=None):
        """
    Delete appraisal note
    ---
    summary: "Delete property appraisal by id"
    parameters:
      - name: "propertyid"
        in: "path"
        description: "Property id"
        required: true
        type: int
      - name: "appraisalid"
        in: "path"
        description: "Appraisal id to delete"
        required: true
        type: int
    responses:
      200:
        description: Property appraisal successfully deleted
      404:
        description: No corresponding appraisal found
        """

        # delete property appraisal
        if not propertyid and not appraisalid:
            abort(404)
        prop = Property.query.filter_by(id = propertyid).first()
        appraisal = Appraisal.query.join(Property).filter(Property.id == propertyid).filter(Appraisal.id==appraisalid).first()
        if prop is not None and appraisal is not None:
            db.session.delete(appraisal)
            db.session.commit()
            return make_response("Appraisal deleted", 204)
        else:
            abort(404)


class ContactsActivities(Resource):
    activities_schema = ActivitySchema(many=True)
    activity_schema = ActivitySchema()

    contact_schema = ContactSchema()

    @auth.login_required

    def get(self, contactid=None, activityid=None):
        """
        A list of all contact activities
       ---
       parameters:
         - in: path
           name: contactid
           type: int
           required: false
         - in: path
           name: activityid
           type: int
           required: false
       responses:
         200:
           description: A single activity object or a list of objects
           schema:
             id: Activity
         400:
           description: No contactid specified
        """

        if contactid is None:
            abort(400, message="No contact id provided")
        
        if activityid is None:
            contact = Contact.query.filter_by(id = contactid).first()
            if contact is not None:
                res = self.activities_schema.dump(contact.activities)
                return res.data, 200
        else:
            activity = Activity.query.join(Contact).filter(Contact.id == contactid).filter(Activity.id == activityid).first()
            if activity is not None:
                return self.activity_schema.dump(activity).data, 200
            else:
                abort(404)

    @auth.login_required
    def post(self, contactid=None):
        """
    Creation of a new contact activity
    ---
    parameters:
      - name: body
        in: body
        schema:
          $ref: "#/definitions/Activity"
    definitions:
      Activity:
        type: object
        properties:
          timestamp:
            type: str
            required: false
            example: 2018-05-18 10:32:05
          duedate:
            type: str
            required: false
            example: 2018-05-18
          activity:
            type: int
            required: true
            example: 1
          note:
            type: str
            required: false
            example: Activity note
    responses:
      201:
        description: New activity created
        schema:
          $ref: '#/definitions/Activity'
        example:
          timestamp: 2018-05-18 10:33:58
          activity: 1
          note: Something important 
      400:
        description: No contactid provided

        """
        request.get_json()

        if contactid is None:
            abort(400, message="No contact id provided")

        contact = Contact.query.filter_by(id = contactid).first()
        if contact is not None:
            newactivity = Activity()
            newactivity.contact_id = contact.id
            # newactivity.currentdate = datetime.date.today()
            duedate = request.json.get('duedate')
            activity = request.json.get('activity', 1)
            newactivity.duedate = duedate
            note = request.json.get('note')
            newactivity.note = note
            newactivity.activity = activity
            db.session.add(newactivity)
            db.session.commit()
            return self.activity_schema.dump(newactivity).data, 201
        else:
            abort(404)

    @auth.login_required
    def patch(self, contactid=None, activityid=None):
        """
    Edition of a contact activity
    ---
    parameters:
      - name: body
        in: body
        schema:
          $ref: "#/definitions/ActivityEdit"
    definitions:
      ActivityEdit:
        type: object
        properties:
          activity:
            type: int
            required: false
            example: 1
          timestamp:
            type: str
            required: false
            example: 2018-05-18 10:32:05
          duedate:
            type: str
            required: false
            example: 2018-05-18
          note:
            type: str
            required: false
            example: Activity note
    responses:
      200:
        description: Activity edited
        schema:
          $ref: '#/definitions/ActivityEdit'
        example:
          timestamp: 2018-05-18 10:33:58
          activity: On DataBase(1)
          note: Something important 
      400:
        description: No contactid provided

        """

        if not  contactid and not activityid:
            abort(404)
        contact = Contact.query.filter_by(id = contactid).first()
        act = Activity.query.join(Contact).filter(Contact.id == contactid).filter(Activity.id==activityid).first()
        if contact is not None and activity is not None:
            request.get_json()
            for pr in ['activity', 'duedate', 'timestamp', 'note']:
                par = request.json.get(pr)
                if par is not None:
                    setattr(act, pr, par)
            db.session.add(act)
            db.session.commit()

            return self.activity_schema.dump(activity).data, 201
        else:
            abort(404)

    @auth.login_required
    def delete(self, contactid=None, activityid=None):
        """
    Delete Contact activity
    ---
    summary: "Delete property by id"
    parameters:
      - name: "contactid"
        in: "path"
        description: "Contact id"
        required: true
        type: "string"
      - name: "activityid"
        in: "path"
        description: "Activity id to delete"
        required: true
        type: "string"
    responses:
      200:
        description: Activity successfully deleted
      404:
        description: No contact or activity with corresponding id found
        """

        if contactid and activityid:
            activity = Activity.query.join(Contact).filter(Contact.id == contactid).filter(Activity.id == activityid).first()
            if activity is not None:
                db.session.delete(activity)
                db.session.commit()
                return make_response("Activity deleted ", 204)
            else:
                abort(404)
        else:
            abort(404)


class Contacts(Resource):
    contact_schema = ContactSchema(exclude=['property', 'postcode_id'])
    contacts_schema = ContactSchema(many=True, exclude=['property', 'postcode_id'])

    @auth.login_required
    def get(self, contactid=None):
        """
        A list of all contacts/one contact if contactid is provided
       ---
       parameters:
         - in: path
           name: contactid
           type: int
           required: false
       responses:
         200:
           description: A single contact object or a list of objects
           schema:
             id: Contact
         400:
           description: No corresponding contacts found
        """

        if contactid is None:
            contacts = Contact.query.all()
            result = self.contacts_schema.dump(contacts)
            return result.data, 200
        else:
            contact = Contact.query.filter_by(id = contactid).first()
            if contact is not None:
                return self.contact_schema.dump(contact).data, 200
            else:
                abort(404)

    @auth.login_required
    def post(self):
        """
    Creation of a new contact
    ---
    parameters:
      - name: body
        in: body
        schema:
          $ref: "#/definitions/Contact"
    definitions:
      Contact:
        type: object
        required:
          - firstname
          - lastname
          - landline
          - mobile
          - email
          - streetLocation
          - street
          - suburb
          - statusflag
          - postcode
        properties:
          firstname:
            type: str
            required: false
            example: John
          lastname:
            type: str
            required: false
            example: Smith
          landline:
            type: str
            required: false
            example: 02 2235 3434
          mobile:
            type: str
            required: false
            example: 0415 123 123
          email:
            type: str
            required: false
            example: john@example.com
          streetLocation:
            type: str
            required: true
            example: "3-34"
          street:
            type: str
            required: true
            example: "Faraway st"
          suburb:
            type: str
            required: true
            example: "DAWES POINT"
          postcode:
            type: str
            required: true
            example: "2000"
          property_id:
            type: int
            required: false
            example: 3
          appraisal_id:
            type: int
            required: false
            example: 5
    responses:
      201:
        description: New contact created
        schema:
          $ref: '#/definitions/Contact'
        example:
          postcode: 2000
          street: Faraway st
          streetLocation: '3-34'
          suburb: 'SYDNEY'
          firstname: John
          lastname: Smith
          email: john@txample.com
          landline: 02 2235 3434
          mobile: 0415 123 123
      400:
        description: No data provided for some mandatory fields

        """

        resp = {}
        request.get_json()
        firstname = request.json.get('firstname', '')
        lastname = request.json.get('lastname', '')
        landline = request.json.get('landline', '0')
        mobile = request.json.get('mobile', '0')
        email = request.json.get('email')
        streetLocation = request.json.get('streetLocation')
        #unitnum = request.json.get('unitnum')
        street = request.json.get('street')
        suburb = request.json.get('suburb')
        postcode = request.json.get('postcode')
        property_linked_status = request.json.get('property_linked_status')
        note = request.json.get('notes', None)
        property_id = request.json.get('property_id')
        appraisal_id = request.json.get('appraisal_id')
        # 

        # try:
        #    int(property_id)
        # except:
        #    abort(400, message="No id specified")


        # try:
        #    int(appraisal_id)
        # except:
        #     abort(400, message="No id specified")

        if len(landline) < 2 and len(mobile) < 2:
            abort(400, message="Landline or mobile are mandatory")

        # if firstname is None or lastname is None:
        #    abort(400, message="Firstname or lastname are mandatory")

        
        # if len(firstname) < 1 or len(lastname) < 1:
        #    abort(400, message="Firstname or lastname are mandatory")
        
        # смотрим чтобы suburb соответствовал посткоду
        pcode = Postcode.query.filter_by(postcode=postcode).all()
        if len(pcode) == 0:
            abort(400, message="Wrong postcode {0}".format(postcode))
        else:
            if suburb not in [s.suburb for s in pcode]:
                abort(400, message="No such suburb {0} with postcode {1}".format(suburb, postcode))
        pcode = [p for p in pcode if p.suburb==suburb][0]

        # contact dulplicates:
        # by phone only
        if len(mobile) > 2:
            mobile_dupl = Contact.query.filter(Contact.mobile == mobile).first()
            if mobile_dupl:
                return self.contact_schema.dump(mobile_dupl).data, 200
        if len(landline) > 2:
            landline_dupl = Contact.query.filter(Contact.landline == landline).first()
            if landline_dupl:
                return self.contact_schema.dump(landline_dupl).data, 200


        # dupl_contact = Contact.query.filter(Contact.firstname == firstname).filter(Contact.lastname == lastname)
        # if len(landline) > 1:
        #    dupl_contact.filter(Contact.landline == landline)
        # if len(mobile) > 1:
        #    dupl_contact.filter(Contact.mobile == mobile)
        # existing = dupl_contact.first()
        # if existing:
        #    return self.contact_schema.dump(existing).data, 200

        newcontact = Contact()
        newcontact.firstname = firstname
        newcontact.lastname = lastname
        if len(landline) > 2:
            newcontact.landline = landline
        if len(mobile) > 2:
            newcontact.mobile = mobile
        newcontact.email = email
        newcontact.streetLocation = streetLocation
        newcontact.street = street
        newcontact.suburb = pcode.suburb
        newcontact.postcode_id = pcode.id

        if property_id is not None:
            prop = Property.query.filter_by(id=property_id).first()
            if prop is not None:
                newcontact.property_linked_status = True
                newcontact.property_id = prop.id

        db.session.add(newcontact)
        db.session.commit()
        # TODO activity отдельным запросом
        # newactivity = Activity(contact_id=newcontact.id, note=note)
        # db.session.add(newactivity)
        # db.session.commit()
        # newnote = ActivityNote(activity_id=newactivity.id, text=note)
        # db.session.add(newnote)
        # db.session.commit()
        
        # print(newnote)
        
        
        return self.contact_schema.dump(newcontact).data, 201


    @auth.login_required
    def patch(self, contactid):
        # edit contact
        """
    Edition of a given contact
    ---
    parameters:
      - name: contactid
        in: path
        type: int
        required: true
      - name: body
        in: body
        schema:
          $ref: "#/definitions/Contact"
    definitions:
      Contact:
        type: object
        properties:
          firstname:
            type: str
            required: true
            example: John
          lastname:
            type: str
            required: true
            example: Smith
          landline:
            type: str
            required: false
            example: 02 2235 3434
          mobile:
            type: str
            required: false
            example: 0415 123 123
          email:
            type: str
            required: false
            example: john@example.com
          streetLocation:
            type: str
            required: true
            example: "3-34"
          street:
            type: str
            required: true
            example: "Faraway st"
          suburb:
            type: str
            required: true
            example: "DAWES POINT"
          postcode:
            type: str
            required: true
            example: "2000"
          property_id:
            type: int
            required: false
            example: 3
          appraisal_id:
            type: int
            required: false
            example: 5
          property_linked_status:
            type: bool
            required: false
            example: false
    responses:
      201:
        description: New contact created
        schema:
          $ref: '#/definitions/Contact'
        example:
          postcode: 2000
          street: Faraway st
          streetLocation: '3-34'
          suburb: 'SYDNEY'
          firstname: John
          lastname: Smith
          email: john@txample.com
          landline: 02 2235 3434
          mobile: 0415 123 123
      400:
        description: No data provided for some mandatory fields

        """
        contact = Contact.query.filter_by(id = contactid).first()
        if contact is not None:
            resp = {}
            request.get_json()
            for pr in ['firstname', 'lastname', 'landline', 'mobile', 'email', 'streetLocation', 'street', 'postcode', 'property_linked_status', 'notes', 'property_id', 'appraisal_id', 'postcode']:

                par = request.json.get(pr)
                if par is not None:
                    if pr == "postcode":
                        postcode = Postcode.query.filter_by(postcode=par).first()
                        #address = request.json.get(address)
                        #clean_street = address.lower()
                        #for s in street_suffixes:
                        #    clean_street = clean_street.replace(s, '')
                            
                        # check for similar address
                        #neighbours = Contact.query.filter_by(postcode_id=postcode.id).all()
                        #for n in neighbours:
                        #    if clean_street == n.street_name:
                        #        abort(400, message="Duplicate address for a contact.")

                        contact.postcode_id = postcode.id
                    else:
                        setattr(contact, pr, par)

            db.session.add(contact)
            db.session.commit()

            return self.contact_schema.dump(contact).data, 201

        else:
            abort(404)

    @auth.login_required
    def delete(self, contactid):
        """
    Delete contact
    ---
    summary: "Delete contact by id"
    parameters:
      - name: "contactid"
        in: "path"
        description: "Contact id to delete"
        required: true
        type: "string"
    responses:
      200:
        description: Contact successfully deleted
      404:
        description: No contact found for a given id or missing contactid argument
        """

        if contactid is not None:
            contact = Contact.query.filter_by(id = contactid).first()
            if contact is not None:
                db.session.delete(contact)
                db.session.commit()
                return make_response("contact successfully deleted ", 204)
        abort(404)


class Properties(Resource):
    properties_schema = PropertySchema(exclude=['postcode_id', 'postcode_', ], many=True)
    property_schema = PropertySchema(exclude=['postcode_id', 'postcode_', ])

    @auth.login_required
    def get(self, propertyid=None):
        """
        A list of all properties/one property if propertyid is provided
       ---
       parameters:
         - in: path
           name: propertyid
           type: int
           required: false
       responses:
         200:
           description: A single property object or a list of objects
           schema:
             id: Property
         400:
           description: No corresponding property found
        """

        if propertyid is None:
            properties = Property.query.all()
            result = self.properties_schema.dump(properties)
            return result.data, 200
        else:
            prop = Property.query.filter_by(id = propertyid).first()
            if prop is not None:
                return self.property_schema.dump(prop).data, 200
            else:
                abort(404)

    @auth.login_required
    def post(self):
        """
    Creation of a new property
    ---
    parameters:
      - name: body
        in: body
        schema:
          $ref: "#/definitions/Property"
    definitions:
      Property:
        type: object
        required:
          - streetLocation
          - street
          - suburb
          - statusflag
          - postcode
        properties:
          pricefinderid:
            type: int
            required: false
            example: 20000
          streetLocation:
            type: str
            required: true
            example: "3-34"
          street:
            type: str
            required: true
            example: "Faraway st"
          suburb:
            type: str
            required: true
            example: "DAWES POINT"
          postcode:
            type: str
            required: true
            example: "2000"
          last_update_date:
            type: str
            required: false
            example: "2018-05-18"
          market_status:
            type: str
            required: false
            example: 'example status'

    responses:
      200:
        description: An existing property with same street and same postcode found
        schema:
          $ref: '#/definitions/Property'
        example:
          postcode: 2000
          pricefinderid: 2000000
          statusflag: 'Recently added property'
          street: somestreet
          streetLocation: '3-34'
          suburb: 'DAWES POINT'
      201:
        description: New property created
        schema:
          $ref: '#/definitions/Property'
        example:
          postcode: 2000
          pricefinderid: 2000000
          statusflag: 'Recently added property'
          street: somestreet
          streetLocation: '3-34'
          suburb: 'DAWES POINT'
      400:
        description: No data provided for some mandatory fields

        """

        resp = {}
        request.get_json()
        streetLocation = request.json.get('streetLocation')
        #unitnum = request.json.get('unitnum')
        street = request.json.get('street')
        postcode = request.json.get('postcode')
        suburb = request.json.get('suburb')
        pricefinderid = request.json.get('pricefinderid')
        last_update_date = request.json.get('last_update_date', None)
        market_status = request.json.get('market_status', None)
        for par in [streetLocation, street, postcode, suburb]:
            if par is None:
                if hasattr(par, "__name__"):
                    abort(400, message="%s mandatory" % par.__name__)
            
        pcode = Postcode.query.filter_by(postcode=postcode).all()
        if len(pcode) == 0:
            abort(400, message="Wrong postcode {0}".format(postcode))
        else:
            if suburb.upper() not in [s.suburb for s in pcode]:
                abort(400, message="No such suburb {0} with postcode {1}".format(suburb, postcode))
        
        pcode = [p for p in pcode if p.suburb==suburb][0]
        # pcode = postcode
        clean_street = street.lower()
        
        # берем все из одного посткода
        neighbours = Property.query.join(Postcode).filter(Postcode.postcode == postcode).all()
        for n in neighbours:
            # один postcode может в себя включать разные suburb 
            # то есть 2066 может иместь разные названия suburb 
            # но все равно повторяющихся улиц в одном postcode нет
            # Возможно 
            # 2 Jones St Suburb1 2000
            # 2 Jones st Suburb2 2001
            # Но не может быть та же улица с тем же названиями в одном suburb
            if clean_street == n.street.lower() and suburb.lower() == n.suburb.lower() and streetLocation == n.streetLocation:
                dupl_property = Property.query.filter_by(id=n.id).first()
                resp = self.property_schema.dump(dupl_property).data
                return resp, 200


        newproperty = Property(streetLocation = streetLocation, 
                               # suburb = pcode.suburb,
                               suburb = suburb,
                               street = street, 
                               postcode_id = pcode.id,
                               last_update_date = last_update_date,
                               market_status = market_status
                              )
        if pricefinderid is not None:
            newproperty.pricefinderid = pricefinderid
        db.session.add(newproperty)
        db.session.commit()

        return self.property_schema.dump(newproperty).data, 201


    @auth.login_required
    def patch(self, propertyid):
        """
    Edit an existing property
    ---
    parameters:
      - name: propertyid
        in: path
        type: int
        required: true
      - name: body
        in: body
        schema:
          $ref: "#/definitions/PropertyEdit"
    definitions:
      PropertyEdit:
        type: object
        required:
          - propertyid
        properties:
          propertyid:
            type: int
            required: true
            example: 2
          pricefinderid:
            type: int
            required: false
            example: 20000
          streetLocation:
            type: str
            required: false
            example: "3-34"
          street:
            type: str
            required: false
            example: "Faraway st"
          suburb:
            type: str
            required: false
            example: "DAWES POINT"
          postcode:
            type: str
            required: false
            example: "2000"
          last_update_date:
            type: str
            required: false
            example: "2018-05-18"
          market_status:
            type: str
            required: false
            example: 'example status'

    responses:
      201:
        description: Property successfully edited
        schema:
          $ref: '#/definitions/PropertyEdit'
        example:
          propertyid: 2
          postcode: 2000
          pricefinderid: 2000000
          statusflag: 'Recently added property'
          street: somestreet
          streetLocation: '3-34'
          suburb: 'DAWES POINT'
      404:
        description: No propertyid provided or no property found for a given id
        """
         
        if not propertyid:
            abort(404)
        prop = Property.query.filter_by(id = propertyid).first()
        if prop is None:
            abort(404)
            
        request.get_json()

        for pr in ['streetLocation', 'street', 'postcode', 'statusflag', 'pricefinderid', 'last_update_date', 'market_status']:
            par = request.json.get(pr)
            
            if par is not None:
                    if pr == "postcode":
                        postcode = Postcode.query.filter_by(postcode=par).first()
                        # address = request.json.get(address)
                        # clean_street = address.lower()
                        # for s in street_suffixes:
                        #    clean_street = clean_street.replace(s, '')
                            
                        # check for similar address
                        # neighbours = Property.query.filter_by(postcode_id=postcode.id).all()
                        # for n in neighbours:
                        #     if clean_street == n.street_name:
                        #        abort(400, message="Duplicate address for a property.")


                        prop.postcode_id = postcode.id
                        prop.suburb = postcode.suburb
                    else:
                        setattr(prop, pr, par)

        db.session.add(prop)
        db.session.commit()
        return self.property_schema.dump(prop).data, 201

    @auth.login_required
    def delete(self, propertyid=None):
        """
    Delete property
    ---
    summary: "Delete property by id"
    parameters:
      - name: "propertyid"
        in: "path"
        description: "Property id to delete"
        required: true
        type: "string"
    responses:
      200:
        description: Property successfully deleted
      404:
        description: No property found for a given id or missing propertyid argument
        """

        if propertyid:
            prop = Property.query.filter_by(id = propertyid).first()
            if prop is not None:
                db.session.delete(prop)
                db.session.commit()
                return make_response("Property deleted", 200)
            else:
                abort(404)
        abort(404, message="No id specified")

@app.route('/api/postcode/update', methods=['GET'])
#@auth.login_required
def postcode_update():
    with open('postcodes.csv', newline='') as csvfile:
        csvf = csv.reader(csvfile, delimiter=';', quotechar='"')
        for row in csvf:
            postcode = row[0]
            suburb = row[1]
            res = Postcode.query.filter(Postcode.suburb == suburb).filter(Postcode.postcode==postcode).first()
            if res is None:
                print(row)
                newpostcode = Postcode()
                newpostcode.postcode = int(postcode)
                newpostcode.suburb = suburb
                db.session.add(newpostcode)
                db.session.commit()


@app.route('/api/properties/search', methods=['POST'])
@auth.login_required
def properties_search():
    """
    Search of a property by postcode, suburb or street name
    ---
    parameters:
      - name: body
        in: body
        schema:
          $ref: "#/definitions/PropertySearch"

    definitions:
      Terms:
        properties:
          street:
            type: str
            example: Alma road
          suburb:
            type: str
            example: Sydney
          postcode:
            type: int
            example: 2000
      PropertySearch:
        properties:
          terms:
            $ref: "#/definitions/Terms"
        additionalProperties:
          $ref: "#/definitions/Terms"
    responses:
      200:
        description: A matching property found
      400:
        description: No search terms provided
      404:
        description: Nothing found

        """
    
    properties_schema = PropertySchema(exclude=['postcode_id', 'postcode_'], many=True)
    property_schema = PropertySchema(exclude=['postcode_id', 'postcode_'])
    # ee
    request.get_json()
    if request.json is not None:
        terms = request.json.get('terms')
        
        # пока будем искать по street, suburb, postcode
        if terms is None or len(terms) == 0:
            abort(400, message="Search terms are required")
        
        properties = Property.query.join(Postcode)
        if "suburb" in terms.keys():
            suburb = terms["suburb"].upper()
        else:
            suburb = None
        if "postcode" in terms.keys():
            postcode = terms["postcode"]
        else:
            postcode = None
        if "street" in terms.keys():
            street = terms["street"].upper()
        else:
            street = None

        try:
            limit = int(request.json.get('limit'))
        except:
            limit = None

        try:
            offset = int(request.json.get('offset'))
        except:
            offset = None

        if suburb is not None:
            properties = properties.filter(Postcode.suburb == suburb)
        if postcode is not None:
            properties = properties.filter(Postcode.postcode == postcode)
        if street is not None:
            properties = properties.filter(func.upper(Property.street) == street)

        if limit is not None:
            properties = properties.limit(limit)

        if offset is not None:
            properties = properties.offset(offset)

        if properties.count() > 1:
            res = properties_schema.dump(properties.all())
            return make_response(jsonify(properties_schema.dump(properties.all()).data))

        elif properties.count() == 1:
            res = property_schema.dump(properties.first())
            return make_response(jsonify(res.data))

        else:
            return abort(404)


    return abort(404)


@app.route('/api/contacts/search', methods=['POST'])
@auth.login_required
def contacts_search():
    """
    Contact search by landline or mobile phone
    ---
    parameters:
      - name: body
        in: body
        schema:
          $ref: "#/definitions/ContactTerms"

    definitions:
      ContactTerms:
        properties:
          phone:
            type: str
            example: "0222353434"
    responses:
      200:
        description: A matching contact found
      400:
        description: No search terms provided
      404:
        description: Nothing found

        """
    
    contacts_schema = ContactSchema(exclude=['postcode_id', 'postcode_'], many=True)
    contact_schema = ContactSchema(exclude=['postcode_id', 'postcode_'], many=True)

    request.get_json()
    if request.json is not None:
        phone = request.json.get('phone', None)
        if phone is None or len(phone) < 2:
            abort(400, message="Search terms are required")

        contacts = None 
        
        contacts = Contact.query.filter(or_(Contact.landline == phone, Contact.mobile == phone))
        res = contacts.all()
        if len(res) > 0:
            res = contacts_schema.dump(res)
            return make_response(jsonify(res.data)), 200
        
    return abort(404)


# urls 
# +GET +POST +PATCH +DELETE
# +TEST +HTTPCODES -VALIDATION
# +API REVIEW
# +поправить response, сделать 2 schemas для 1 и для > 1 результата
# -посмотреть как в flask-marshmaillow можно оформить related fields
# -поправить ресурсы чтобы в swagger попадали правильные urlы а не все подряд
#  для этого надо разделить классы чтобы часть принимала id как аргумент, а вторая часть работала
#  бы без аргументов
# +swagger 
# +++++users
# +++++propertiescontacts 
# +++++appraisalnotes
# +++++contactsnotes 
# +++++propertiesappraisal
# +++++contactsactivities 
# +++++contacts
# +++++properties

# Посмотреть как работают:
# AppraisalContacts
# ContactsNotes
# AppraisalNotes

# activity duedate - передавать где?

#api.add_resource(Users, '/api/users', '/api/users/<int:userid>')
api.add_resource(ContactsActivities,
                 '/api/contacts/<int:contactid>/activities',
                 '/api/contacts/<int:contactid>/activities/<int:activityid>'
                 )
api.add_resource(PropertiesContacts,
                 '/api/properties/<int:propertyid>/contacts',
                 '/api/properties/<int:propertyid>/contacts/<int:contactid>'
                 )
api.add_resource(PropertiesAppraisals,
                 '/api/properties/<int:propertyid>/appraisals',
                 '/api/properties/<int:propertyid>/appraisals/<int:appraisalid>'
                 )
api.add_resource(Contacts, 
                 '/api/contacts', 
                 '/api/contacts/<int:contactid>'
                 )
api.add_resource(Properties,
                 '/api/properties', 
                 '/api/properties/<int:propertyid>',
                 )
api.add_resource(AppraisalsNotes,
                 '/api/appraisals/<int:appraisalid>/notes',
                 '/api/appraisals/<int:appraisalid>/notes/<int:noteid>'
                 )
api.add_resource(ActivitiesNotes,
                 '/api/activities/<int:activityid>/notes',
                 '/api/activities/<int:activityid>/notes/<int:noteid>'
                 )
api.add_resource(ContactsNotes,
                 '/api/contacts/<int:contactid>/notes',
                 '/api/contacts/<int:contactid>/notes/<int:noteid>'
                 )


if __name__ == '__main__':
    app.run(host='0.0.0.0')
