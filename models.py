#!/usr/bin/python
# -*- coding: utf-8 -*-

import datetime

import enum
import re
import random
import string

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint
from sqlalchemy.orm import backref, validates
from sqlalchemy.ext.hybrid import hybrid_property
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import URLSafeSerializer, BadSignature, SignatureExpired
from flask import current_app


landline_regex = re.compile("(\(?\d{2}\)?)\s?(\d{4})\s?(\d{4})")
mobile_regex = re.compile("(\d{4})\s?(\d{3})\s?(\d{3})")

db = SQLAlchemy()

street_suffixes = [" st", " pl", " cr", " dr", " rd"]

class ActivityType(enum.Enum):
    nophone = "No phone number(4)"
    rangout = "Phone rang out(5)"
    notconnected = "Phone not connected(4)"
    potential = "Potential(7)"
    post = "Post(8)"
    connectiton = "Phone call (connection)(1)"
    ondatabase = "On DataBase(1)"
    succknocked = "Door knocked (success)"
    unsuccknocked = "Door knocked (unseccessful)"
    leftvoicemessage = "Left voice message"
    cardsent = "Card sent"


class StatusFlag(enum.Enum):
    # TODO What flags to return?
    newdata = "Recently added property"
    status1 = "Status 1"
    status2 = "Status 2"


class Postcode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    postcode = db.Column(db.Integer())
    suburb = db.Column(db.String(400))

class ContactNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(), nullable=False, default=datetime.datetime.utcnow)
    text = db.Column(db.Text(), nullable=False)
    contact_id = db.Column(db.Integer, db.ForeignKey('contact.id', ondelete='CASCADE'))

class ActivityNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(), nullable=False, default=datetime.datetime.utcnow)
    text = db.Column(db.Text(), nullable=False)
    activity_id = db.Column(db.Integer, db.ForeignKey('activity.id', ondelete='CASCADE'))

class AppraisalNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(), nullable=False, default=datetime.datetime.utcnow)
    text = db.Column(db.Text(), nullable=False)
    appraisal_id = db.Column(db.Integer, db.ForeignKey('appraisal.id', ondelete='CASCADE'))

class Contact(db.Model):
    # checkconstraint doesnt work in mysql
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(150))
    lastname = db.Column(db.String(150))
    landline = db.Column(db.String(15))
    mobile = db.Column(db.String(15))
    email = db.Column(db.String(150))
    streetLocation = db.Column(db.Text())
    street = db.Column(db.Text())
    
    #address = db.Column(db.Text())
    #unitnum = db.Column(db.String(15))
    #streetnum = db.Column(db.String(15))
    # suburb is from postcodes
    # suburb = db.Column(db.String(150))
    # ENUM
    postcode = db.relationship('Postcode', backref='contacts')
    postcode_id = db.Column(db.Integer, db.ForeignKey('postcode.id'))
    property_linked_status = db.Column(db.Boolean, default=False)
    # FK
    notes = db.relationship('ContactNote', backref='contact', cascade="all,delete")
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'))
    appraisal_id = db.Column(db.Integer, db.ForeignKey('appraisal.id'))
    activities = db.relationship('Activity', backref='contact', cascade="all,delete", order_by="Activity.timestamp")

    #@hybrid_property
    #def addr_string(self):
    #    return "{} {} {} {} [}".format(self.unitnum, self.streetnum, self.address, self.postcode.suburb, self.postcode.postcode)

    @validates('email')
    def validate_email(self, key, mail):
        if len(mail) > 1:
            assert '@' in mail
        return mail

    @validates('landline', 'mobile')
    def validate_phone(self, key, phone):
        if phone.startswith("^"):
            phone = phone.replace("^", "")
        if key == 'landline':
            if len(phone) > 1:
                assert landline_regex.search(phone)
        if key == 'mobile':
            if len(phone) > 1:
                assert mobile_regex.search(phone)

        return phone

    @hybrid_property
    def street_name(self):
        street = self.address.lower()
        for s in street_suffixes:
            street = street.replace(s, "")
        return street


class Property(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pricefinderid = db.Column(db.Integer, nullable=True)
    streetLocation = db.Column(db.Text(), nullable=False)
    street = db.Column(db.Text(), nullable=False)
    #unitnum = db.Column(db.String(15), nullable=False)
    #streetnum = db.Column(db.String(15), nullable=False)
    suburb = db.Column(db.String(150), nullable=False)
    postcode_ = db.relationship('Postcode', backref='properties')
    postcode_id = db.Column(db.Integer, db.ForeignKey('postcode.id'))
    statusflag = db.Column(db.Enum(StatusFlag), nullable=False, default=StatusFlag.newdata)
    # FK
    contacts = db.relationship('Contact', backref='property')
    last_update_date = db.Column(db.Date())
    market_status = db.Column(db.String(15))

    #@hybrid_property
    #def addr_string(self):
    #    return "{} {} {} {} [}".format(self.unitnum, self.streetnum, self.address, self.postcode.suburb, self.postcode.postcode)

    @hybrid_property
    def street_name(self):
        street = self.address.lower()
        for s in street_suffixes:
            street = street.replace(s, "")
        return street

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # currentdate = db.Column(db.Date(), nullable=False, default=datetime.date.today)
    timestamp = db.Column(db.DateTime(), nullable=False, default=datetime.datetime.utcnow)
    duedate = db.Column(db.Date(), nullable=True)
    activity = db.Column(db.Integer, nullable=False, default=1)
    contact_id = db.Column(db.Integer, db.ForeignKey('contact.id', ondelete='CASCADE'))
    note = db.Column(db.Text(), nullable=True)
    # db.relationship('ActivityNote', backref=backref('activity', cascade="all,delete"))
    

class Appraisal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(), nullable=False, default=datetime.datetime.utcnow)
    # FK -> Contact Id может быть больше чем один
    _property = db.relationship('Property', backref=backref('appraisal', cascade="all,delete"))
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'))
    contacts = db.relationship('Contact', backref=backref('appraisal', cascade="all,delete"))
    notes = db.relationship('AppraisalNote', backref='appraisal', cascade="all,delete")


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(400))
    password_hash = db.Column(db.String(400))
    note = db.Column(db.Text(), nullable=True)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self):
        s = URLSafeSerializer(current_app.config['SECRET_KEY'])
        return s.dumps({ 'id': self.id })

    @staticmethod
    def verify_auth_token(token):
        s = URLSafeSerializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None 
        except BadSignature:
            return None 
        user = User.query.get(data['id'])

        return user

# DB events, for insert initial values
# after tables creation

@db.event.listens_for(Postcode.__table__, 'after_create')
def fill_postcodes(mapper, connection, target):
    postcodes = []
    with open('./postcodes.csv', 'r') as pcodes:
        for line in pcodes:
            p, s = line.replace('"', split(":"))
            newpostcode = Postcode(p, s)
            postcodes.append(newpostode)
    db.session.bulk_save_object(postcodes)
    db.session.commit()

@db.event.listens_for(User.__table__, 'after_create')
def create_db_user(mapper, connection, target):
    print('trololo')
