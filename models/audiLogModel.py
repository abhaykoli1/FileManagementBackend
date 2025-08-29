from mongoengine import Document, StringField, EmailField, DateTimeField, BooleanField, ListField, ReferenceField, IntField
from datetime import datetime
from models.userModel import User
class AuditLog(Document):
    user = ReferenceField(User, null=True)
    action = StringField()
    target = StringField()
    timestamp = DateTimeField(default=datetime.utcnow)