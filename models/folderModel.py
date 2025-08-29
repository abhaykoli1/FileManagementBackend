
from typing import List, Optional
from mongoengine import Document, StringField, EmailField, DateTimeField, BooleanField, ListField, ReferenceField
from models.userModel import User
from datetime import datetime
from pydantic import BaseModel

class Folder(Document):
    name = StringField(required=True)
    owner = ReferenceField(User, required=True)
    parent = ReferenceField('self', null=True)
    password_hash = StringField(null=True)
    visibility = StringField(choices=["private","public","restricted"], default="private")
    allowed_users = ListField(ReferenceField(User))
    expiry_date = DateTimeField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)

class FolderCreate(BaseModel):
    name: str
    parent_id: Optional[str] = None
    password: Optional[str] = None
    visibility: Optional[str] = "private"
    allowed_usernames: Optional[List[str]] = None
    expiry_days: Optional[int] = None