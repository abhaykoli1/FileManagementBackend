from typing import Optional
from mongoengine import Document, StringField, EmailField, DateTimeField, BooleanField, ListField
from datetime import datetime
from pydantic import BaseModel
class User(Document):
    username = StringField(required=True, unique=True)
    password_hash = StringField(required=True)
    role = StringField(choices=["admin", "user"], default="user")
    is_active = BooleanField(default=True)
    permissions = ListField(StringField(choices=["read","write","delete"]))
    created_at = DateTimeField(default=datetime.utcnow)

class UserCreate(BaseModel):
    username: str
    password: str
    role: Optional[str] = "user"

class UserOut(BaseModel):
    id: str
    username: str
    role: str
    is_active: bool
    created_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"