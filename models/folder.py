from mongoengine import Document, StringField, EmailField, DateTimeField, ReferenceField, ListField
from models.userModel import User
from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class Folder(Document):
    name = StringField(required=True, unique=True)
    owner = ReferenceField(User, required=True)
    parent = ReferenceField('self', null=True)
    created_at = DateTimeField(default=datetime.utcnow)
    visibility = StringField(choices=["private","public","restricted"], default="private")
    allowed_users = ListField(ReferenceField(User))
    meta = {
        "indexes": [
            {"fields": ["owner", "name"], "unique": True}
        ]
    }



class FolderBase(BaseModel):
    name: str = Field(..., description="Folder name")
    parent: Optional[str] = Field(None, description="Parent Folder ID")
    visibility: str = Field(default="private", description="Visibility of folder: private, public, restricted")
    allowed_users: List[str] = Field(default_factory=list, description="List of allowed User IDs")

    class Config:
        orm_mode = True