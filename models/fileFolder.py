from mongoengine import Document, StringField, EmailField, DateTimeField, ReferenceField, ListField
from models.userModel import User
from datetime import datetime
from pydantic import BaseModel, Field
from models.folder import Folder

class FileTable(Document):
    name = StringField(required=True)
    owner = ReferenceField(User, required=True)
    parent = ReferenceField(Folder, null=True)
    file_link = StringField(required=True)
    creted_date = DateTimeField(default=datetime.utcnow)
    

