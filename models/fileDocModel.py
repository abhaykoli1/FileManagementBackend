from mongoengine import Document, StringField, EmailField, DateTimeField, BooleanField, ListField, ReferenceField, IntField
from datetime import datetime
from models.userModel import User
from models.folderModel import Folder
class FileDoc(Document):
    folder = ReferenceField(Folder, required=True)
    original_name = StringField(required=True)
    s3_key = StringField(required=True)
    uploaded_by = ReferenceField(User)
    size = IntField()
    created_at = DateTimeField(default=datetime.utcnow)