"""
Office Document Management System - FastAPI backend with local server storage
Single-file reference implementation for development/testing.

Features:
- Admin and user login (JWT)
- RBAC: admin, user
- Nested folders (parent reference)
- Folder visibility: private, public, restricted
- Optional folder password protection (bcrypt)
- Folder expiry
- Files uploaded to local storage with key: <folder_id>/<uuid>.<ext>
- File metadata stored in MongoDB
- Direct file downloads from server
- User list + activate/deactivate
- Audit logs

NOTES:
- For production split into modules, add HTTPS, rate-limits, validation, pagination, background tasks, proper logging.
"""

import json
import os
import uuid
from datetime import datetime, timedelta
from typing import List, Optional
import mongoengine as me
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status, Body
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware

from models.userModel import User, UserCreate, UserOut, Token
from models.folderModel import Folder, FolderCreate
from models.fileDocModel import FileDoc
from models.audiLogModel import AuditLog
import uvicorn
# ---------------------------
# Configuration
# ---------------------------
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://avbigbuddy:nZ4ATPTwJjzYnm20@cluster0.wplpkxz.mongodb.net/smsTest2")
JWT_SECRET = os.getenv("JWT_SECRET", "supersecretjwtkey")
JWT_ALGO = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60*24*7))

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")  # Local storage path
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------------------------
# DB connection
# ---------------------------
me.connect(host=MONGO_URI)

# ---------------------------
# Password & Auth
# ---------------------------
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="Office DMS (Local Storage)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Helpers
# ---------------------------
def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_ctx.verify(password, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES())
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGO)

def ACCESS_TOKEN_EXPIRY_MINUTES():
    return ACCESS_TOKEN_EXPIRE_MINUTES

def get_user_by_username(username: str) -> Optional[User]:
    return User.objects(username=username).first()


async def get_current_user_from_token(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate":"Bearer"}
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(username)
    if user is None or not user.is_active:
        raise credentials_exception
    return user

def admin_required(user: User = Depends(get_current_user_from_token)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user

def audit(user: Optional[User], action: str, target: str):
    try:
        AuditLog(user=user, action=action, target=target).save()
    except Exception:
        pass

# ---------------------------
# Local file helpers
# ---------------------------
def local_save_file(fileobj, key: str):
    save_path = os.path.join(UPLOAD_DIR, key)
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    with open(save_path, "wb") as f:
        f.write(fileobj.read())

def local_get_file_path(key: str) -> str:
    return os.path.join(UPLOAD_DIR, key)

# ---------------------------
# Routes: Auth & Users
# ---------------------------
@app.post('/auth/register', response_model=UserOut)
def register_user(payload: UserCreate):
    if get_user_by_username(payload.username):
        raise HTTPException(status_code=400, detail="Username exists")
    hashed = hash_password(payload.password)
    user = User(username=payload.username, password_hash=hashed, role=payload.role).save()
    # audit(admin, "create_user", user.username)
    return UserOut(id=str(user.id), username=user.username, role=user.role, is_active=user.is_active, created_at=user.created_at)


@app.post('/auth/login', response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_username(form_data.username)
    if not user or not verify_password(form_data.password, user.password_hash) or not user.is_active:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES()))
    audit(user, "login", user.username)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/auth/me", )
def read_users_me(current_user = Depends(get_current_user_from_token)):
   
    return {
        "message":"user deatils",
        "data": json.loads(current_user.to_json())
    }


@app.get('/users', response_model=List[UserOut])
def list_users(admin: User = Depends(admin_required)):
    users = User.objects()
    return [UserOut(id=str(u.id), username=u.username, role=u.role, is_active=u.is_active, created_at=u.created_at) for u in users]


@app.get('/usersDetails', response_model=List[UserOut])
def list_users(admin: User = Depends(admin_required)):
    print(users.to)
    users = User.objects()
    print(users.to_json())
    return [UserOut(id=str(u.id), username=u.username, role=u.role, is_active=u.is_active, created_at=u.created_at) for u in users]

@app.post('/users/{username}/activate')
def activate_user(username: str, admin: User = Depends(admin_required)):
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(404, "User not found")
    user.is_active = True
    user.save()
    audit(admin, "activate_user", username)
    return {"ok": True}

@app.post('/users/{username}/deactivate')
def deactivate_user(username: str, admin: User = Depends(admin_required)):
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(404, "User not found")
    user.is_active = False
    user.save()
    audit(admin, "deactivate_user", username)
    return {"ok": True}

# ---------------------------
# Folder endpoints
# ---------------------------
@app.post('/folders/create')
def create_folder(payload: FolderCreate, user: User = Depends(get_current_user_from_token)):
    parent = None
    if payload.parent_id:
        parent = Folder.objects(id=payload.parent_id).first()
        if not parent:
            raise HTTPException(404, "Parent folder not found")
        if not _has_write_permission(user, parent):
            raise HTTPException(403, "No write permission on parent folder")
    folder = Folder(name=payload.name, owner=user, parent=parent, visibility=payload.visibility)
    if payload.password:
        folder.password_hash = hash_password(payload.password)
    if payload.allowed_usernames:
        users = [get_user_by_username(uname) for uname in payload.allowed_usernames if get_user_by_username(uname)]
        folder.allowed_users = users
    if payload.expiry_days:
        folder.expiry_date = datetime.utcnow() + timedelta(days=payload.expiry_days)
    folder.save()
    audit(user, "create_folder", folder.name)
    return {"id": str(folder.id), "name": folder.name, "parent_id": str(parent.id) if parent else None}

@app.get('/folders',)
def list_folders(user: User = Depends(get_current_user_from_token)):
    folders = Folder.objects(owner=user)
    return {
        "folders": json.loads(folders.to_json()),
    }

@app.get('/folders/{folder_id}')
def get_folder(folder_id: str, user: User = Depends(get_current_user_from_token), password: Optional[str] = None):
    folder = Folder.objects(id=folder_id).first()
    if not folder:
        raise HTTPException(404, "Folder not found")
    if not _has_read_permission(user, folder):
        if folder.password_hash:
            if not password or not verify_password(password, folder.password_hash):
                raise HTTPException(403, "Password required or wrong")
        else:
            raise HTTPException(403, "No access to folder")
    if folder.expiry_date and folder.expiry_date < datetime.utcnow():
        raise HTTPException(403, "Folder expired")
    audit(user, "view_folder", folder.name)
    return {
        "id": str(folder.id),
        "name": folder.name,
        "owner": folder.owner.username,
        "parent_id": str(folder.parent.id) if folder.parent else None,
        "visibility": folder.visibility,
        "has_password": bool(folder.password_hash),
        "expiry_date": folder.expiry_date,
        "created_at": folder.created_at
    }

# ---------------------------
# Files: upload & download (local)
# ---------------------------
@app.post('/files/upload')
def upload_file(folder_id: str = Body(...), upload: UploadFile = File(...), user: User = Depends(get_current_user_from_token)):
    folder = Folder.objects(id=folder_id).first()
    if not folder:
        raise HTTPException(404, "Folder not found")
    if not _has_write_permission(user, folder):
        raise HTTPException(403, "No write permission on folder")
    if folder.expiry_date and folder.expiry_date < datetime.utcnow():
        raise HTTPException(403, "Folder expired")

    ext = ''
    if '.' in upload.filename:
        ext = '.' + upload.filename.split('.')[-1]
    key = f"{str(folder.id)}/{uuid.uuid4()}{ext}"

    try:
        local_save_file(upload.file, key)
        size = os.path.getsize(local_get_file_path(key))
        fdoc = FileDoc(folder=folder, original_name=upload.filename, s3_key=key, uploaded_by=user, size=size)
        fdoc.save()
        audit(user, "upload_file", upload.filename)
        return {"file_id": str(fdoc.id), "original_name": fdoc.original_name}
    except Exception as e:
        raise HTTPException(500, f"Upload failed: {str(e)}")

@app.get('/files/download/{file_id}')
def download_file(file_id: str, user: User = Depends(get_current_user_from_token), password: Optional[str] = None):
    fdoc = FileDoc.objects(id=file_id).first()
    if not fdoc:
        raise HTTPException(404, "File not found")
    folder = fdoc.folder
    if not _has_read_permission(user, folder):
        if folder.password_hash:
            if not password or not verify_password(password, folder.password_hash):
                raise HTTPException(403, "Password required or wrong")
        else:
            raise HTTPException(403, "No access to file")

    file_path = local_get_file_path(fdoc.s3_key)
    if not os.path.exists(file_path):
        raise HTTPException(404, "File missing on server")

    audit(user, "download_file", fdoc.original_name)
    return FileResponse(file_path, filename=fdoc.original_name)

# ---------------------------
# Permissions
# ---------------------------
def _has_read_permission(user: User, folder: Folder) -> bool:
    if user.role == 'admin':
        return True
    if folder.owner.id == user.id:
        return True
    if folder.visibility == 'public':
        return True
    if folder.visibility == 'restricted' and any(u.id == user.id for u in folder.allowed_users):
        return True
    return False

def _has_write_permission(user: User, folder: Folder) -> bool:
    if user.role == 'admin' or folder.owner.id == user.id or 'write' in getattr(user, 'permissions', []):
        return True
    return False

# ---------------------------
# Startup: default admin
# ---------------------------
@app.on_event('startup')
def ensure_admin():
    try:
        if User.objects(role='admin').count() == 0:
            print("No admin found. Creating default admin: username=admin password=admin")
            hashed = hash_password('admin')
            User(username='admin', password_hash=hashed, role='admin').save()
    except Exception as e:
        print('Startup admin creation error:', e)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True, log_level="info")