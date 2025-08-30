import os
from typing import Optional
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status, Body
JWT_SECRET = os.getenv("JWT_SECRET", "supersecretjwtkey")
JWT_ALGO = "HS256"
from models.userModel import User
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
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


def get_user_by_username(username: str) -> Optional[User]:
    return User.objects(username=username).first()

