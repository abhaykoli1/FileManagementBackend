import json
import re
from typing import Optional
import uuid
from fastapi import APIRouter, Depends, UploadFile, Form, HTTPException, File
from models.fileFolder import FileTable
from utils.auth import get_current_user_from_token
from models.folder import Folder, FolderBase
from bson import ObjectId
from mongoengine.queryset.visitor import Q
from pathlib import Path

from utils.data_incrypto import encrypt_response
router = APIRouter()

@router.post("/folder-create")
async def createFolder(body: FolderBase, current_user = Depends(get_current_user_from_token)):
    try:
        folder = Folder(
        owner = ObjectId(current_user.id),
        name = body.name,
        parent = body.parent,
        visibility = body.visibility,
        allowed_users = body.allowed_users
        )
        folder.save()
        response = {
        "status": "ok",
        "data": json.loads(folder.to_json()),
        "message": "Folder created succes",
        }
        encrypted = encrypt_response(response)
        return {
            "data": encrypted
        }
    except :
        response = {
        "status": "ok",
        "data": None,
        "message": "Folder already exist in your orgonisation",
        }
        encrypted = encrypt_response(response)
        return {
            "data": encrypted
        }



    

   


@router.put("/folder-update")
async def updateFolder(current_user = Depends(get_current_user_from_token)):
    return {
        "data": json.loads(current_user.to_json())
    }

@router.get("/folder-get-root")
async def getAllFolders(current_user = Depends(get_current_user_from_token)):
    findata = Folder.objects(Q(owner = ObjectId(current_user.id)) | Q(allowed_users = ObjectId(current_user.id) )).all()
    findataFile = FileTable.objects(Q(owner = ObjectId(current_user.id)) & Q(parent = None )).all()
    response = {
        "message": "All Folders",

        "data": {
            "folderes":json.loads(findata.to_json()),
            "files": json.loads(findataFile.to_json())
        }
    }
    return {
        "data":encrypt_response(response)
    }


@router.get("/folder-get-inner")
async def getAllFolders(current_user = Depends(get_current_user_from_token),   folderId: str = Form(...),):
    findata = Folder.objects(Q(owner = ObjectId(current_user.id)) | Q(allowed_users = ObjectId(current_user.id) )).all()
    findataFile = FileTable.objects(parent = ObjectId(folderId)).all()
    response = {
        "message": "All Foldersv & files",

        "data": {
            "folderes":json.loads(findata.to_json()),
            "files": json.loads(findataFile.to_json())
        }
    }
    return {
        "data": encrypt_response(response)
    }


UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

@router.post("/upload-chunk/")
async def upload_chunk(
    file: UploadFile = File(...),
    chunk_number: int = Form(...),
    total_chunks: int = Form(...),
    file_id: str = Form(...),
):
    chunk_dir = UPLOAD_DIR / file_id
    chunk_dir.mkdir(exist_ok=True)

    # Save this chunk
    chunk_path = chunk_dir / f"{chunk_number}.part"
    with open(chunk_path, "wb") as buffer:
        buffer.write(await file.read())

    response = {"status": "success", "chunk_number": chunk_number}
    return {
        "data": encrypt_response(response)
    }


def get_unique_filename(filename: str, owner_id: str) -> str:
    # Extract base name and extension
    match = re.match(r"^(.*?)(?: \((\d+)\))?(\.\w+)$", filename)
    if not match:
        raise ValueError("Invalid filename format")
    
    base_name, copy_number, extension = match.groups()
    copy_number = int(copy_number) if copy_number else 0

    # Check if filename exists for the same owner
    counter = copy_number
    new_filename = filename
    
    while FileTable.objects(name=new_filename, owner=owner_id).first():
        counter += 1
        new_filename = f"{base_name} ({counter}){extension}"
    
    return new_filename


@router.post("/merge-chunks/")
async def merge_chunks(
    file_id: str = Form(...),
    original_filename: str = Form(...),
    total_chunks: int = Form(...),
    folderId: Optional[str] = Form(None),
    current_user = Depends(get_current_user_from_token)
):
    """
    Merge all uploaded chunks into a single file and return a download URL.
    File will be stored with a random UUID name but keep original extension.
    """
    try:
        chunk_dir = UPLOAD_DIR / file_id
        if not chunk_dir.exists():
            raise HTTPException(status_code=404, detail="Chunks not found")

        # Get original extension (like .mp4, .pdf, etc.)
        extension = Path(original_filename).suffix
        random_name = f"{uuid.uuid4().hex}{extension}"
        final_path = UPLOAD_DIR / random_name

        # Merge chunks
        with open(final_path, "wb") as outfile:
            for i in range(1, total_chunks + 1):
                chunk_file = chunk_dir / f"{i}.part"
                if not chunk_file.exists():
                    raise HTTPException(
                        status_code=400,
                        detail=f"Missing chunk {i}, re-upload required",
                    )
                with open(chunk_file, "rb") as infile:
                    outfile.write(infile.read())

        # cleanup chunks
        for f in chunk_dir.glob("*.part"):
            f.unlink()
        chunk_dir.rmdir()

        # ✅ Download URL
        download_url = f"/files/{random_name}"
        filename = get_unique_filename(filename= original_filename, owner_id=current_user.id)
        saveFile = FileTable(
            name = filename,
            owner = ObjectId(current_user.id),
            parent = folderId,
            file_link = download_url
        ),
        saveFile.save()
       
        response =  {
            "status": "merged",
            "stored_filename": random_name,
            "original_filename": original_filename,
            "size_in_gb": round(final_path.stat().st_size / (1024**3), 2),
            "download_url": download_url,
        }
        return {
            "data" : encrypt_response(response)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))