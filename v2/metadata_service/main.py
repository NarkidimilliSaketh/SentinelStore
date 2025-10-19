import os
import secrets
import json
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from bson import ObjectId
from typing import List
import httpx

from database import user_collection, file_collection, access_control_collection, logs_collection
from models import (
    UserRegisterSchema, FileCreateSchema, FileResponseSchema, 
    TokenSchema, FileDeleteSchema, SharedFileResponseSchema,
    ShareRequestSchema, FileDetailsResponseSchema,
    UserPublicKeysRequest, UserPublicKeyResponse, FileBulkDeleteSchema, FileBulkUnshareSchema
)
from auth import (
    get_password_hash, verify_password, create_access_token, 
    get_current_user, get_current_admin_user
)
# CORRECTED: Import the function with the correct name
from worker import re_shard_file

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://localhost:\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def create_log_entry(request: Request, username: str, action: str, status: str, details: dict = None):
    log_entry = {
        "timestamp": datetime.now(timezone.utc),
        "username": username,
        "action": action,
        "ip_address": request.client.host if request else "N/A",
        "user_agent": request.headers.get("user-agent") if request else "N/A",
        "status": status,
        "details": details or {}
    }
    await logs_collection.insert_one(log_entry)

@app.post("/logs/record", status_code=status.HTTP_201_CREATED)
async def record_log_entry(request: Request, details: dict, current_user: str = Depends(get_current_user)):
    action = details.pop("action", "UNKNOWN_CLIENT_ACTION")
    await create_log_entry(request, current_user, action, "SUCCESS", details)
    return {"message": "Log recorded"}

# --- Authentication and User Routes ---

@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
async def register_user(request: Request, user: UserRegisterSchema):
    existing_user = await user_collection.find_one({"username": user.username})
    if existing_user:
        await create_log_entry(request, user.username, "REGISTER_ATTEMPT", "FAILURE", {"reason": "Username already exists"})
        raise HTTPException(status_code=400, detail="Username already registered")
    
    salt = secrets.token_hex(16)
    hashed_password = get_password_hash(user.password)
    
    new_user = {
        "username": user.username,
        "hashed_password": hashed_password,
        "salt": salt,
        "public_key": user.public_key,
        "encrypted_private_key": user.encrypted_private_key,
        "role": "user"
    }
    await user_collection.insert_one(new_user)
    await create_log_entry(request, user.username, "REGISTER", "SUCCESS")
    return {"message": "User registered successfully"}

@app.post("/auth/login", response_model=TokenSchema)
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = await user_collection.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        await create_log_entry(request, form_data.username, "LOGIN_ATTEMPT", "FAILURE", {"reason": "Incorrect username or password"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    
    await create_log_entry(request, form_data.username, "LOGIN", "SUCCESS")
    
    access_token = create_access_token(data={"sub": user["username"], "role": user.get("role", "user")})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/{username}")
async def get_user_info(username: str, current_user: str = Depends(get_current_user)):
    user = await user_collection.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return { "username": user["username"], "public_key": user["public_key"] }

@app.post("/users/public-keys", response_model=List[UserPublicKeyResponse])
async def get_users_public_keys(request: UserPublicKeysRequest, current_user: str = Depends(get_current_user)):
    users_cursor = user_collection.find({"username": {"$in": request.usernames}})
    users = await users_cursor.to_list(len(request.usernames))
    found_users = [
        UserPublicKeyResponse(username=user["username"], public_key=user["public_key"])
        for user in users
    ]
    return found_users

@app.get("/me")
async def get_my_info(current_user: str = Depends(get_current_user)):
    user = await user_collection.find_one({"username": current_user})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "username": user["username"],
        "public_key": user["public_key"],
        "encrypted_private_key": user["encrypted_private_key"]
    }

# --- File Management Routes ---

@app.post("/files", response_model=FileResponseSchema)
async def add_file_entry(request: Request, file: FileCreateSchema, current_user: str = Depends(get_current_user)):
    file_doc = {
        "filename": file.filename,
        "root_hash": file.root_hash,
        "encrypted_file_key": file.encrypted_file_key,
        "owner": current_user,
        "erasure": file.erasure,
        "createdAt": datetime.now(timezone.utc)
    }
    result = await file_collection.insert_one(file_doc)
    created_file = await file_collection.find_one({"_id": result.inserted_id})
    created_file["_id"] = str(created_file["_id"])
    
    await create_log_entry(request, current_user, "UPLOAD_FILE", "SUCCESS", {"file_id": str(result.inserted_id), "filename": file.filename})
    return created_file

@app.get("/files", response_model=List[FileResponseSchema])
async def list_my_files(current_user: str = Depends(get_current_user)):
    files = await file_collection.find({"owner": current_user}).to_list(1000)
    for file in files:
        file["_id"] = str(file["_id"])
    return files

@app.get("/files/{file_id}/details", response_model=FileDetailsResponseSchema)
async def get_file_details(file_id: str, current_user: str = Depends(get_current_user)):
    try:
        obj_id = ObjectId(file_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid file ID format")

    file_doc = await file_collection.find_one({"_id": obj_id})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    is_owner = file_doc["owner"] == current_user
    
    if not is_owner:
        is_shared_with = await access_control_collection.find_one({
            "file_id": file_id,
            "shared_with_user": current_user
        })
        if not is_shared_with:
            raise HTTPException(status_code=403, detail="You do not have permission to view this file's details")

    sharing_cursor = access_control_collection.find({"file_id": file_id})
    sharing_info = await sharing_cursor.to_list(1000)

    log_cursor = logs_collection.find({"details.file_id": file_id}).sort("timestamp", -1)
    activity_log = await log_cursor.to_list(100)

    file_doc["_id"] = str(file_doc["_id"])
    file_doc["sharing_info"] = sharing_info
    file_doc["activity_log"] = activity_log
    
    return file_doc

@app.get("/files/{file_id}/access-key")
async def get_access_key(file_id: str, current_user: str = Depends(get_current_user)):
    try:
        obj_id = ObjectId(file_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid file ID format")

    file_doc = await file_collection.find_one({"_id": obj_id})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    if file_doc["owner"] == current_user:
        return {"encrypted_file_key": file_doc["encrypted_file_key"]}

    share_doc = await access_control_collection.find_one({
        "file_id": file_id,
        "shared_with_user": current_user
    })
    if share_doc:
        return {"encrypted_file_key": share_doc["encrypted_file_key_for_recipient"]}
    
    raise HTTPException(status_code=403, detail="You do not have permission to access this file.")

@app.post("/files/delete-bulk", status_code=status.HTTP_204_NO_CONTENT)
async def secure_bulk_delete_file_entries(
    request: Request, delete_request: FileBulkDeleteSchema,
    current_user: str = Depends(get_current_user)
):
    user = await user_collection.find_one({"username": current_user})
    if not user or not verify_password(delete_request.password, user["hashed_password"]):
        await create_log_entry(request, current_user, "DELETE_BULK_ATTEMPT", "FAILURE", {"reason": "Incorrect password"})
        raise HTTPException(status_code=401, detail="Incorrect password. Deletion denied.")

    try:
        object_ids = [ObjectId(fid) for fid in delete_request.file_ids]
    except Exception:
        raise HTTPException(status_code=400, detail="One or more file IDs are invalid.")

    delete_result = await file_collection.delete_many({
        "_id": {"$in": object_ids},
        "owner": current_user
    })

    await access_control_collection.delete_many({
        "file_id": {"$in": delete_request.file_ids}
    })

    await create_log_entry(
        request, current_user, "DELETE_BULK", "SUCCESS", 
        {"deleted_count": delete_result.deleted_count, "file_ids": delete_request.file_ids}
    )
    return

# --- File Sharing Routes ---

@app.post("/files/{file_id}/share", status_code=status.HTTP_201_CREATED)
async def share_file(request: Request, file_id: str, share_request: ShareRequestSchema, current_user: str = Depends(get_current_user)):
    try:
        obj_id = ObjectId(file_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid file ID format")

    file_to_share = await file_collection.find_one({"_id": obj_id})
    if not file_to_share:
        raise HTTPException(status_code=404, detail="File not found")
    if file_to_share["owner"] != current_user:
        raise HTTPException(status_code=403, detail="Only the owner can share this file")

    recipient = await user_collection.find_one({"username": share_request.share_with_username})
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient user not found")

    existing_share = await access_control_collection.find_one({
        "file_id": file_id,
        "shared_with_user": share_request.share_with_username
    })
    if existing_share:
        raise HTTPException(status_code=400, detail="File is already shared with this user")

    share_doc = {
        "file_id": file_id,
        "owner": current_user,
        "shared_with_user": share_request.share_with_username,
        "encrypted_file_key_for_recipient": share_request.encrypted_file_key_for_recipient,
        "permission": "read"
    }
    await access_control_collection.insert_one(share_doc)
    await create_log_entry(request, current_user, "SHARE_FILE", "SUCCESS", {"file_id": file_id, "filename": file_to_share["filename"], "shared_with": share_request.share_with_username})
    return {"message": f"File successfully shared with {share_request.share_with_username}"}

@app.post("/files/{file_id}/unshare", status_code=status.HTTP_204_NO_CONTENT)
async def unshare_file(request: Request, file_id: str, share_info: dict, current_user: str = Depends(get_current_user)):
    user_to_unshare = share_info.get("username")
    if not user_to_unshare:
        raise HTTPException(status_code=400, detail="Username to unshare is required")

    try:
        obj_id = ObjectId(file_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid file ID format")

    file_doc = await file_collection.find_one({"_id": obj_id})
    if not file_doc or file_doc["owner"] != current_user:
        raise HTTPException(status_code=403, detail="Only the owner can unshare this file")

    result = await access_control_collection.delete_one({
        "file_id": file_id,
        "shared_with_user": user_to_unshare
    })

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Sharing entry not found")

    await create_log_entry(request, current_user, "UNSHARE_FILE", "SUCCESS", {"file_id": file_id, "unshared_from": user_to_unshare})
    return

@app.post("/files/unshare-bulk", status_code=status.HTTP_204_NO_CONTENT)
async def secure_bulk_unshare_file_entries(
    request: Request, unshare_request: FileBulkUnshareSchema,
    current_user: str = Depends(get_current_user)
):
    try:
        object_ids = [ObjectId(fid) for fid in unshare_request.file_ids]
    except Exception:
        raise HTTPException(status_code=400, detail="One or more file IDs are invalid.")

    owned_files_count = await file_collection.count_documents({
        "_id": {"$in": object_ids},
        "owner": current_user
    })
    if owned_files_count != len(unshare_request.file_ids):
        raise HTTPException(status_code=403, detail="You do not own all the specified files.")

    await access_control_collection.delete_many({
        "file_id": {"$in": unshare_request.file_ids},
        "shared_with_user": unshare_request.username
    })

    await create_log_entry(
        request, current_user, "UNSHARE_BULK", "SUCCESS", 
        {"unshared_from": unshare_request.username, "file_ids": unshare_request.file_ids}
    )
    return

@app.get("/files/shared-with-me", response_model=List[SharedFileResponseSchema])
async def list_files_shared_with_me(current_user: str = Depends(get_current_user)):
    shared_entries = await access_control_collection.find({"shared_with_user": current_user}).to_list(1000)
    
    response_files = []
    for entry in shared_entries:
        file_doc = await file_collection.find_one({"_id": ObjectId(entry["file_id"])})
        if file_doc:
            response_files.append({
                "file_id": entry["file_id"],
                "filename": file_doc["filename"],
                "root_hash": file_doc["root_hash"],
                "owner": file_doc["owner"],
                "encrypted_file_key": entry["encrypted_file_key_for_recipient"]
            })
    return response_files

# --- Admin Section ---

@app.get("/admin/stats")
async def get_admin_stats(admin_user: dict = Depends(get_current_admin_user)):
    total_users = await user_collection.count_documents({})
    
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    active_user_pipeline = [
        {"$match": {"action": "LOGIN", "status": "SUCCESS", "timestamp": {"$gte": seven_days_ago}}},
        {"$group": {"_id": "$username"}},
        {"$count": "count"}
    ]
    active_user_result = await logs_collection.aggregate(active_user_pipeline).to_list(1)
    active_users = active_user_result[0]["count"] if active_user_result else 0

    logins_today = await logs_collection.count_documents({
        "action": "LOGIN", "status": "SUCCESS",
        "timestamp": {"$gte": datetime.now(timezone.utc) - timedelta(days=1)}
    })
    
    registrations_today = await logs_collection.count_documents({
        "action": "REGISTER", "status": "SUCCESS",
        "timestamp": {"$gte": datetime.now(timezone.utc) - timedelta(days=1)}
    })

    total_files = await file_collection.count_documents({})

    return {
        "total_users": total_users,
        "active_users": active_users,
        "logins_today": logins_today,
        "registrations_today": registrations_today,
        "total_files": total_files
    }

@app.get("/admin/users")
async def get_all_users(admin_user: dict = Depends(get_current_admin_user)):
    users_cursor = user_collection.find({})
    users = await users_cursor.to_list(1000)
    for user in users:
        del user["hashed_password"]
        del user["salt"]
        del user["encrypted_private_key"]
        user["_id"] = str(user["_id"])
    return users

@app.delete("/admin/users/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_by_admin(username: str, admin_user: dict = Depends(get_current_admin_user)):
    if username == admin_user.username:
        raise HTTPException(status_code=400, detail="Admin cannot delete their own account.")
    
    delete_result = await user_collection.delete_one({"username": username})
    if delete_result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found.")
    
    await file_collection.delete_many({"owner": username})
    await access_control_collection.delete_many({"owner": username})
    await access_control_collection.delete_many({"shared_with_user": username})
    
    return

@app.post("/admin/files/{file_id}/re-shard")
async def admin_re_shard_file(
    file_id: str, 
    new_params: dict,
    admin_user: dict = Depends(get_current_admin_user)
):
    try:
        obj_id = ObjectId(file_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid file ID format")

    file_doc = await file_collection.find_one({"_id": obj_id})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    owner_doc = await user_collection.find_one({"username": file_doc["owner"]})
    if not owner_doc:
        raise HTTPException(status_code=404, detail="File owner not found")

    new_n = new_params.get("n")
    new_k = new_params.get("k")
    owner_password = new_params.get("owner_password")
    if not all([new_n, new_k, owner_password]):
        raise HTTPException(status_code=400, detail="New 'n', 'k', and 'owner_password' parameters are required.")

    if not verify_password(owner_password, owner_doc["hashed_password"]):
        raise HTTPException(status_code=401, detail="The provided password for the file owner is incorrect.")

    try:
        # Call the corrected worker function
        new_root_hash, new_encrypted_file_key = await re_shard_file(file_doc, owner_doc, new_n, new_k, owner_password)
        
        await file_collection.update_one(
            {"_id": obj_id},
            {"$set": {
                "root_hash": new_root_hash,
                "erasure": {"n": new_n, "k": new_k}
            }}
        )
        
        return {"message": "File re-sharded successfully", "new_root_hash": new_root_hash}
    except Exception as e:
        print(f"Re-sharding failed: {e}")
        raise HTTPException(status_code=500, detail=f"An internal error occurred during re-sharding: {e}")

@app.post("/admin/trigger-gc")
async def trigger_gc_on_all_nodes(admin_user: dict = Depends(get_current_admin_user)):
    print("Admin triggered network-wide Garbage Collection.")
    
    all_files = await file_collection.find({}).to_list(None)
    active_hashes = set()
    for file_doc in all_files:
        active_hashes.add(file_doc["root_hash"])
    
    active_hashes_list = list(active_hashes)
    print(f"Found {len(active_hashes_list)} active root hashes in the database.")

    p2p_node_urls = [
        "http://p2p_node_0:8001",
        "http://p2p_node_1:8001",
        "http://p2p_node_2:8001",
    ]
    
    results = {}
    async with httpx.AsyncClient(timeout=60.0) as client:
        for url in p2p_node_urls:
            try:
                print(f"Triggering GC on node: {url}")
                response = await client.post(f"{url}/gc", json=active_hashes_list)
                response.raise_for_status()
                results[url] = response.json()
            except Exception as e:
                results[url] = {"status": "error", "detail": str(e)}
    
    print("Garbage Collection cycle complete.")
    return results

@app.get("/admin/users/{username}/files", response_model=List[FileResponseSchema])
async def get_user_files_by_admin(username: str, admin_user: dict = Depends(get_current_admin_user)):
    user = await user_collection.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    files = await file_collection.find({"owner": username}).to_list(1000)
    for file in files:
        file["_id"] = str(file["_id"])
    return files