from pydantic import BaseModel, Field
from typing import List, Optional
from bson import ObjectId
from datetime import datetime

# --- User Schemas ---
class UserRegisterSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    public_key: str
    encrypted_private_key: str

class UserLoginSchema(BaseModel):
    username: str
    password: str

class UserInDB(BaseModel):
    username: str
    hashed_password: str
    salt: str
    public_key: str
    encrypted_private_key: str
    role: str = "user" # Role defaults to "user"

class TokenSchema(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
    role: str | None = None # Role is now part of the token data

# --- File Schemas ---
class FileCreateSchema(BaseModel):
    filename: str
    root_hash: str
    encrypted_file_key: str
    erasure: dict

class FileResponseSchema(BaseModel):
    id: str = Field(..., alias="_id")
    filename: str
    root_hash: str
    owner: str
    encrypted_file_key: str
    erasure: dict
    createdAt: datetime

    class Config:
        populate_by_name = True
        json_encoders = { ObjectId: str }

class FileDeleteSchema(BaseModel):
    password: str

class FileBulkDeleteSchema(BaseModel):
    file_ids: List[str]
    password: str

# --- Sharing & Details Schemas ---
class ShareRequestSchema(BaseModel):
    share_with_username: str
    encrypted_file_key_for_recipient: str

class SharedFileResponseSchema(BaseModel):
    file_id: str
    filename: str
    root_hash: str
    owner: str
    encrypted_file_key: str

class LogEntrySchema(BaseModel):
    timestamp: datetime
    action: str
    username: str
    status: str
    details: dict

class SharingInfoSchema(BaseModel):
    shared_with_user: str
    permission: str

class FileDetailsResponseSchema(BaseModel):
    id: str = Field(..., alias="_id")
    filename: str
    root_hash: str
    owner: str
    erasure: dict
    sharing_info: List[SharingInfoSchema]
    activity_log: List[LogEntrySchema]

    class Config:
        populate_by_name = True
        json_encoders = { ObjectId: str }

class UserPublicKeysRequest(BaseModel):
    usernames: List[str]

class UserPublicKeyResponse(BaseModel):
    username: str
    public_key: str

class FileBulkUnshareSchema(BaseModel):
    file_ids: List[str]
    username: str


