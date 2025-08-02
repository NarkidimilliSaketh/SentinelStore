import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URL = os.getenv("MONGO_URL")

client = AsyncIOMotorClient(MONGO_URL)
db = client.sentinelstore

# Create collections for users, their files, and sharing permissions
user_collection = db.get_collection("users")
file_collection = db.get_collection("files")
access_control_collection = db.get_collection("access_control")
logs_collection = db.get_collection("logs")