import os
from pymongo import MongoClient

mongo_url = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
client = MongoClient(mongo_url)
db = client["myapp"]
users = db["users"]


result = users.delete_many({})
print(f"Deleted {result.deleted_count} users.")

