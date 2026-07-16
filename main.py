import os
import random
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient, ASCENDING
from dotenv import load_dotenv
from passlib.context import CryptContext
import resend

# Load environment variables
load_dotenv()

app = FastAPI(title="Max Fitness Registration API")

# Enable CORS 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this to specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize MongoDB
MONGO_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URL)
db = client["max_fitness_db"]
users_collection = db["users"]
otp_collection = db["otps"]

# Create a TTL index on the "created_at" field for OTPs (Expires after 300 seconds / 5 minutes)
otp_collection.create_index("created_at", expireAfterSeconds=300)
# Ensure unique lookups are fast
otp_collection.create_index("email", unique=True)
users_collection.create_index("email", unique=True)
users_collection.create_index("username", unique=True)

# Initialize Password Hashing Context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Initialize Resend
resend.api_key = os.getenv("RESEND_API_KEY")

# Pydantic Schemas for Request Validation
class OTPRequest(BaseModel):
    email: EmailStr

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    otp: str
    password: str

# Helper functions for password security
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

@app.post("/api/send-otp")
def send_otp(payload: OTPRequest):
    email = payload.email.lower()
    
    # Optional: Check if user is already registered before sending an OTP
    if users_collection.find_one({"email": email}):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="An account with this email already exists."
        )
    
    # Generate a 6-digit random OTP
    otp = f"{random.randint(100000, 999999)}"
    
    # Save/Update the OTP in MongoDB with the current UTC timestamp
    # upsert=True replaces old OTPs if they click "resend" before expiration
    otp_collection.update_one(
        {"email": email},
        {"$set": {"otp": otp, "created_at": datetime.now(timezone.utc)}},
        upsert=True
    )
    
    try:
        # Send the OTP using Resend
        params = {
            "from": "Max Fitness <onboarding@resend.dev>",
            "to": [email],
            "subject": "Your Max Fitness Verification Code",
            "html": f"""
                <h3>Welcome to Max Fitness!</h3>
                <p>Your 6-digit verification code is: <strong style="font-size: 18px; color: #f97316;">{otp}</strong></p>
                <p>This code will expire in 5 minutes. Do not share this code with anyone.</p>
            """
        }
        resend.Emails.send(params)
        return {"message": "OTP sent successfully to your email."}
        
    except Exception as e:
        # Rollback the saved OTP if the email gateway fails
        otp_collection.delete_one({"email": email})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send email: {str(e)}"
        )

@app.post("/api/register")
def register_user(payload: RegisterRequest):
    email = payload.email.lower()
    username = payload.username.strip()

    # 1. Fetch OTP from MongoDB
    otp_record = otp_collection.find_one({"email": email})
    
    # 2. Verify if OTP exists and matches
    if not otp_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Verification code expired or not requested. Please request a new OTP."
        )
        
    if otp_record["otp"] != payload.otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Invalid verification code."
        )
        
    # 3. Check if user already exists (Double check in case they registered while waiting)
    if users_collection.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="An account with this email already exists.")
    if users_collection.find_one({"username": username}):
        raise HTTPException(status_code=400, detail="Username is already taken.")
        
    # 4. Hash the password securely and save the user
    hashed_password = hash_password(payload.password)
    
    new_user = {
        "username": username,
        "email": email,
        "password": hashed_password
    }
    
    users_collection.insert_one(new_user)
    
    # 5. Clean up the OTP document immediately after successful registration
    otp_collection.delete_one({"email": email})
    
    return {"message": "Registration successful! Welcome to Max Fitness."}

if __name__ == "__main__":
    import uvicorn
    # Points to this file name. Assuming you name this file `main.py`
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)