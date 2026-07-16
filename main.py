import os
import random
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
from dotenv import load_dotenv
import resend

# Load environment variables
load_dotenv()

app = FastAPI(title="Max Fitness Registration API")

# Enable CORS so your frontend can communicate with the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize MongoDB
MONGO_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URL)
db = client["max_fitness_db"]
users_collection = db["users"]

# Initialize Resend
resend.api_key = os.getenv("RESEND_API_KEY")

# Temporary in-memory database for OTPs (In production, use Redis or a DB collection with TTL)
otp_store = {}

# Pydantic Schemas for Request Validation
class OTPRequest(BaseModel):
    email: EmailStr

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    otp: str
    password: str

@app.post("/api/send-otp")
def send_otp(payload: OTPRequest):
    email = payload.email
    
    # Generate a 6-digit random OTP
    otp = f"{random.randint(100000, 999999)}"
    
    # Save to our temporary store
    otp_store[email] = otp
    
    try:
        # Send the OTP using Resend
        # Note: 'onboarding@resend.dev' works for free/test accounts to your own registered email.
        params = {
            "from": "Max Fitness <onboarding@resend.dev>",
            "to": [email],
            "subject": "Your Max Fitness Verification Code",
            "html": f"""
                <h3>Welcome to Max Fitness!</h3>
                <p>Your 6-digit verification code is: <strong style="font-size: 18px; color: #f97316;">{otp}</strong></p>
                <p>This code will expire shortly. Do not share this code with anyone.</p>
            """
        }
        resend.Emails.send(params)
        return {"message": "OTP sent successfully to your email."}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send email: {str(e)}"
        )

@app.post("/api/register")
def register_user(payload: RegisterRequest):
    # 1. Verify if OTP exists for this email
    if payload.email not in otp_store:
        raise HTTPException(status_code=400, detail="Please request an OTP first.")
        
    # 2. Verify if the provided OTP matches
    if otp_store[payload.email] != payload.otp:
        raise HTTPException(status_code=400, detail="Invalid verification code.")
        
    # 3. Check if user already exists in MongoDB
    if users_collection.find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="An account with this email already exists.")
    if users_collection.find_one({"username": payload.username}):
        raise HTTPException(status_code=400, detail="Username is already taken.")
        
    # 4. Save user to MongoDB (In production, make sure to hash the password!)
    new_user = {
        "username": payload.username,
        "email": payload.email,
        "password": payload.password # Ideal production setup should use a hashing library like passlib
    }
    
    users_collection.insert_one(new_user)
    
    # Clear the OTP out of memory after successful registration
    del otp_store[payload.email]
    
    return {"message": "Registration successful! Welcome to Max Fitness."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main.py:app", host="127.0.0.1", port=8000, reload=True)