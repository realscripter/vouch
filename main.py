from fastapi import FastAPI, Header, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict
import time
import uuid
import httpx
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Add CORS middleware to allow all origins, methods, and headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

@app.middleware("http")
async def add_client_ip(request: Request, call_next):
    client_ip = request.client.host
    request.state.client_ip = client_ip
    response = await call_next(request)
    return response

# In-memory storage
vouches = []  # Each vouch: {id, ip, username, message, type, timestamp, session_id, expires}
sessions = {}  # session_id: {vouch_id, expires, ip}

RATE_LIMIT = 3  # max vouches per hour per ip/username
SESSION_DURATION = 1800  # 30 min in seconds

LLM7_API_URL = "https://api.llm7.io/v1/chat/completions"
LLM7_API_KEY = "unused"
LLM7_MODEL = "gpt-4.1-nano-2025-04-14"

RULES = """
Minecraft Server Rules
• No Hacked Clients
• No Movement Mods
• No Inventory Mod
• No Health Indicators
• No Radar
• No Freecam
• No Auto or Easy Place
• No Macros or Scripts
• No Auto Clicker
• No Mouse Tweaks/ Scrollers
• No Crafting Modifications
• No Abusing Bugs
• No Attempted Duplicating
• No Duplicating Items
• No IRL Trading
• No Invite Rewards
• No External Gambling
• No Discord Boost Rewards
• No Cross-Server Trading
• No Staff Impersonation
• No Using More Than 5 Accounts
• No Finding or Using the Seed
• No Spamming Voice Chat
• Report all Bugs, Glitches, and Cheaters

Chat Rules
• No Spamming or getting others to spam
• No Harassing
• No Advertising or Promotion (except for the <#786066953105702932> channel)
• No Discrimination or Hate Speech
• No Death Threats
• No Sharing Others Private Information
• No Pretending to be Staff Members
• No Ban Evasion
• No Dumb Forum Posts
• Use common sense, so don't do things that will get you banned just because the specific rule isn't up here
"""

class VouchRequest(BaseModel):
    message: str
    type: str  # "scam vouch" or "vouch"

class EditVouchRequest(BaseModel):
    sessionid: str
    ip: str
    new_message: str

class DeleteVouchRequest(BaseModel):
    sessionid: str
    ip: str

class CheckVouchTimeRequest(BaseModel):
    sessionid: str
    ip: str

@app.get("/ping")
def ping():
    return {"pong": True}

async def check_message_llm7(message: str) -> bool:
    prompt = f"Check if this message clearly violates any rules or contains swearing. If it is mostly fine, allow it. Reply 'OK' if allowed, or 'BAD: <short reason>' if not.\nRules:\n{RULES}\nMessage: {message}"
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            LLM7_API_URL,
            headers={"Authorization": f"Bearer {LLM7_API_KEY}"},
            json={
                "model": LLM7_MODEL,
                "messages": [{"role": "user", "content": prompt}]
            },
            timeout=5.0
        )
        result = resp.json()
        content = result["choices"][0]["message"]["content"].strip()
        if content.upper() == "OK":
            return True, None
        if content.upper().startswith("BAD"):
            reason = content[4:].strip() if len(content) > 4 else "Message violates rules"
            return False, reason
        return False, "Message violates rules"

# Update /vouch endpoint to support usernames with a dot (.) for Bedrock users
@app.post("/vouch")
async def vouch(request: Request, vouch: VouchRequest, username: str = Header(...)):
    ip = request.state.client_ip
    now = time.time()
    # Check if the same IP has already vouched for the same username
    existing_vouch = next((v for v in vouches if v["ip"] == ip and v["username"].lower() == username.lower()), None)
    if existing_vouch:
        return JSONResponse({"success": False, "error": "You have already vouched for this user from this IP"}, status_code=400)
    # LLM7 check
    valid, reason = await check_message_llm7(vouch.message)
    if not valid:
        return JSONResponse({"success": False, "error": reason or "Message violates rules"}, status_code=400)
    # Rate limit
    recent = [v for v in vouches if v["ip"] == ip and now - v["timestamp"] < 3600]
    if len(recent) >= RATE_LIMIT:
        return JSONResponse({"success": False, "error": "Rate limited"}, status_code=429)
    if len(vouch.message) > 250:
        return JSONResponse({"success": False, "error": "Message too long"}, status_code=400)
    if vouch.type not in ["scam vouch", "vouch"]:
        return JSONResponse({"success": False, "error": "Invalid type"}, status_code=400)
    vouch_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    expires = now + SESSION_DURATION
    vouch_obj = {
        "id": vouch_id,
        "ip": ip,
        "username": username,
        "message": vouch.message,
        "type": vouch.type,
        "timestamp": now,
        "session_id": session_id,
        "expires": expires
    }
    vouches.append(vouch_obj)
    sessions[session_id] = {"vouch_id": vouch_id, "expires": expires, "ip": ip}
    return {"success": True, "session_id": session_id}

# Update /checkvouch endpoint to use automatic IP
@app.get("/checkvouch")
async def checkvouch(request: Request, username: str = Header(...)):
    ip = request.state.client_ip
    user_vouches = [v for v in vouches if v["ip"] == ip and v["username"] == username]
    total = len([v for v in user_vouches if v["type"] == "vouch"])
    scam = len([v for v in user_vouches if v["type"] == "scam vouch"])
    recent = [v for v in user_vouches if time.time() - v["timestamp"] < 3600]
    recent_vouches = [v for v in recent if v["type"] == "vouch"]
    recent_scam = [v for v in recent if v["type"] == "scam vouch"]
    return {
        "total_vouches": total,
        "total_scam_vouches": scam,
        "recent_vouches": [{"message": v["message"]} for v in recent_vouches],
        "recent_scam_vouches": [{"message": v["message"]} for v in recent_scam]
    }

@app.post("/deletevouch")
async def deletevouch(req: DeleteVouchRequest):
    session = sessions.get(req.sessionid)
    if not session:
        return {"success": False, "error": "invalid"}
    if session["ip"] != req.ip:
        return {"success": False, "error": "no permission"}
    if time.time() > session["expires"]:
        return {"success": False, "error": "outoftime"}
    vouch_id = session["vouch_id"]
    for i, v in enumerate(vouches):
        if v["id"] == vouch_id:
            vouches.pop(i)
            sessions.pop(req.sessionid)
            return {"success": True}
    return {"success": False, "error": "invalid"}

@app.post("/editvouch")
async def editvouch(req: EditVouchRequest):
    session = sessions.get(req.sessionid)
    if not session:
        return {"success": False, "error": "invalid"}
    if session["ip"] != req.ip:
        return {"success": False, "error": "no permission"}
    if time.time() > session["expires"]:
        return {"success": False, "error": "outoftime"}
    if len(req.new_message) > 250:
        return {"success": False, "error": "Message too long"}
    valid, reason = await check_message_llm7(req.new_message)
    if not valid:
        return {"success": False, "error": reason or "Message violates rules"}
    vouch_id = session["vouch_id"]
    for v in vouches:
        if v["id"] == vouch_id:
            v["message"] = req.new_message
            return {"success": True}
    return {"success": False, "error": "invalid"}

@app.post("/checkvouchtime")
async def checkvouchtime(req: CheckVouchTimeRequest):
    session = sessions.get(req.sessionid)
    if not session or session["ip"] != req.ip:
        return {"success": False, "error": "invalid"}
    left = int(session["expires"] - time.time())
    if left < 0:
        return {"success": False, "error": "outoftime"}
    return {"success": True, "seconds_left": left}

@app.get("/mostvouches")
async def mostvouches():
    stats = {}
    for v in vouches:
        u = v["username"]
        if u not in stats:
            stats[u] = {"vouch": 0, "scam": 0}
        if v["type"] == "vouch":
            stats[u]["vouch"] += 1
        elif v["type"] == "scam vouch":
            stats[u]["scam"] += 1
    top = sorted(stats.items(), key=lambda x: (x[1]["vouch"] + x[1]["scam"]), reverse=True)[:10]
    return [{"username": u, "vouch": s["vouch"], "scam": s["scam"]} for u, s in top]
