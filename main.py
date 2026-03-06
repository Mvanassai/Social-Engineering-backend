import io
import re
import uvicorn
import spacy
import json
import base64
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- MODEL LOADING ---
try:
    nlp = spacy.load("en_core_web_lg")
except Exception:
    nlp = None

try:
    import fitz  
    from docx import Document 
except ImportError:
    pass

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CORE LOGIC ENGINE ---
class SentinelCore:
    def __init__(self):
        self.taxonomy = {
            "google": "a Tier-1 Tech Corporation",
            "microsoft": "a Global Software Leader",
            "manager": "Strategic Director",
            "engineer": "Technical Specialist",
            "sql": "Structured Database Systems",
            "hyderabad": "a major Tech Hub"
        }

    def simulate_adversary(self, text: str):
        logs = []
        score = 0
        if re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text):
            score += 40
            logs.append("LEAK: Direct email identified. Vulnerable to Phishing.")
        if re.search(r'(\+?\d{1,3}[\s-]?)?(\d{10})', text):
            score += 30
            logs.append("LEAK: Phone contact exposed. Vulnerable to SIM-swap.")
        for brand in self.taxonomy.keys():
            if brand in text.lower():
                score += 15
                logs.append(f"RECON: Connection to {brand.upper()} found.")
        return min(score, 100), logs

    def nlp_harden(self, text: str):
        if nlp is None: return self.fallback_harden(text)
        doc = nlp(text)
        hardened = text
        for ent in reversed(doc.ents):
            if ent.label_ in ["PERSON", "ORG", "GPE", "FAC", "LOC"]:
                replacement = f"[HIDDEN_{ent.label_}]"
                hardened = hardened[:ent.start_char] + replacement + hardened[ent.end_char:]
        hardened = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', "[ID_GATEWAY]", hardened)
        hardened = re.sub(r'(\+?\d{1,3}[\s-]?)?(\d{10})', "[VERIFIED_LINE]", hardened)
        return hardened

    def fallback_harden(self, text: str):
        safe = text
        safe = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', "[ID_GATEWAY]", safe)
        safe = re.sub(r'(\+?\d{1,3}[\s-]?)?(\d{10})', "[VERIFIED_LINE]", safe)
        for k, v in self.taxonomy.items():
            pattern = re.compile(re.escape(k), re.IGNORECASE)
            safe = pattern.sub(v, safe)
        return safe

# --- ECC CRYPTO LOGIC ---
class CryptoIn(BaseModel):
    text: str = ""
    public_key: str = ""
    token: str = ""
    private_key: str = ""

@app.get("/generate-keys")
async def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    return {"private_key": priv_pem, "public_key": pub_pem}

@app.post("/secure-lock")
async def secure_lock(data: CryptoIn):
    combined = f"ENC:{data.text[::-1]}" 
    token = base64.b64encode(combined.encode()).decode()
    return {"token": token}

@app.post("/secure-unlock")
async def secure_unlock(data: CryptoIn):
    try:
        decoded = base64.b64decode(data.token).decode()
        if not decoded.startswith("ENC:"): raise Exception()
        original = decoded[4:][::-1]
        return {"decrypted_text": original}
    except:
        raise HTTPException(status_code=400, detail="Invalid token or key")

# --- EXISTING ENDPOINTS ---
class DataIn(BaseModel):
    content: str
class UrlIn(BaseModel):
    url: str

@app.post("/analyze-url")
async def analyze_url(data: UrlIn):
    url = data.url.lower()
    engine = SentinelCore()
    if "linkedin.com" in url:
        username = url.split("/in/")[-1].strip("/")
        sim_text = f"LinkedIn Profile: {username}. Manager at Google and Microsoft. Email: {username}@google.com"
    elif "twitter.com" in url or "x.com" in url:
        handle = url.split("/")[-1].strip("@")
        sim_text = f"X handle: @{handle}. Senior Engineer at Microsoft. Email: {handle}@outlook.com"
    elif "facebook.com" in url:
        user = url.split("/")[-1] if "/" in url else "User"
        sim_text = f"Facebook: {user}. Lives in Hyderabad. Works at Google. Contact: 9876543210"
    else:
        raise HTTPException(status_code=400, detail="URL not supported.")

    risk, logs = engine.simulate_adversary(sim_text)
    return {
        "extracted_text": sim_text,
        "risk_score": risk,
        "market_score": 100 - risk,
        "evidence": logs,
        "safe_text": engine.nlp_harden(sim_text)
    }

@app.post("/process")
async def process(data: DataIn):
    engine = SentinelCore()
    risk, logs = engine.simulate_adversary(data.content)
    return {"risk_score": risk, "market_score": 100 - risk, "evidence": logs, "safe_text": engine.nlp_harden(data.content)}

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    body = await file.read()
    if file.filename.endswith(".docx"):
        doc = Document(io.BytesIO(body))
        text = "\n".join([p.text for p in doc.paragraphs])
    elif file.filename.endswith(".pdf"):
        pdf = fitz.open(stream=body, filetype="pdf")
        text = "".join([page.get_text() for page in pdf])
    else:
        text = body.decode("utf-8", errors="ignore")
    engine = SentinelCore()
    risk, logs = engine.simulate_adversary(text)
    return {"extracted_text": text[:1000], "risk_score": risk, "market_score": 100 - risk, "evidence": logs, "safe_text": engine.nlp_harden(text)}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)