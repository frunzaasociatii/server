from fastapi import FastAPI, Depends, HTTPException, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import jwt
import os
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader
import paramiko
import xml.etree.ElementTree as ET
import requests

load_dotenv()

# ==================== CONFIG ====================
# SFTP / cPanel
CPANEL_HOST = os.getenv("CPANEL_HOST")
CPANEL_PORT = int(os.getenv("CPANEL_PORT", 22))
CPANEL_USER = os.getenv("CPANEL_USERNAME")
CPANEL_PASSWORD = os.getenv("CPANEL_PASSWORD")
UPLOAD_PATH = os.getenv("UPLOAD_PATH")
SITE_URL = os.getenv("SITE_URL")

# Admin / JWT
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", 60))

# Frontend / API
GENERATED_DIR = "generated"
os.makedirs(GENERATED_DIR, exist_ok=True)
SITEMAP_FILE = os.path.join(GENERATED_DIR, "sitemap.xml")

# Templates
env = Environment(loader=FileSystemLoader("templates"))

# ==================== APP ====================
app = FastAPI()

# ==================== CORS ====================
origins = [
    "http://localhost:3000",          # frontend local
    "https://frunza-asociatii.ro",   # live frontend
    "https://www.frunza-asociatii.ro"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ==================== JWT FUNCTIONS ====================
def create_jwt_token(username: str):
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXP_MINUTES)
    payload = {"sub": username, "exp": expire}
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

def verify_jwt_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username != ADMIN_USERNAME:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ==================== AUTH ENDPOINT ====================
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username == ADMIN_USERNAME and form_data.password == ADMIN_PASSWORD:
        token = create_jwt_token(form_data.username)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Incorrect username or password")

# ==================== SFTP UPLOAD ====================
def upload_to_cpanel(local_path, remote_filename):
    transport = paramiko.Transport((CPANEL_HOST, CPANEL_PORT))
    transport.connect(username=CPANEL_USER, password=CPANEL_PASSWORD)
    sftp = paramiko.SFTPClient.from_transport(transport)
    sftp.put(local_path, f"{UPLOAD_PATH}/{remote_filename}")
    sftp.close()
    transport.close()

# ==================== SITEMAP ====================
def update_sitemap(new_url: str):
    if os.path.exists(SITEMAP_FILE):
        tree = ET.parse(SITEMAP_FILE)
        root = tree.getroot()
    else:
        root = ET.Element("urlset", xmlns="http://www.sitemaps.org/schemas/sitemap/0.9")

    url_elem = ET.Element("url")
    ET.SubElement(url_elem, "loc").text = new_url
    ET.SubElement(url_elem, "lastmod").text = datetime.utcnow().strftime("%Y-%m-%d")
    ET.SubElement(url_elem, "changefreq").text = "weekly"
    ET.SubElement(url_elem, "priority").text = "0.8"

    root.append(url_elem)
    tree = ET.ElementTree(root)
    tree.write(SITEMAP_FILE, encoding="utf-8", xml_declaration=True)

def ping_google(sitemap_url: str):
    try:
        requests.get(f"http://www.google.com/ping?sitemap={sitemap_url}")
    except Exception as e:
        print("Eroare la ping Google:", e)

# ==================== CREATE ARTICLE ====================
@app.post("/create-article/")
async def create_article(
    title: str = Form(...),
    slug: str = Form(...),
    category: str = Form(...),
    tags: str = Form(...),
    extras: str = Form(None),
    cover_image: str = Form(None),
    content: str = Form(...),
    token: str = Depends(oauth2_scheme)
):
    verify_jwt_token(token)

    template = env.get_template("article_template.html")
    html_content = template.render(
        title=title,
        slug=slug,
        category=category,
        tags=tags,
        extras=extras,
        cover_image=cover_image,
        content=content
    )

    filename = slug.lower().replace(" ", "-") + ".html"
    local_path = os.path.join(GENERATED_DIR, filename)
    with open(local_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    upload_to_cpanel(local_path, filename)

    file_url = f"{SITE_URL}/noutati/{filename}"
    update_sitemap(file_url)
    upload_to_cpanel(SITEMAP_FILE, "sitemap.xml")

    ping_google(f"{SITE_URL}/sitemap.xml")

    os.remove(local_path)

    return {"status": "ok", "file": filename, "url": file_url}

# ==================== RUN UVICORN ====================
if __name__ == "__main__":
    import uvicorn
    PORT = int(os.getenv("PORT", 8000))  # Railway va seta PORT automat
    uvicorn.run("main:app", host="0.0.0.0", port=PORT)
