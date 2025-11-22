# main_full.py
import os, json, logging, urllib.parse, xml.etree.ElementTree as ET, base64, math
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

# FastAPI Imports
from fastapi import FastAPI, Depends, HTTPException, Form, File, UploadFile, Query, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from googleapiclient.errors import HttpError

# Database Imports
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, JSON, desc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# FTP
from ftplib import FTP, error_perm

# Auth & Utils
import jwt
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader

# Google Indexing
from google.oauth2 import service_account
from googleapiclient.discovery import build
import requests

# ==================== CONFIG ====================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
load_dotenv()

# DATABASE
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cms_database.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# FTP / SITE
CPANEL_HOST = os.getenv("CPANEL_HOST")
CPANEL_PORT = int(os.getenv("CPANEL_PORT", 21))
CPANEL_USER = os.getenv("CPANEL_USERNAME")
CPANEL_PASSWORD = os.getenv("CPANEL_PASSWORD")
ARTICLES_UPLOAD_PATH_FTP = os.getenv("ARTICLES_UPLOAD_PATH_FTP", "/public_html/noutati")
SITEMAP_UPLOAD_PATH_FTP = os.getenv("SITEMAP_UPLOAD_PATH_FTP", "/public_html")
ARTICLES_URL_SUBDIR = os.getenv("ARTICLES_URL_SUBDIR", "noutati")
SITE_URL = os.getenv("SITE_URL", "https://frunza-asociatii.ro")

# AUTH
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "secret_key_super_secure")
JWT_ALGORITHM = "HS256"

SCOPES = ["https://www.googleapis.com/auth/indexing"]
GENERATED_DIR = "generated"
os.makedirs(GENERATED_DIR, exist_ok=True)

# Template Env
if not os.path.exists("templates"):
    os.makedirs("templates")
env = Environment(loader=FileSystemLoader("templates"))

# ==================== DATABASE MODEL ====================
class ArticleDB(Base):
    __tablename__ = "articles"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(500), nullable=False)
    slug = Column(String(500), unique=True, index=True, nullable=False)
    category = Column(String(100), nullable=False)
    tags = Column(JSON, default=[])
    excerpt = Column(Text, nullable=True)
    cover_image = Column(Text, nullable=True)
    content = Column(Text, nullable=False)
    status = Column(String(50), default="Draft")
    author = Column(String(100), default="Frunză & Asociații")
    url = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    published_at = Column(DateTime, nullable=True)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==================== FTP FUNCTIONS ====================
def get_ftp_connection():
    ftp = FTP()
    ftp.connect(CPANEL_HOST, CPANEL_PORT, timeout=30)
    ftp.login(CPANEL_USER, CPANEL_PASSWORD)
    logger.info("FTP: Connected")
    return ftp

def upload_file_ftp(local_path: str, remote_filename: str, remote_dir: str):
    ftp = None
    try:
        ftp = get_ftp_connection()
        try:
            ftp.cwd(remote_dir)
        except error_perm:
            logger.info(f"FTP: Creating directory {remote_dir}")
            ftp.mkd(remote_dir)
            ftp.cwd(remote_dir)
        with open(local_path, "rb") as f:
            ftp.storbinary(f"STOR {remote_filename}", f)
        logger.info(f"FTP: Uploaded {remote_filename}")
        return True
    except Exception as e:
        logger.error(f"FTP Upload Error: {e}")
        return False
    finally:
        if ftp: ftp.quit()

def delete_file_ftp(remote_filename: str, remote_dir: str):
    ftp = None
    try:
        ftp = get_ftp_connection()
        ftp.cwd(remote_dir)
        ftp.delete(remote_filename)
        logger.info(f"FTP: Deleted {remote_filename}")
        return True
    except error_perm:
        logger.warning(f"FTP: File {remote_filename} not found for deletion")
        return False
    except Exception as e:
        logger.error(f"FTP Delete Error: {e}")
        return False
    finally:
        if ftp: ftp.quit()

def download_from_ftp(remote_filename: str, local_path: str, remote_dir: str):
    ftp = None
    try:
        ftp = get_ftp_connection()
        ftp.cwd(remote_dir)
        with open(local_path, "wb") as f:
            ftp.retrbinary(f"RETR {remote_filename}", f.write)
        logger.info(f"FTP: Downloaded {remote_filename}")
        return True
    except:
        logger.warning(f"FTP: Could not download {remote_filename}")
        return False
    finally:
        if ftp: ftp.quit()

# ==================== GOOGLE INDEXING ====================
def request_google_indexing(url: str, type_: str = "URL_UPDATED"):
    try:
        credentials = get_service_account_credentials()
        if not credentials:
            logger.warning("⚠️ Google Indexing API not configured - skipping")
            return False

        service = build('indexing', 'v3', credentials=credentials)

        body = {
            "url": url,
            "type": type_
        }

        response = service.urlNotifications().publish(body=body).execute()
        logger.info(f"✅ Google indexing requested successfully for: {url}")
        logger.debug(f"Google API response: {response}")

        return True
    except Exception as e:
        logger.error(f"❌ Unexpected error requesting indexing: {e}")
        return False

def get_service_account_credentials():
    """
    Build Google service account credentials from environment variables

    Returns:
        google.oauth2.service_account.Credentials or None
    """
    try:
        # Check if all required variables are present
        project_id = os.getenv("GOOGLE_PROJECT_ID")
        private_key = os.getenv("GOOGLE_PRIVATE_KEY")
        client_email = os.getenv("GOOGLE_CLIENT_EMAIL")

        if not all([project_id, private_key, client_email]):
            logger.warning("Google service account credentials not configured in environment")
            return None

        # Build credentials dictionary
        credentials_dict = {
            "type": "service_account",
            "project_id": project_id,
            "private_key_id": os.getenv("GOOGLE_PRIVATE_KEY_ID"),
            "private_key": private_key.replace('\\n', '\n'),  # Convert literal \n to actual newlines
            "client_email": client_email,
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1",
            "client_x509_cert_url": f"https://www.googleapis.com/robot/v1/metadata/x509/{client_email.replace('@', '%40')}",
            "universe_domain": "googleapis.com"
        }

        # Create credentials from dict
        credentials = service_account.Credentials.from_service_account_info(
            credentials_dict,
            scopes=SCOPES
        )

        logger.info("✅ Google service account credentials loaded from environment variables")
        return credentials

    except Exception as e:
        logger.error(f"❌ Error loading service account credentials: {e}")
        return None

# ==================== SITEMAP ====================
def update_sitemap(new_url: str, changefreq: str = "weekly", priority: str = "0.8"):
    """
    Adaugă sau actualizează un URL în sitemap.xml pe server.
    Se asigură că sitemap-ul include <loc>, <lastmod>, <changefreq> și <priority>.
    """
    local_sitemap = os.path.join(GENERATED_DIR, "sitemap.xml")
    try:
        # 1. Conectare FTP și download sitemap existent
        ftp = get_ftp_connection()
        ftp.cwd(SITEMAP_UPLOAD_PATH_FTP)
        try:
            with open(local_sitemap, "wb") as f:
                ftp.retrbinary("RETR sitemap.xml", f.write)
        except:
            # Dacă nu există sitemap, creăm unul gol
            with open(local_sitemap, "w", encoding="utf-8") as f:
                f.write('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>')

        # 2. Parse XML
        ET.register_namespace('', "http://www.sitemaps.org/schemas/sitemap/0.9")
        tree = ET.parse(local_sitemap)
        root = tree.getroot()
        ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}

        # 3. Caută URL existent
        found = False
        for url in root.findall("s:url", ns):
            loc = url.find("s:loc", ns)
            if loc is not None and loc.text == new_url:
                # Update lastmod, changefreq, priority
                lastmod = url.find("s:lastmod", ns)
                if lastmod is not None:
                    lastmod.text = datetime.utcnow().strftime("%Y-%m-%d")
                change = url.find("s:changefreq", ns)
                if change is not None:
                    change.text = changefreq
                prio = url.find("s:priority", ns)
                if prio is not None:
                    prio.text = priority
                found = True
                break

        # 4. Dacă nu există, adaugă URL nou
        if not found:
            url_elem = ET.Element("url")
            ET.SubElement(url_elem, "loc").text = new_url
            ET.SubElement(url_elem, "lastmod").text = datetime.utcnow().strftime("%Y-%m-%d")
            ET.SubElement(url_elem, "changefreq").text = changefreq
            ET.SubElement(url_elem, "priority").text = priority
            root.append(url_elem)

        # 5. Scrie și urcă sitemap înapoi pe FTP
        tree.write(local_sitemap, encoding="utf-8", xml_declaration=True)
        upload_file_ftp(local_sitemap, "sitemap.xml", SITEMAP_UPLOAD_PATH_FTP)

        # 6. Ping Google
        requests.get(f"https://www.google.com/ping?sitemap={urllib.parse.quote(SITE_URL+'/sitemap.xml')}", timeout=5)
        logger.info(f"Sitemap updated for {new_url}")
        return True
    except Exception as e:
        logger.error(f"Sitemap Update Error: {e}")
        return False
    finally:
        if ftp:
            try: ftp.quit()
            except: pass


def remove_from_sitemap(target_url: str):
    local_sitemap = os.path.join(GENERATED_DIR, "sitemap.xml")
    try:
        download_from_ftp("sitemap.xml", local_sitemap, SITEMAP_UPLOAD_PATH_FTP)
        if not os.path.exists(local_sitemap): return
        tree = ET.parse(local_sitemap)
        root = tree.getroot()
        ns = {"s":"http://www.sitemaps.org/schemas/sitemap/0.9"}
        for url in root.findall("s:url", ns):
            loc = url.find("s:loc", ns)
            if loc is not None and loc.text == target_url:
                root.remove(url)
                tree.write(local_sitemap, encoding="utf-8", xml_declaration=True)
                upload_file_ftp(local_sitemap,"sitemap.xml", SITEMAP_UPLOAD_PATH_FTP)
                logger.info(f"Sitemap: Removed {target_url}")
                break
    except Exception as e:
        logger.error(f"Sitemap Remove Error: {e}")

# ==================== PUBLISH / UNPUBLISH ====================
def generate_tags_html(tags_list):
    return "\n".join([f'<span class="tag">{t}</span>' for t in tags_list]) if tags_list else '<span class="tag">General</span>'

def publish_article(article: ArticleDB):
    try:
        filename = f"{article.slug}.html"
        local_path = os.path.join(GENERATED_DIR, filename)
        article_url = f"{SITE_URL}/{ARTICLES_URL_SUBDIR}/{article.slug}.html"
        template = env.get_template("article_template.html")
        html_content = template.render(
            ARTICLE_TITLE=article.title,
            ARTICLE_CATEGORY=article.category,
            ARTICLE_COVER_IMAGE=article.cover_image,
            ARTICLE_AUTHOR=article.author,
            ARTICLE_DATE=(article.published_at or datetime.utcnow()).strftime("%d %B %Y"),
            ARTICLE_CONTENT=article.content,
            ARTICLE_URL=article_url,
            SITE_URL=SITE_URL,
            ARTICLE_EXCERPT=article.excerpt or "",
            ARTICLE_TAGS_HTML=generate_tags_html(article.tags)
        )
        with open(local_path, "w", encoding="utf-8") as f: f.write(html_content)
        upload_file_ftp(local_path, filename, ARTICLES_UPLOAD_PATH_FTP)
        os.remove(local_path)
        update_sitemap(article_url)
        request_google_indexing(article_url, "URL_UPDATED")
        logger.info(f"Published article: {article.slug}")
    except Exception as e:
        logger.error(f"Publish Article Error: {e}")

def unpublish_article(article: ArticleDB):
    try:
        filename = f"{article.slug}.html"
        article_url = f"{SITE_URL}/{ARTICLES_URL_SUBDIR}/{article.slug}.html"
        delete_file_ftp(filename, ARTICLES_UPLOAD_PATH_FTP)
        remove_from_sitemap(article_url)
        request_google_indexing(article_url, "URL_DELETED")
        logger.info(f"Unpublished article: {article.slug}")
    except Exception as e:
        logger.error(f"Unpublish Article Error: {e}")

# ==================== FASTAPI ====================
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_jwt(token:str):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("sub") != ADMIN_USERNAME:
            raise HTTPException(status_code=401, detail="Invalid Token")
    except:
        raise HTTPException(status_code=401, detail="Invalid Token")

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username == ADMIN_USERNAME and form_data.password == ADMIN_PASSWORD:
        expire = datetime.utcnow() + timedelta(hours=2)
        token = jwt.encode({"sub": form_data.username, "exp": expire}, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Invalid credentials")

# --- CRUD ENDPOINTS ---
@app.post("/articles")
async def create_article(payload: dict = Body(...), token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    verify_jwt(token)
    slug = payload.get("slug")
    if db.query(ArticleDB).filter(ArticleDB.slug == slug).first():
        raise HTTPException(status_code=400, detail="Slug already exists")
    status = "Published" if payload.get("status","draft").lower() == "published" else "Draft"
    article_url = f"{SITE_URL}/{ARTICLES_URL_SUBDIR}/{slug}.html"
    article = ArticleDB(
        title=payload.get("title"),
        slug=slug,
        category=payload.get("category","General"),
        tags=payload.get("tags",[]),
        excerpt=payload.get("excerpt",""),
        cover_image=payload.get("coverImage"),
        content=payload.get("content"),
        status=status,
        url=article_url,
        published_at=datetime.utcnow() if status=="Published" else None
    )
    db.add(article)
    db.commit()
    db.refresh(article)
    if status=="Published": publish_article(article)
    return {"status":"success","article":article}

@app.get("/articles")
def list_articles(page:int=1, limit:int=6, search:Optional[str]=None, db:Session=Depends(get_db)):
    query = db.query(ArticleDB)
    if search: query = query.filter(ArticleDB.title.ilike(f"%{search}%"))
    query = query.order_by(desc(ArticleDB.created_at))
    total_items = query.count()
    total_pages = math.ceil(total_items / limit)
    articles = query.offset((page-1)*limit).limit(limit).all()
    return {"status":"success","data":articles,"pagination":{"current_page":page,"items_per_page":limit,"total_items":total_items,"total_pages":total_pages}}

@app.get("/articles/{article_id}")
def get_article(article_id:int, db:Session=Depends(get_db)):
    article = db.query(ArticleDB).filter(ArticleDB.id==article_id).first()
    if not article: raise HTTPException(status_code=404, detail="Article not found")
    return article

@app.get("/articles/slug/{slug}")
def get_article_by_slug(slug:str, db:Session=Depends(get_db)):
    article = db.query(ArticleDB).filter(ArticleDB.slug==slug).first()
    if not article: raise HTTPException(status_code=404, detail="Article not found")
    return article

@app.put("/articles/{article_id}")
def update_article(article_id:int, payload:dict=Body(...), token:str=Depends(oauth2_scheme), db:Session=Depends(get_db)):
    verify_jwt(token)
    article = db.query(ArticleDB).filter(ArticleDB.id==article_id).first()
    if not article: raise HTTPException(status_code=404, detail="Article not found")
    old_status, old_slug = article.status, article.slug
    new_status = "Published" if payload.get("status", article.status).lower()=="published" else "Draft"
    new_slug = payload.get("slug", article.slug)
    article.title = payload.get("title", article.title)
    article.slug = new_slug
    article.category = payload.get("category", article.category)
    article.tags = payload.get("tags", article.tags)
    article.excerpt = payload.get("excerpt", article.excerpt)
    article.cover_image = payload.get("coverImage", article.cover_image)
    article.content = payload.get("content", article.content)
    article.status = new_status
    article.updated_at = datetime.utcnow()
    article.url = f"{SITE_URL}/{ARTICLES_URL_SUBDIR}/{new_slug}.html"
    if new_status=="Published" and not article.published_at:
        article.published_at = datetime.utcnow()
    db.commit()
    db.refresh(article)
    # State machine
    if old_status=="Published" and new_status=="Draft": unpublish_article(article)
    elif old_status=="Draft" and new_status=="Published": publish_article(article)
    elif old_status=="Published" and new_status=="Published" and old_slug!=new_slug:
        unpublish_article(article)
        publish_article(article)
    return {"status":"success","article":article}

@app.delete("/articles/{article_id}")
def delete_article(article_id:int, token:str=Depends(oauth2_scheme), db:Session=Depends(get_db)):
    verify_jwt(token)
    article = db.query(ArticleDB).filter(ArticleDB.id==article_id).first()
    if not article: raise HTTPException(status_code=404, detail="Article not found")
    was_published = article.status=="Published"
    slug = article.slug
    db.delete(article)
    db.commit()
    if was_published: unpublish_article(article)
    return {"status":"success","message":"Article deleted"}

@app.get("/health")
def health(): return {"status":"ok"}

if __name__=="__main__":
    import uvicorn
    port = int(os.getenv("PORT",8000))
    uvicorn.run("main_full:app", host="0.0.0.0", port=port)
