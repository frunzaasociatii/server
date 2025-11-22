import os
import json
import logging
import urllib.parse
import xml.etree.ElementTree as ET
import base64
import math
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

# FastAPI Imports
from fastapi import FastAPI, Depends, HTTPException, Form, File, UploadFile, Query, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

# Database Imports
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, JSON, desc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# FTP Import
from ftplib import FTP, error_perm

# Auth & Utils
import jwt
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader

# Google API
from google.oauth2 import service_account
from googleapiclient.discovery import build
import requests

# ==================== 1. SETUP & CONFIGURARE ====================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# --- DATABASE ---
# Folosește SQLite local dacă nu e setat un URL de Postgres
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cms_database.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- FTP & SITE ---
CPANEL_HOST = os.getenv("CPANEL_HOST")
CPANEL_PORT = int(os.getenv("CPANEL_PORT", 21))
CPANEL_USER = os.getenv("CPANEL_USERNAME")
CPANEL_PASSWORD = os.getenv("CPANEL_PASSWORD")

# Căi FTP (fără slash la final)
# Exemplu: /public_html/noutati
ARTICLES_UPLOAD_PATH_FTP = os.getenv("ARTICLES_UPLOAD_PATH_FTP", "/public_html/noutati")
# Exemplu: /public_html (unde stă sitemap.xml)
SITEMAP_UPLOAD_PATH_FTP = os.getenv("SITEMAP_UPLOAD_PATH_FTP", "/public_html")

ARTICLES_URL_SUBDIR = os.getenv("ARTICLES_URL_SUBDIR", "noutati")
SITE_URL = os.getenv("SITE_URL", "https://frunza-asociatii.ro")

# --- AUTH ---
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "secret_key_super_secure")
JWT_ALGORITHM = "HS256"

SCOPES = ["https://www.googleapis.com/auth/indexing"]
GENERATED_DIR = "generated"
os.makedirs(GENERATED_DIR, exist_ok=True)

# Template Environment
if not os.path.exists("templates"):
    os.makedirs("templates")
env = Environment(loader=FileSystemLoader("templates"))


# ==================== 2. MODEL BAZĂ DE DATE ====================
class ArticleDB(Base):
    __tablename__ = "articles"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(500), nullable=False)
    slug = Column(String(500), unique=True, index=True, nullable=False)
    category = Column(String(100), nullable=False)

    # Tag-urile salvate ca listă JSON ["tag1", "tag2"]
    tags = Column(JSON, default=[])

    excerpt = Column(Text, nullable=True)
    cover_image = Column(Text, nullable=True)  # Base64 string
    content = Column(Text, nullable=False)  # HTML Content din Editor

    # 'Published' sau 'Draft' (Case sensitive in DB, normalizam in cod)
    status = Column(String(50), default="Draft")

    author = Column(String(100), default="Frunză & Asociații")
    url = Column(String(500), nullable=True)  # URL-ul public complet

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    published_at = Column(DateTime, nullable=True)


# Creare tabele la pornire
Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==================== 3. FTP UTILS ====================

def get_ftp_connection():
    ftp = FTP()
    ftp.connect(CPANEL_HOST, CPANEL_PORT, timeout=30)
    ftp.login(CPANEL_USER, CPANEL_PASSWORD)
    return ftp


def upload_file_ftp(local_path: str, remote_filename: str, remote_dir: str):
    """Urcă un fișier pe FTP. Creează folderul dacă nu există."""
    ftp = None
    try:
        ftp = get_ftp_connection()
        try:
            ftp.cwd(remote_dir)
        except error_perm:
            try:
                ftp.mkd(remote_dir)
                ftp.cwd(remote_dir)
            except:
                logger.error(f"FTP: Could not access or create dir {remote_dir}")
                return False

        with open(local_path, 'rb') as f:
            ftp.storbinary(f'STOR {remote_filename}', f)
        logger.info(f"FTP: Uploaded {remote_filename}")
        return True
    except Exception as e:
        logger.error(f"FTP Upload Error: {e}")
        return False
    finally:
        if ftp:
            try:
                ftp.quit()
            except:
                pass


def delete_file_ftp(remote_filename: str, remote_dir: str):
    """Șterge un fișier de pe FTP"""
    ftp = None
    try:
        ftp = get_ftp_connection()
        ftp.cwd(remote_dir)
        ftp.delete(remote_filename)
        logger.info(f"FTP: Deleted {remote_filename}")
        return True
    except error_perm:
        logger.warning(f"FTP: File {remote_filename} not found to delete.")
        return False
    except Exception as e:
        logger.error(f"FTP Delete Error: {e}")
        return False
    finally:
        if ftp:
            try:
                ftp.quit()
            except:
                pass


def download_from_cpanel(remote_filename: str, local_path: str, remote_dir: str):
    """Descarcă un fișier de pe FTP (pt sitemap)"""
    ftp = None
    try:
        ftp = get_ftp_connection()
        ftp.cwd(remote_dir)
        with open(local_path, 'wb') as f:
            ftp.retrbinary(f'RETR {remote_filename}', f.write)
        return True
    except:
        return False
    finally:
        if ftp:
            try:
                ftp.quit()
            except:
                pass


# ==================== 4. GOOGLE & SEO UTILS ====================

def request_google_indexing(url: str, type="URL_UPDATED"):
    """
    Trimite ping la Google Indexing API.
    type: URL_UPDATED sau URL_DELETED
    """
    try:
        if not os.getenv("GOOGLE_CLIENT_EMAIL"):
            logger.warning("Google Credentials missing. Skipping indexing.")
            return False

        creds_dict = {
            "type": "service_account",
            "project_id": os.getenv("GOOGLE_PROJECT_ID"),
            "private_key_id": os.getenv("GOOGLE_PRIVATE_KEY_ID"),
            "private_key": os.getenv("GOOGLE_PRIVATE_KEY", "").replace('\\n', '\n'),
            "client_email": os.getenv("GOOGLE_CLIENT_EMAIL"),
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
        creds = service_account.Credentials.from_service_account_info(creds_dict, scopes=SCOPES)
        service = build('indexing', 'v3', credentials=creds)
        service.urlNotifications().publish(body={"url": url, "type": type}).execute()
        logger.info(f"Google Indexing Ping sent for {url} as {type}")
        return True
    except Exception as e:
        logger.error(f"Google Indexing Error: {e}")
        return False


def update_sitemap(new_url: str):
    """Adaugă sau actualizează un URL în sitemap.xml pe server"""
    LOCAL_SITEMAP = os.path.join(GENERATED_DIR, "sitemap.xml")
    try:
        # 1. Descarcă sitemap existent
        download_from_cpanel("sitemap.xml", LOCAL_SITEMAP, SITEMAP_UPLOAD_PATH_FTP)

        root = None
        # 2. Parsează XML
        if os.path.exists(LOCAL_SITEMAP):
            try:
                ET.register_namespace('', "http://www.sitemaps.org/schemas/sitemap/0.9")
                tree = ET.parse(LOCAL_SITEMAP)
                root = tree.getroot()
            except:
                pass

        # 3. Creează nou dacă nu există
        if root is None:
            root = ET.Element("urlset", xmlns="http://www.sitemaps.org/schemas/sitemap/0.9")

        # 4. Caută URL-ul
        found = False
        # Namespace necesar pentru findall
        ns = {'s': 'http://www.sitemaps.org/schemas/sitemap/0.9'}

        for url in root.findall("s:url", ns):
            loc = url.find("s:loc", ns)
            if loc is not None and loc.text == new_url:
                found = True
                lastmod = url.find("s:lastmod", ns)
                if lastmod is not None: lastmod.text = datetime.utcnow().strftime("%Y-%m-%d")
                break

        # 5. Adaugă dacă nu există
        if not found:
            url_elem = ET.Element("url")
            loc = ET.SubElement(url_elem, "loc")
            loc.text = new_url
            lastmod = ET.SubElement(url_elem, "lastmod")
            lastmod.text = datetime.utcnow().strftime("%Y-%m-%d")
            root.append(url_elem)

        # 6. Salvează și Urcă înapoi
        tree = ET.ElementTree(root)
        ET.register_namespace('', "http://www.sitemaps.org/schemas/sitemap/0.9")
        tree.write(LOCAL_SITEMAP, encoding="utf-8", xml_declaration=True)
        upload_file_ftp(LOCAL_SITEMAP, "sitemap.xml", SITEMAP_UPLOAD_PATH_FTP)

        # 7. Ping Google Sitemap (diferit de Indexing API)
        requests.get(f"https://www.google.com/ping?sitemap={urllib.parse.quote(SITE_URL + '/sitemap.xml')}", timeout=5)
        return True
    except Exception as e:
        logger.error(f"Sitemap Update Error: {e}")
        return False


def remove_from_sitemap(target_url: str):
    """Șterge un URL din sitemap.xml"""
    LOCAL_SITEMAP = os.path.join(GENERATED_DIR, "sitemap.xml")
    try:
        download_from_cpanel("sitemap.xml", LOCAL_SITEMAP, SITEMAP_UPLOAD_PATH_FTP)
        if not os.path.exists(LOCAL_SITEMAP): return False

        ET.register_namespace('', "http://www.sitemaps.org/schemas/sitemap/0.9")
        tree = ET.parse(LOCAL_SITEMAP)
        root = tree.getroot()
        ns = {'s': 'http://www.sitemaps.org/schemas/sitemap/0.9'}

        # Găsește și șterge
        urls = root.findall("s:url", ns)
        for url in urls:
            loc = url.find("s:loc", ns)
            if loc is not None and loc.text == target_url:
                root.remove(url)
                tree.write(LOCAL_SITEMAP, encoding="utf-8", xml_declaration=True)
                upload_file_ftp(LOCAL_SITEMAP, "sitemap.xml", SITEMAP_UPLOAD_PATH_FTP)
                logger.info(f"Removed {target_url} from sitemap")
                return True
        return False
    except Exception as e:
        logger.error(f"Sitemap Remove Error: {e}")
        return False


def generate_tags_html(tags_list):
    html = []
    for tag in tags_list:
        html.append(f'<span class="tag">{tag}</span>')
    return "\n".join(html) if html else '<span class="tag">General</span>'


# ==================== 5. PIPELINES (CORE LOGIC) ====================

def publish_content_pipeline(article: ArticleDB):
    """
    Această funcție se execută când un articol devine sau rămâne 'Published'.
    1. Generează HTML.
    2. Urcă pe FTP.
    3. Actualizează Sitemap.
    4. Notifică Google.
    """
    try:
        tags_list = article.tags if article.tags else []
        # Asigurare compatibilitate tipuri
        if isinstance(tags_list, str): tags_list = tags_list.split(",")

        article_url = f"{SITE_URL}/{ARTICLES_URL_SUBDIR}/{article.slug}.html"

        # 1. Render Template
        try:
            template = env.get_template("article_template.html")
        except:
            logger.error("Template 'article_template.html' not found!")
            return False

        html_content = template.render(
            ARTICLE_TITLE=article.title,
            ARTICLE_CATEGORY=article.category,
            ARTICLE_COVER_IMAGE=article.cover_image,
            ARTICLE_AUTHOR=article.author,
            ARTICLE_DATE=(article.published_at or datetime.utcnow()).strftime("%d %B %Y"),
            ARTICLE_CONTENT=article.content,
            ARTICLE_TAGS_HTML=generate_tags_html(tags_list),
            ARTICLE_URL=article_url,
            SITE_URL=SITE_URL,
            ARTICLE_EXCERPT=article.excerpt or ""
        )

        # 2. Upload FTP
        filename = f"{article.slug}.html"
        local_path = os.path.join(GENERATED_DIR, filename)
        with open(local_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        success = upload_file_ftp(local_path, filename, ARTICLES_UPLOAD_PATH_FTP)

        if os.path.exists(local_path): os.remove(local_path)

        if not success:
            logger.error("Failed to upload file to FTP")
            return False

        # 3. SEO Operations
        update_sitemap(article_url)
        request_google_indexing(article_url, "URL_UPDATED")

        return True
    except Exception as e:
        logger.error(f"Publish Pipeline Failed: {e}")
        return False


def unpublish_content_pipeline(slug: str):
    """
    Această funcție se execută când un articol devine 'Draft' sau este șters.
    1. Șterge fișierul de pe FTP.
    2. Șterge din Sitemap.
    3. Notifică Google (URL_DELETED).
    """
    try:
        filename = f"{slug}.html"
        article_url = f"{SITE_URL}/{ARTICLES_URL_SUBDIR}/{slug}.html"

        # 1. FTP Delete
        delete_file_ftp(filename, ARTICLES_UPLOAD_PATH_FTP)

        # 2. Sitemap Remove
        remove_from_sitemap(article_url)

        # 3. Google Ping
        request_google_indexing(article_url, "URL_DELETED")

        return True
    except Exception as e:
        logger.error(f"Unpublish Pipeline Failed: {e}")
        return False


# ==================== 6. FASTAPI ENDPOINTS ====================

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_jwt_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("sub") != ADMIN_USERNAME: raise HTTPException(status_code=401)
    except:
        raise HTTPException(status_code=401, detail="Invalid Token")


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username == ADMIN_USERNAME and form_data.password == ADMIN_PASSWORD:
        expire = datetime.utcnow() + timedelta(minutes=120)
        token = jwt.encode({"sub": form_data.username, "exp": expire}, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Invalid credentials")


# --- CREATE ARTICLE ---
@app.post("/articles")
async def create_article(
        payload: dict = Body(...),
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    verify_jwt_token(token)

    slug = payload.get('slug')
    # Validare slug unic
    if db.query(ArticleDB).filter(ArticleDB.slug == slug).first():
        raise HTTPException(status_code=400, detail="Slug already exists")

    # Normalizare status (Published/Draft)
    raw_status = payload.get('status', 'draft').lower()
    status = "Published" if raw_status == "published" else "Draft"

    article_url = f"{SITE_URL}/{ARTICLES_URL_SUBDIR}/{slug}.html"

    new_article = ArticleDB(
        title=payload.get('title'),
        slug=slug,
        category=payload.get('category'),
        tags=payload.get('tags', []),
        excerpt=payload.get('excerpt', ''),
        cover_image=payload.get('coverImage'),  # Base64
        content=payload.get('content'),
        status=status,
        url=article_url,
        published_at=datetime.utcnow() if status == "Published" else None
    )

    db.add(new_article)
    db.commit()
    db.refresh(new_article)

    # STATE MACHINE: Doar dacă e Published se generează fișiere
    if status == "Published":
        publish_content_pipeline(new_article)

    return {"status": "success", "article": new_article}


# --- READ ARTICLES (PAGINATED) ---
@app.get("/articles")
def get_articles(
        page: int = 1,
        limit: int = 6,
        search: str = None,
        db: Session = Depends(get_db)
):
    query = db.query(ArticleDB)

    if search:
        query = query.filter(ArticleDB.title.ilike(f"%{search}%"))

    query = query.order_by(desc(ArticleDB.created_at))

    total_items = query.count()
    total_pages = math.ceil(total_items / limit) if limit > 0 else 1
    offset = (page - 1) * limit

    articles = query.offset(offset).limit(limit).all()

    return {
        "status": "success",
        "data": articles,
        "pagination": {
            "current_page": page,
            "items_per_page": limit,
            "total_items": total_items,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1
        }
    }


@app.get("/articles/{article_id}")
def get_article_by_id(article_id: int, db: Session = Depends(get_db)):
    article = db.query(ArticleDB).filter(ArticleDB.id == article_id).first()
    if not article: raise HTTPException(status_code=404)
    return article


@app.get("/articles/slug/{slug}")
def get_article_by_slug(slug: str, db: Session = Depends(get_db)):
    article = db.query(ArticleDB).filter(ArticleDB.slug == slug).first()
    if not article: raise HTTPException(status_code=404)
    return article


# --- UPDATE ARTICLE (FULL) ---
@app.put("/articles/{article_id}")
async def update_article(
        article_id: int,
        payload: dict = Body(...),
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    verify_jwt_token(token)

    article = db.query(ArticleDB).filter(ArticleDB.id == article_id).first()
    if not article: raise HTTPException(status_code=404, detail="Article not found")

    # 1. Păstrăm starea veche
    old_slug = article.slug
    old_status = article.status  # "Published" sau "Draft"

    # 2. Determinăm starea nouă
    new_slug = payload.get('slug', old_slug)
    raw_status = payload.get('status', old_status).lower()
    new_status = "Published" if raw_status == "published" else "Draft"

    # 3. Actualizăm DB
    article.title = payload.get('title', article.title)
    article.slug = new_slug
    article.category = payload.get('category', article.category)
    article.content = payload.get('content', article.content)
    article.excerpt = payload.get('excerpt', article.excerpt)
    article.tags = payload.get('tags', article.tags)
    article.cover_image = payload.get('coverImage', article.cover_image)
    article.status = new_status
    article.updated_at = datetime.utcnow()
    article.url = f"{SITE_URL}/{ARTICLES_URL_SUBDIR}/{new_slug}.html"

    if new_status == "Published" and not article.published_at:
        article.published_at = datetime.utcnow()

    db.commit()
    db.refresh(article)

    # 4. STATE MACHINE LOGIC

    # Cazul A: Era Published -> Acum e Draft (Unpublish)
    if old_status == "Published" and new_status == "Draft":
        unpublish_content_pipeline(old_slug)

    # Cazul B: Era Draft -> Acum e Published (Publish)
    elif old_status == "Draft" and new_status == "Published":
        publish_content_pipeline(article)

    # Cazul C: Rămâne Published, dar s-a schimbat Slug-ul sau Conținutul
    elif old_status == "Published" and new_status == "Published":
        if old_slug != new_slug:
            # Ștergem vechiul fișier/URL
            unpublish_content_pipeline(old_slug)
        # Creăm/Actualizăm noul fișier
        publish_content_pipeline(article)

    return {"status": "success", "article": article}


# --- PATCH STATUS (QUICK TOGGLE) ---
@app.patch("/articles/{article_id}")
async def patch_status(
        article_id: int,
        payload: dict = Body(...),
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    verify_jwt_token(token)

    article = db.query(ArticleDB).filter(ArticleDB.id == article_id).first()
    if not article: raise HTTPException(status_code=404)

    old_status = article.status
    raw_status = payload.get('status', '').lower()
    new_status = "Published" if raw_status == "published" else "Draft"

    article.status = new_status
    if new_status == "Published" and not article.published_at:
        article.published_at = datetime.utcnow()

    db.commit()

    # State Machine simplificat pentru Toggle
    if old_status == "Published" and new_status == "Draft":
        unpublish_content_pipeline(article.slug)
    elif new_status == "Published":
        publish_content_pipeline(article)

    return {"status": "success", "article": article}


# --- DELETE ARTICLE ---
@app.delete("/articles/{article_id}")
async def delete_article(
        article_id: int,
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    verify_jwt_token(token)

    article = db.query(ArticleDB).filter(ArticleDB.id == article_id).first()
    if not article: raise HTTPException(status_code=404)

    slug_to_remove = article.slug
    status_was = article.status

    db.delete(article)
    db.commit()

    # Doar dacă era publicat ștergem de pe net
    if status_was == "Published":
        unpublish_content_pipeline(slug_to_remove)

    return {"status": "success", "message": "Article deleted"}


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)