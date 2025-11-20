import os
import json
import logging
import urllib.parse
import xml.etree.ElementTree as ET
import base64
import math
from datetime import datetime, timedelta
from typing import List, Optional, Union, Dict, Any

# FastAPI Imports
from fastapi import FastAPI, Depends, HTTPException, Form, File, UploadFile, BackgroundTasks, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

# Database Imports (SQLAlchemy)
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
from googleapiclient.errors import HttpError
import requests

# ==================== 1. SETUP & CONFIGURARE ====================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# --- DATABASE SETUP (RAILWAY) ---
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if not DATABASE_URL:
    logger.warning("⚠️ DATABASE_URL lipsă. Rulez pe SQLite local (doar pentru teste).")
    DATABASE_URL = "sqlite:///./local_dev.db"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- FTP & SITE CONFIG ---
CPANEL_HOST = os.getenv("CPANEL_HOST")
CPANEL_PORT = int(os.getenv("CPANEL_PORT", 21))
CPANEL_USER = os.getenv("CPANEL_USERNAME")
CPANEL_PASSWORD = os.getenv("CPANEL_PASSWORD")

ARTICLES_UPLOAD_PATH_FTP = os.getenv("ARTICLES_UPLOAD_PATH_FTP")
SITEMAP_UPLOAD_PATH_FTP = os.getenv("SITEMAP_UPLOAD_PATH_FTP")
ARTICLES_URL_SUBDIR = os.getenv("ARTICLES_URL_SUBDIR", "noutati")
SITE_URL = os.getenv("SITE_URL")

# --- AUTH CONFIG ---
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", 60))

SCOPES = ["https://www.googleapis.com/auth/indexing"]

# --- LOCAL DIRS ---
GENERATED_DIR = "generated"
os.makedirs(GENERATED_DIR, exist_ok=True)
SITEMAP_FILE = os.path.join(GENERATED_DIR, "sitemap.xml")

# Asigurare folder templates
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

    # Stocăm tag-urile ca JSON simplu
    tags = Column(JSON, default=[])

    excerpt = Column(Text, nullable=True)

    # IMPORTANT: Folosim Text pentru Base64 (String are limită de lungime)
    cover_image = Column(Text, nullable=True)

    content = Column(Text, nullable=False)
    status = Column(String(50), default="draft")  # 'published' sau 'draft'
    author = Column(String(100), default="Frunză & Asociații")
    url = Column(String(500), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    published_at = Column(DateTime, nullable=True)


# Creare tabele automat
try:
    Base.metadata.create_all(bind=engine)
except Exception as e:
    logger.error(f"Database Init Error: {e}")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==================== 3. INIT FASTAPI ====================
app = FastAPI(title="CMS API (Paginare + Base64)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# ==================== 4. FUNCȚII AJUTĂTOARE (CORE LOGIC) ====================

# --- IMAGINI BASE64 ---
async def file_to_base64(file: UploadFile) -> str:
    """Convertește fișier uploadat în string Base64 pentru DB"""
    if not file:
        return None
    contents = await file.read()
    encoded = base64.b64encode(contents).decode("utf-8")
    mime_type = file.content_type or "image/jpeg"
    return f"data:{mime_type};base64,{encoded}"


def generate_tags_html(tags_input):
    """Generează HTML pentru tag-uri"""
    tags_list = []
    if isinstance(tags_input, list):
        tags_list = tags_input
    elif isinstance(tags_input, str):
        tags_list = [t.strip() for t in tags_input.split(",") if t.strip()]

    html = []
    for tag in tags_list:
        html.append(f'<span class="tag">{tag}</span>')
    return "\n".join(html) if html else '<span class="tag">General</span>'


# --- FTP ---
def upload_to_cpanel(local_path: str, remote_filename: str, remote_dir: str):
    ftp = None
    try:
        ftp = FTP()
        ftp.connect(CPANEL_HOST, CPANEL_PORT, timeout=30)
        ftp.login(CPANEL_USER, CPANEL_PASSWORD)

        # Navigare sau creare folder recursiv
        try:
            ftp.cwd(remote_dir)
        except error_perm:
            # Dacă nu există, încercăm să îl creăm
            try:
                ftp.mkd(remote_dir)
                ftp.cwd(remote_dir)
            except:
                # Logică recursivă simplă
                parts = remote_dir.strip('/').split('/')
                curr = ""
                for part in parts:
                    curr = f"{curr}/{part}"
                    try:
                        ftp.mkd(curr)
                    except:
                        pass
                ftp.cwd(remote_dir)

        with open(local_path, 'rb') as f:
            ftp.storbinary(f'STOR {remote_filename}', f)
        return True
    except Exception as e:
        logger.error(f"FTP Upload Error: {e}")
        raise ValueError(f"FTP Failed: {str(e)}")
    finally:
        if ftp:
            try: ftp.quit();
            except: pass


def download_from_cpanel(remote_filename: str, local_path: str, remote_dir: str):
    ftp = None
    try:
        ftp = FTP()
        ftp.connect(CPANEL_HOST, CPANEL_PORT, timeout=10)
        ftp.login(CPANEL_USER, CPANEL_PASSWORD)
        ftp.cwd(remote_dir)
        with open(local_path, 'wb') as f:
            ftp.retrbinary(f'RETR {remote_filename}', f.write)
        return True
    except:
        return False
    finally:
        if ftp:
            try:ftp.quit();
            except:pass


# --- GOOGLE SERVICES ---
def get_service_account_credentials():
    try:
        if not os.getenv("GOOGLE_CLIENT_EMAIL"): return None
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
        return service_account.Credentials.from_service_account_info(creds_dict, scopes=SCOPES)
    except:
        return None


def request_google_indexing(url: str, type="URL_UPDATED"):
    try:
        creds = get_service_account_credentials()
        if not creds: return False
        service = build('indexing', 'v3', credentials=creds)
        service.urlNotifications().publish(body={"url": url, "type": type}).execute()
        return True
    except Exception as e:
        logger.error(f"Indexing Error: {e}")
        return False


def update_sitemap(new_url: str):
    try:
        download_from_cpanel("sitemap.xml", SITEMAP_FILE, SITEMAP_UPLOAD_PATH_FTP)
        root = None

        # Încearcă să parseze, altfel creează nou
        if os.path.exists(SITEMAP_FILE):
            try:
                ET.register_namespace('', "http://www.sitemaps.org/schemas/sitemap/0.9")
                tree = ET.parse(SITEMAP_FILE)
                root = tree.getroot()
            except:
                pass

        if root is None:
            root = ET.Element("urlset", xmlns="http://www.sitemaps.org/schemas/sitemap/0.9")

        ns = {'sitemap': 'http://www.sitemaps.org/schemas/sitemap/0.9'}

        # Verifică dacă URL-ul există deja
        found = False
        # Căutare generică pentru a evita probleme de namespace
        for url in root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}url"):
            loc = url.find("{http://www.sitemaps.org/schemas/sitemap/0.9}loc")
            if loc is not None and loc.text == new_url:
                found = True
                lastmod = url.find("{http://www.sitemaps.org/schemas/sitemap/0.9}lastmod")
                if lastmod is not None: lastmod.text = datetime.utcnow().strftime("%Y-%m-%d")
                break

        if not found:
            url_elem = ET.Element("url")
            ET.SubElement(url_elem, "loc").text = new_url
            ET.SubElement(url_elem, "lastmod").text = datetime.utcnow().strftime("%Y-%m-%d")
            root.append(url_elem)

        tree = ET.ElementTree(root)
        ET.register_namespace('', "http://www.sitemaps.org/schemas/sitemap/0.9")
        tree.write(SITEMAP_FILE, encoding="utf-8", xml_declaration=True)

        upload_to_cpanel(SITEMAP_FILE, "sitemap.xml", SITEMAP_UPLOAD_PATH_FTP)

        # Ping
        ping_url = f"https://www.google.com/ping?sitemap={urllib.parse.quote(SITE_URL + '/sitemap.xml')}"
        requests.get(ping_url, timeout=5)
        return True
    except Exception as e:
        logger.error(f"Sitemap error: {e}")
        return False


# ==================== 5. AUTHENTICATION ====================
def create_jwt_token(username: str):
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXP_MINUTES)
    return jwt.encode({"sub": username, "exp": expire}, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("sub") != ADMIN_USERNAME: raise HTTPException(status_code=401)
        return payload.get("sub")
    except:
        raise HTTPException(status_code=401, detail="Invalid Token")


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username == ADMIN_USERNAME and form_data.password == ADMIN_PASSWORD:
        return {"access_token": create_jwt_token(form_data.username), "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Invalid credentials")


# ==================== 6. API ENDPOINTS ====================

@app.get("/articles")
def get_articles(
        page: int = Query(1, ge=1, description="Numărul paginii"),
        limit: int = Query(6, ge=1, le=100, description="Articole per pagină (Default 6)"),
        search: Optional[str] = None,
        db: Session = Depends(get_db)
):
    """
    Returnează articolele paginate.
    Ex: /articles?page=1&limit=6
    """
    query = db.query(ArticleDB)

    # Filtrare (Search)
    if search:
        query = query.filter(ArticleDB.title.ilike(f"%{search}%"))

    # Sortare: Cele mai noi primele
    query = query.order_by(desc(ArticleDB.created_at))

    # Calcule Paginare
    total_items = query.count()
    total_pages = math.ceil(total_items / limit)
    offset = (page - 1) * limit

    # Obținere date
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
def get_article(article_id: int, db: Session = Depends(get_db)):
    article = db.query(ArticleDB).filter(ArticleDB.id == article_id).first()
    if not article: raise HTTPException(status_code=404, detail="Article not found")
    return {"status": "success", "article": article}


# --- CREATE via FORM DATA (Upload Fisier) ---
@app.post("/create-article/")
async def create_article_form(
        title: str = Form(...),
        slug: str = Form(...),
        category: str = Form(...),
        tags: str = Form(""),
        extras: str = Form(None),
        content: str = Form(...),
        # Acceptam imaginea ca fisier SAU ca url string
        cover_image_file: UploadFile = File(None),
        cover_image_url: str = Form(None),
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    verify_jwt_token(token)

    # 1. Validare Slug
    if db.query(ArticleDB).filter(ArticleDB.slug == slug).first():
        raise HTTPException(status_code=400, detail="Slug already exists")

    # 2. Procesare Imagine -> Base64
    final_cover_image = None
    if cover_image_file:
        final_cover_image = await file_to_base64(cover_image_file)
    elif cover_image_url:
        final_cover_image = cover_image_url
    else:
        final_cover_image = "https://frunza-asociatii.ro/images/default-article.jpg"

    # 3. Salvare in DB
    tags_list = [t.strip() for t in tags.split(",")] if tags else []
    article_url = f"{SITE_URL}/{ARTICLES_URL_SUBDIR}/{slug}.html"

    new_article = ArticleDB(
        title=title, slug=slug, category=category, tags=tags_list,
        excerpt=extras or "",
        cover_image=final_cover_image,
        content=content, status="published", url=article_url,
        published_at=datetime.utcnow()
    )
    db.add(new_article)
    db.commit()
    db.refresh(new_article)

    # 4. Generare HTML & Upload FTP
    try:
        template = env.get_template("article_template.html")
        html_content = template.render(
            ARTICLE_TITLE=title,
            ARTICLE_CATEGORY=category,
            ARTICLE_COVER_IMAGE=final_cover_image,
            ARTICLE_AUTHOR="Frunză & Asociații",
            ARTICLE_DATE=datetime.utcnow().strftime("%d %B %Y"),
            ARTICLE_EXCERPT=extras or "",
            ARTICLE_TAGS_HTML=generate_tags_html(tags_list),
            ARTICLE_CONTENT=content,
            ARTICLE_URL=article_url,
            SITE_URL=SITE_URL
        )

        filename = slug.lower().replace(" ", "-") + ".html"
        local_path = os.path.join(GENERATED_DIR, filename)
        with open(local_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        upload_to_cpanel(local_path, filename, ARTICLES_UPLOAD_PATH_FTP)
        os.remove(local_path)

        # 5. SEO
        update_sitemap(article_url)
        request_google_indexing(article_url)

        return {"status": "success", "article_id": new_article.id}
    except Exception as e:
        logger.error(f"Pipeline Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# --- CREATE via JSON (Frontend trimite direct Base64) ---
@app.post("/articles")
async def create_article_json(
        payload: dict,
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    verify_jwt_token(token)
    slug = payload.get('slug')

    if db.query(ArticleDB).filter(ArticleDB.slug == slug).first():
        raise HTTPException(status_code=400, detail="Slug exists")

    article_url = f"{SITE_URL}/{ARTICLES_URL_SUBDIR}/{slug}.html"
    tags = payload.get('tags', [])
    tags_list = [t.strip() for t in tags.split(",")] if isinstance(tags, str) else tags

    # Frontendul trebuie să trimită stringul Base64 complet în 'coverImage'
    new_article = ArticleDB(
        title=payload.get('title'), slug=slug, category=payload.get('category'),
        tags=tags_list, excerpt=payload.get('excerpt', ''),
        cover_image=payload.get('coverImage'),
        content=payload.get('content'), status=payload.get('status', 'draft'),
        url=article_url, published_at=datetime.utcnow()
    )
    db.add(new_article)
    db.commit()

    if payload.get('status') == 'published':
        # Refolosim logica de template (simplificata aici)
        try:
            template = env.get_template("article_template.html")
            html_content = template.render(
                ARTICLE_TITLE=new_article.title,
                ARTICLE_CATEGORY=new_article.category,
                ARTICLE_COVER_IMAGE=new_article.cover_image,
                ARTICLE_AUTHOR="Frunză & Asociații",
                ARTICLE_DATE=datetime.utcnow().strftime("%d %B %Y"),
                ARTICLE_CONTENT=new_article.content,
                ARTICLE_TAGS_HTML=generate_tags_html(tags_list),
                ARTICLE_URL=article_url,
                SITE_URL=SITE_URL
            )
            filename = slug.lower().replace(" ", "-") + ".html"
            local_path = os.path.join(GENERATED_DIR, filename)
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            upload_to_cpanel(local_path, filename, ARTICLES_UPLOAD_PATH_FTP)
            os.remove(local_path)
            update_sitemap(article_url)
            request_google_indexing(article_url)
        except Exception as e:
            logger.error(f"Publishing Error: {e}")

    return {"status": "success", "article": new_article}


@app.put("/articles/{article_id}")
async def update_article(
        article_id: int,
        title: str = Form(None),
        category: str = Form(None),
        content: str = Form(None),
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    verify_jwt_token(token)
    article = db.query(ArticleDB).filter(ArticleDB.id == article_id).first()
    if not article: raise HTTPException(status_code=404)

    if title: article.title = title
    if category: article.category = category
    if content: article.content = content
    article.updated_at = datetime.utcnow()

    db.commit()
    return {"status": "success", "article": article}


@app.delete("/articles/{article_id}")
async def delete_article(article_id: int, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    verify_jwt_token(token)
    article = db.query(ArticleDB).filter(ArticleDB.id == article_id).first()
    if not article: raise HTTPException(status_code=404)

    url_to_remove = article.url
    db.delete(article)
    db.commit()

    if url_to_remove:
        request_google_indexing(url_to_remove, "URL_DELETED")

    return {"status": "success", "message": "Article deleted"}


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    try:
        count = db.query(ArticleDB).count()
        return {"status": "healthy", "db_items": count}
    except Exception as e:
        return {"status": "error", "details": str(e)}


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)