from fastapi import FastAPI, Depends, HTTPException, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import jwt
import os
import json
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader
import xml.etree.ElementTree as ET
import requests
import logging
import urllib.parse
import tempfile
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ["https://www.googleapis.com/auth/indexing"]

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# ==================== CONFIG ====================
# SFTP / cPanel
CPANEL_HOST = os.getenv("CPANEL_HOST")
CPANEL_PORT = int(os.getenv("CPANEL_PORT", 21))
CPANEL_USER = os.getenv("CPANEL_USERNAME")
CPANEL_PASSWORD = os.getenv("CPANEL_PASSWORD")
UPLOAD_PATH = os.getenv("UPLOAD_PATH")
SITE_URL = os.getenv("SITE_URL")

# Admin / JWT
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", 60))

# Validare configurație
required_vars = {
    "CPANEL_HOST": CPANEL_HOST,
    "CPANEL_USERNAME": CPANEL_USER,
    "CPANEL_PASSWORD": CPANEL_PASSWORD,
    "UPLOAD_PATH": UPLOAD_PATH,
    "SITE_URL": SITE_URL,
    "ADMIN_USERNAME": ADMIN_USERNAME,
    "ADMIN_PASSWORD": ADMIN_PASSWORD,
    "JWT_SECRET_KEY": JWT_SECRET_KEY,
}

missing_vars = [key for key, value in required_vars.items() if not value]
if missing_vars:
    raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Frontend / API
GENERATED_DIR = "generated"
os.makedirs(GENERATED_DIR, exist_ok=True)
SITEMAP_FILE = os.path.join(GENERATED_DIR, "sitemap.xml")
ARTICLES_JSON = os.path.join(GENERATED_DIR, "articles.json")

# Templates
env = Environment(loader=FileSystemLoader("templates"))

# ==================== APP ====================
app = FastAPI(title="Frunză & Asociații CMS API")

# ==================== CORS ====================
origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "https://frunza-asociatii.ro",
    "https://www.frunza-asociatii.ro",
    "https://www.frunza-asociatii.ro/noutati",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ⚠️ Permite TOATE originile
    allow_credentials=False,  # TREBUIE False cu "*"
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# ==================== JWT FUNCTIONS ====================
def create_jwt_token(username: str):
    """Create JWT token for authenticated user"""
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXP_MINUTES)
    payload = {"sub": username, "exp": expire}
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


def verify_jwt_token(token: str):
    """Verify JWT token and return username"""
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


# ==================== ARTICLES JSON MANAGEMENT ====================
def load_articles():
    """Load articles metadata from JSON file (download from cPanel if needed)"""
    try:
        # Încearcă să descarci de pe cPanel mai întâi
        try:
            download_from_cpanel("articles.json", ARTICLES_JSON)
            logger.info("Downloaded articles.json from cPanel")
        except Exception as e:
            logger.warning(f"Could not download from cPanel: {e}")

        # Citește local (fie descărcat, fie existent)
        if os.path.exists(ARTICLES_JSON):
            with open(ARTICLES_JSON, 'r', encoding='utf-8') as f:
                articles = json.load(f)
                logger.info(f"Loaded {len(articles)} articles from local file")
                return articles

        logger.info("No articles.json found, returning empty list")
        return []
    except Exception as e:
        logger.error(f"Error loading articles: {e}")
        return []


def download_from_cpanel(remote_filename: str, local_path: str):
    """Download file from cPanel via FTP"""
    from ftplib import FTP

    ftp = None
    try:
        logger.info(f"Downloading {remote_filename} from cPanel...")

        ftp = FTP()
        ftp.connect(CPANEL_HOST, CPANEL_PORT, timeout=30)
        ftp.login(CPANEL_USER, CPANEL_PASSWORD)
        ftp.cwd(UPLOAD_PATH)

        with open(local_path, 'wb') as f:
            ftp.retrbinary(f'RETR {remote_filename}', f.write)

        logger.info(f"Downloaded {remote_filename} successfully")

    except Exception as e:
        logger.error(f"Download failed: {e}")
        raise ValueError(f"Could not download {remote_filename}: {str(e)}")
    finally:
        if ftp:
            try:
                ftp.quit()
            except:
                try:
                    ftp.close()
                except:
                    pass


def save_article_metadata(metadata: dict):
    """Save new article metadata to JSON file and upload to server"""
    try:
        articles = load_articles()

        # Add new article at the beginning
        articles.insert(0, metadata)

        # Save locally
        with open(ARTICLES_JSON, 'w', encoding='utf-8') as f:
            json.dump(articles, f, ensure_ascii=False, indent=2)

        logger.info(f"Article metadata saved locally: {metadata['title']}")

        # Upload to server
        try:
            upload_to_cpanel(ARTICLES_JSON, "articles.json")
            logger.info("Articles JSON uploaded to server successfully")
        except Exception as e:
            logger.error(f"Failed to upload articles.json: {e}")
            # Non-critical, continue

    except Exception as e:
        logger.error(f"Error saving article metadata: {e}")
        raise ValueError(f"Failed to save article metadata: {str(e)}")


def update_article_metadata(article_id: str, updates: dict):
    """Update existing article metadata"""
    try:
        articles = load_articles()

        # Find and update article
        for i, article in enumerate(articles):
            if str(article.get('id')) == str(article_id):
                articles[i].update(updates)
                articles[i]['updatedAt'] = datetime.utcnow().isoformat()

                # Save locally
                with open(ARTICLES_JSON, 'w', encoding='utf-8') as f:
                    json.dump(articles, f, ensure_ascii=False, indent=2)

                # Upload to server
                upload_to_cpanel(ARTICLES_JSON, "articles.json")
                logger.info(f"Article updated: {article_id}")
                return True

        return False
    except Exception as e:
        logger.error(f"Error updating article: {e}")
        raise ValueError(f"Failed to update article: {str(e)}")


def delete_article_metadata(article_id: str):
    """Delete article metadata"""
    try:
        articles = load_articles()

        # Filter out the article
        original_length = len(articles)
        articles = [a for a in articles if str(a.get('id')) != str(article_id)]

        if len(articles) == original_length:
            return False  # Article not found

        # Save locally
        with open(ARTICLES_JSON, 'w', encoding='utf-8') as f:
            json.dump(articles, f, ensure_ascii=False, indent=2)

        # Upload to server
        upload_to_cpanel(ARTICLES_JSON, "articles.json")
        logger.info(f"Article deleted: {article_id}")
        return True

    except Exception as e:
        logger.error(f"Error deleting article: {e}")
        raise ValueError(f"Failed to delete article: {str(e)}")


# ==================== AUTH ENDPOINT ====================
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login endpoint to get JWT token"""
    if form_data.username == ADMIN_USERNAME and form_data.password == ADMIN_PASSWORD:
        token = create_jwt_token(form_data.username)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Incorrect username or password")


# ==================== FTP UPLOAD ====================
def upload_to_cpanel(local_path: str, remote_filename: str):
    """
    Upload file to cPanel via FTP with improved error handling

    Args:
        local_path: Local file path to upload
        remote_filename: Remote filename (without path)

    Returns:
        str: Remote file path

    Raises:
        ValueError: If upload fails
    """
    from ftplib import FTP, error_perm

    ftp = None

    try:
        logger.info(f"Attempting FTP connection to {CPANEL_HOST}:{CPANEL_PORT}")

        # Create FTP connection
        ftp = FTP()
        ftp.connect(CPANEL_HOST, CPANEL_PORT, timeout=30)

        # Login
        logger.info(f"Logging in as user: {CPANEL_USER}")
        ftp.login(CPANEL_USER, CPANEL_PASSWORD)

        logger.info(f"FTP connection successful. Current directory: {ftp.pwd()}")

        # Change to upload directory
        try:
            ftp.cwd(UPLOAD_PATH)
            logger.info(f"Changed to directory: {UPLOAD_PATH}")
        except error_perm as e:
            logger.error(f"Cannot access directory {UPLOAD_PATH}: {e}")
            # Try to create directory
            try:
                # Navigate to parent and create
                parts = UPLOAD_PATH.strip('/').split('/')
                current = '/'
                for part in parts:
                    current = f"{current}{part}/"
                    try:
                        ftp.cwd(current)
                    except:
                        ftp.mkd(current)
                        ftp.cwd(current)
                logger.info(f"Created and changed to directory: {UPLOAD_PATH}")
            except Exception as create_error:
                logger.error(f"Could not create directory: {create_error}")
                raise ValueError(f"Remote directory {UPLOAD_PATH} does not exist and cannot be created")

        # Upload file in binary mode
        remote_path = f"{UPLOAD_PATH}/{remote_filename}".replace('//', '/')
        logger.info(f"Uploading {local_path} to {remote_path}")

        with open(local_path, 'rb') as f:
            ftp.storbinary(f'STOR {remote_filename}', f)

        logger.info(f"File uploaded successfully to {remote_path}")

        return remote_path

    except error_perm as e:
        logger.error(f"FTP permission error: {e}")
        if "530" in str(e):
            raise ValueError(f"FTP authentication failed. Check username and password.")
        elif "550" in str(e):
            raise ValueError(f"FTP permission denied. Check directory permissions.")
        else:
            raise ValueError(f"FTP error: {str(e)}")

    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        raise ValueError(f"Local file not found: {local_path}")

    except Exception as e:
        logger.error(f"Unexpected error during FTP upload: {e}")
        raise ValueError(f"Upload failed: {str(e)}")

    finally:
        # Close FTP connection
        if ftp:
            try:
                ftp.quit()
            except:
                try:
                    ftp.close()
                except:
                    pass


# ==================== GOOGLE INDEXING API ====================
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
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
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


def request_google_indexing(url: str):
    """
    Request indexing for a URL using Google Indexing API

    Args:
        url: Full URL to index (e.g., https://frunza-asociatii.ro/noutati/article.html)

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Get credentials
        credentials = get_service_account_credentials()
        if not credentials:
            logger.warning("⚠️ Google Indexing API not configured - skipping")
            return False

        # Build the service
        service = build('indexing', 'v3', credentials=credentials)

        # Request indexing
        body = {
            "url": url,
            "type": "URL_UPDATED"
        }

        response = service.urlNotifications().publish(body=body).execute()

        logger.info(f"✅ Google indexing requested successfully for: {url}")
        logger.debug(f"Google API response: {response}")

        return True

    except HttpError as e:
        # Handle specific Google API errors
        if e.resp.status == 403:
            logger.error(f"❌ Google API permission denied. Check service account permissions in Search Console")
        elif e.resp.status == 429:
            logger.error(f"❌ Google API rate limit exceeded. Try again later")
        else:
            logger.error(f"❌ Google Indexing API HTTP error ({e.resp.status}): {e.content}")
        return False
    except Exception as e:
        logger.error(f"❌ Unexpected error requesting indexing: {e}")
        return False


def request_google_batch_indexing(urls: list):
    """
    Request indexing for multiple URLs in a batch

    Args:
        urls: List of URLs to index

    Returns:
        dict: Results with success count and errors
    """
    try:
        credentials = get_service_account_credentials()
        if not credentials:
            logger.warning("⚠️ Google Indexing API not configured - skipping batch")
            return {"success": 0, "failed": len(urls), "errors": ["API not configured"]}

        service = build('indexing', 'v3', credentials=credentials)
        batch = service.new_batch_http_request()

        results = {"success": 0, "failed": 0, "errors": []}

        def callback(request_id, response, exception):
            if exception:
                results["failed"] += 1
                results["errors"].append(str(exception))
                logger.error(f"Batch indexing error for request {request_id}: {exception}")
            else:
                results["success"] += 1

        for url in urls:
            body = {"url": url, "type": "URL_UPDATED"}
            batch.add(service.urlNotifications().publish(body=body), callback=callback)

        batch.execute()

        logger.info(f"✅ Batch indexing completed: {results['success']} succeeded, {results['failed']} failed")

        return results

    except Exception as e:
        logger.error(f"❌ Batch indexing error: {e}")
        return {"success": 0, "failed": len(urls), "errors": [str(e)]}


def delete_url_from_index(url: str):
    """
    Request removal of a URL from Google index

    Args:
        url: Full URL to remove

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        credentials = get_service_account_credentials()
        if not credentials:
            return False

        service = build('indexing', 'v3', credentials=credentials)

        body = {
            "url": url,
            "type": "URL_DELETED"
        }

        response = service.urlNotifications().publish(body=body).execute()

        logger.info(f"✅ Google removal requested for: {url}")
        return True

    except Exception as e:
        logger.error(f"❌ Error requesting URL removal: {e}")
        return False


# ==================== SITEMAP ====================
def update_sitemap(new_url: str):
    """Add new URL to sitemap.xml"""
    try:
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

        logger.info(f"Sitemap updated with new URL: {new_url}")

    except Exception as e:
        logger.error(f"Error updating sitemap: {e}")
        raise ValueError(f"Failed to update sitemap: {str(e)}")


def ping_google(sitemap_url: str):
    """Notify Google about sitemap update"""
    try:
        encoded_url = urllib.parse.quote(sitemap_url, safe='')
        response = requests.get(
            f"https://www.google.com/ping?sitemap={encoded_url}",
            timeout=10
        )
        logger.info(f"Google pinged successfully for sitemap. Status: {response.status_code}")
    except Exception as e:
        logger.warning(f"Failed to ping Google (non-critical): {e}")


# ==================== ARTICLES ENDPOINTS ====================
@app.get("/articles")
async def get_articles():
    """Get all articles metadata"""
    try:
        articles = load_articles()
        return {
            "status": "success",
            "count": len(articles),
            "articles": articles
        }
    except Exception as e:
        logger.error(f"Error fetching articles: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to fetch articles"
        )


@app.get("/articles/{article_id}")
async def get_article(article_id: str):
    """Get single article by ID"""
    try:
        articles = load_articles()
        article = next((a for a in articles if str(a.get('id')) == article_id), None)

        if not article:
            raise HTTPException(status_code=404, detail="Article not found")

        return {
            "status": "success",
            "article": article
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching article: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to fetch article"
        )


def generate_tags_html(tags):
    """Generate HTML for tags"""
    if isinstance(tags, str):
        tags = [tag.strip() for tag in tags.split(",")]
    elif not isinstance(tags, list):
        tags = []

    html_tags = []
    for tag in tags:
        if tag.strip():  # Skip empty tags
            html_tags.append(f'<span class="tag">{tag.strip()}</span>')

    return "\n".join(html_tags) if html_tags else '<span class="tag">General</span>'


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
    """Create a new article and upload to cPanel"""
    verify_jwt_token(token)
    local_path = None

    try:
        logger.info(f"Creating article: {title} (slug: {slug})")

        # Render template
        template = env.get_template("article_template.html")
        html_content = template.render(
            ARTICLE_TITLE=title,
            ARTICLE_CATEGORY=category,
            ARTICLE_COVER_IMAGE=cover_image or "https://frunza-asociatii.ro/images/default-article.jpg",
            ARTICLE_AUTHOR="Frunză & Asociații",
            ARTICLE_DATE=datetime.utcnow().strftime("%d %B %Y"),
            ARTICLE_DATE_ISO=datetime.utcnow().isoformat(),
            ARTICLE_MODIFIED_DATE_ISO=datetime.utcnow().isoformat(),
            ARTICLE_EXCERPT=extras or "",
            ARTICLE_TAGS=tags,
            ARTICLE_TAGS_HTML=generate_tags_html(tags),
            ARTICLE_CONTENT=content,
            ARTICLE_URL=f"{SITE_URL}/noutati/{slug}.html",
            SITE_URL=SITE_URL
        )

        # Generate filename
        filename = slug.lower().replace(" ", "-") + ".html"
        local_path = os.path.join(GENERATED_DIR, filename)

        # Write local file
        with open(local_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"Article file created locally: {local_path}")

        # Upload to cPanel
        try:
            upload_to_cpanel(local_path, filename)
        except ValueError as e:
            logger.error(f"Upload failed: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to upload article to server: {str(e)}"
            )

        # Create article URL
        file_url = f"{SITE_URL}/noutati/{filename}"

        # Create metadata object
        article_id = int(datetime.utcnow().timestamp() * 1000)
        metadata = {
            "id": article_id,
            "title": title,
            "slug": slug,
            "category": category,
            "tags": [tag.strip() for tag in tags.split(",")],
            "excerpt": extras or "",
            "coverImage": cover_image,
            "content": content,
            "status": "published",
            "author": "Frunză & Asociații",
            "createdAt": datetime.utcnow().isoformat(),
            "updatedAt": datetime.utcnow().isoformat(),
            "publishedAt": datetime.utcnow().isoformat(),
            "url": file_url
        }

        # Save metadata
        try:
            save_article_metadata(metadata)
        except Exception as e:
            logger.warning(f"Failed to save article metadata (non-critical): {e}")

        # Update sitemap
        sitemap_updated = False
        try:
            update_sitemap(file_url)
            upload_to_cpanel(SITEMAP_FILE, "sitemap.xml")
            logger.info("✅ Sitemap updated and uploaded")

            # 🆕 PING GOOGLE SITEMAP
            ping_google(f"{SITE_URL}/sitemap.xml")

            sitemap_updated = True
        except Exception as e:
            logger.warning(f"Sitemap update/ping failed (non-critical): {e}")

        # 🆕 REQUEST INDEXING
        indexing_requested = False
        try:
            indexing_requested = request_google_indexing(file_url)
            if indexing_requested:
                logger.info(f"🚀 Google indexing requested for: {file_url}")
        except Exception as e:
            logger.warning(f"Indexing request failed (non-critical): {e}")

        logger.info(f"✅ Article published successfully: {file_url}")

        return {
            "status": "success",
            "message": "Article created and published successfully",
            "file": filename,
            "url": file_url,
            "article": metadata,
            "sitemap_updated": sitemap_updated,
            "indexing_requested": indexing_requested  # 🆕
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error creating article: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create article: {str(e)}"
        )
    finally:
        if local_path and os.path.exists(local_path):
            try:
                os.remove(local_path)
                logger.info(f"Local file cleaned up: {local_path}")
            except Exception as e:
                logger.warning(f"Failed to remove local file: {e}")


@app.put("/articles/{article_id}")
async def update_article(
        article_id: str,
        title: str = Form(None),
        category: str = Form(None),
        tags: str = Form(None),
        extras: str = Form(None),
        cover_image: str = Form(None),
        status: str = Form(None),
        token: str = Depends(oauth2_scheme)
):
    """Update existing article metadata"""
    verify_jwt_token(token)

    try:
        updates = {}
        if title:
            updates['title'] = title
        if category:
            updates['category'] = category
        if tags:
            updates['tags'] = [tag.strip() for tag in tags.split(",")]
        if extras:
            updates['excerpt'] = extras
        if cover_image:
            updates['coverImage'] = cover_image
        if status:
            updates['status'] = status
            if status == 'published' and 'publishedAt' not in updates:
                updates['publishedAt'] = datetime.utcnow().isoformat()

        success = update_article_metadata(article_id, updates)

        if not success:
            raise HTTPException(status_code=404, detail="Article not found")

        return {
            "status": "success",
            "message": "Article updated successfully",
            "article_id": article_id
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating article: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update article: {str(e)}"
        )


@app.get("/test-google-indexing")
async def test_google_indexing(token: str = Depends(oauth2_scheme)):
    """Test Google Indexing API configuration"""
    verify_jwt_token(token)

    try:
        credentials = get_service_account_credentials()
        if not credentials:
            return {
                "status": "error",
                "message": "Google credentials not configured",
                "configured": False
            }

        # Try to build service
        service = build('indexing', 'v3', credentials=credentials)

        return {
            "status": "success",
            "message": "Google Indexing API configured correctly",
            "configured": True,
            "project_id": os.getenv("GOOGLE_PROJECT_ID"),
            "client_email": os.getenv("GOOGLE_CLIENT_EMAIL")
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Google API configuration error: {str(e)}",
            "configured": False
        }


@app.delete("/articles/{article_id}")
async def delete_article(article_id: str, token: str = Depends(oauth2_scheme)):
    """Delete article metadata and request removal from index"""
    verify_jwt_token(token)

    try:
        # Get article info before deletion
        articles = load_articles()
        article = next((a for a in articles if str(a.get('id')) == article_id), None)

        if not article:
            raise HTTPException(status_code=404, detail="Article not found")

        article_url = article.get('url')

        # Delete from metadata
        success = delete_article_metadata(article_id)

        if not success:
            raise HTTPException(status_code=404, detail="Article not found")

        # Request removal from Google index
        removal_requested = False
        if article_url:
            try:
                removal_requested = delete_url_from_index(article_url)
                if removal_requested:
                    logger.info(f"🗑️ Google removal requested for: {article_url}")
            except Exception as e:
                logger.warning(f"Could not request removal from index: {e}")

        return {
            "status": "success",
            "message": "Article deleted successfully",
            "article_id": article_id,
            "removal_requested": removal_requested
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting article: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete article: {str(e)}"
        )


# ==================== HEALTH CHECK ====================
@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "Frunză & Asociații CMS API",
        "version": "1.0.0"
    }


@app.get("/health")
async def health_check():
    """Detailed health check"""
    articles = load_articles()

    # Check Google API configuration
    google_configured = False
    try:
        creds = get_service_account_credentials()
        google_configured = creds is not None
    except:
        pass

    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "config": {
            "cpanel_host": CPANEL_HOST,
            "cpanel_port": CPANEL_PORT,
            "site_url": SITE_URL,
            "upload_path_configured": bool(UPLOAD_PATH),
            "articles_count": len(articles),
            "google_indexing_configured": google_configured  # 🆕
        }
    }


@app.post("/articles")
async def create_article_json(
        payload: dict,
        token: str = Depends(oauth2_scheme)
):
    """Create article with JSON payload"""
    verify_jwt_token(token)
    local_path = None

    try:
        # Extract data from payload
        title = payload.get('title')
        slug = payload.get('slug')
        category = payload.get('category')
        tags = payload.get('tags', [])
        excerpt = payload.get('excerpt', '')
        cover_image = payload.get('coverImage')
        content = payload.get('content')
        status = payload.get('status', 'draft')

        # Validate required fields
        if not all([title, slug, content, category]):
            raise HTTPException(status_code=400, detail="Missing required fields: title, slug, content, category")

        logger.info(f"Creating article via JSON: {title} (slug: {slug})")

        # Render template
        template = env.get_template("article_template.html")
        html_content = template.render(
            ARTICLE_TITLE=title,
            ARTICLE_CATEGORY=category,
            ARTICLE_COVER_IMAGE=cover_image or "https://frunza-asociatii.ro/images/default-article.jpg",
            ARTICLE_AUTHOR="Frunză & Asociații",
            ARTICLE_DATE=datetime.utcnow().strftime("%d %B %Y"),
            ARTICLE_DATE_ISO=datetime.utcnow().isoformat(),
            ARTICLE_MODIFIED_DATE_ISO=datetime.utcnow().isoformat(),
            ARTICLE_EXCERPT=excerpt,
            ARTICLE_TAGS=", ".join(tags) if isinstance(tags, list) else tags,
            ARTICLE_TAGS_HTML=generate_tags_html(tags),
            ARTICLE_CONTENT=content,
            ARTICLE_URL=f"{SITE_URL}/noutati/{slug}.html",
            SITE_URL=SITE_URL
        )

        # Generate filename
        filename = slug.lower().replace(" ", "-") + ".html"
        local_path = os.path.join(GENERATED_DIR, filename)

        # Write local file
        with open(local_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"Article HTML created locally: {local_path}")

        # Upload HTML to server
        try:
            upload_to_cpanel(local_path, filename)
            logger.info(f"Article HTML uploaded to server: {filename}")
        except ValueError as e:
            logger.error(f"Upload failed: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to upload article to server: {str(e)}"
            )

        # Create article URL
        file_url = f"{SITE_URL}/noutati/{filename}"

        # Create metadata
        article_id = int(datetime.utcnow().timestamp() * 1000)
        metadata = {
            "id": article_id,
            "title": title,
            "slug": slug,
            "category": category,
            "tags": tags if isinstance(tags, list) else [tags],
            "excerpt": excerpt,
            "coverImage": cover_image,
            "content": content,
            "status": status,
            "author": "Frunză & Asociații",
            "createdAt": datetime.utcnow().isoformat(),
            "updatedAt": datetime.utcnow().isoformat(),
            "publishedAt": datetime.utcnow().isoformat() if status == 'published' else None,
            "url": file_url
        }

        # Save metadata
        save_article_metadata(metadata)

        # Update sitemap
        sitemap_updated = False
        try:
            update_sitemap(file_url)
            upload_to_cpanel(SITEMAP_FILE, "sitemap.xml")
            logger.info("✅ Sitemap updated and uploaded")

            # 🆕 PING GOOGLE SITEMAP
            ping_google(f"{SITE_URL}/sitemap.xml")

            sitemap_updated = True
        except Exception as e:
            logger.warning(f"Sitemap update/ping failed (non-critical): {e}")

        # 🆕 REQUEST INDEXING (doar dacă articolul e publicat)
        indexing_requested = False
        if status == 'published':
            try:
                indexing_requested = request_google_indexing(file_url)
                if indexing_requested:
                    logger.info(f"🚀 Google indexing requested for: {file_url}")
                else:
                    logger.warning(f"⚠️ Could not request Google indexing (non-critical)")
            except Exception as e:
                logger.warning(f"Indexing request failed (non-critical): {e}")

        logger.info(f"✅ Article published successfully: {file_url}")

        return {
            "status": "success",
            "message": "Article created and published successfully",
            "file": filename,
            "url": file_url,
            "article": metadata,
            "sitemap_updated": sitemap_updated,
            "indexing_requested": indexing_requested  # 🆕
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating article: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if local_path and os.path.exists(local_path):
            try:
                os.remove(local_path)
                logger.info(f"Local file cleaned up: {local_path}")
            except Exception as e:
                logger.warning(f"Failed to remove local file: {e}")


# ==================== RUN UVICORN ====================
if __name__ == "__main__":
    import uvicorn

    PORT = int(os.getenv("PORT", 8000))

    logger.info(f"Starting server on port {PORT}")
    logger.info(f"CORS origins: {origins}")
    logger.info(f"cPanel host: {CPANEL_HOST}:{CPANEL_PORT}")

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        reload=False  # Set to True only in development
    )