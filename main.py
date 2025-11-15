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
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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


# ==================== AUTH ENDPOINT ====================
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login endpoint to get JWT token"""
    if form_data.username == ADMIN_USERNAME and form_data.password == ADMIN_PASSWORD:
        token = create_jwt_token(form_data.username)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Incorrect username or password")


# ==================== SFTP UPLOAD ====================
def upload_to_cpanel(local_path: str, remote_filename: str):
    """
    Upload file to cPanel via SFTP with improved error handling

    Args:
        local_path: Local file path to upload
        remote_filename: Remote filename (without path)

    Returns:
        str: Remote file path

    Raises:
        ValueError: If upload fails
    """
    transport = None
    sftp = None

    try:
        logger.info(f"Attempting SFTP connection to {CPANEL_HOST}:{CPANEL_PORT}")

        # Create SSH transport
        transport = paramiko.Transport((CPANEL_HOST, CPANEL_PORT))
        transport.set_keepalive(30)

        # Set timeouts
        transport.banner_timeout = 30
        transport.auth_timeout = 30

        # Connect with credentials
        logger.info(f"Connecting as user: {CPANEL_USER}")
        transport.connect(
            username=CPANEL_USER,
            password=CPANEL_PASSWORD,
            hostkey=None
        )

        # Open SFTP session
        sftp = paramiko.SFTPClient.from_transport(transport)

        # Ensure remote directory exists
        remote_path = f"{UPLOAD_PATH}/{remote_filename}"
        try:
            sftp.stat(UPLOAD_PATH)
        except FileNotFoundError:
            logger.warning(f"Remote directory {UPLOAD_PATH} not found, attempting to create")
            # Try to create directory (might fail if permissions are insufficient)
            try:
                sftp.mkdir(UPLOAD_PATH)
            except Exception as e:
                logger.error(f"Could not create directory {UPLOAD_PATH}: {e}")
                raise ValueError(f"Remote directory {UPLOAD_PATH} does not exist and cannot be created")

        # Upload file
        logger.info(f"Uploading {local_path} to {remote_path}")
        sftp.put(local_path, remote_path)
        logger.info(f"File uploaded successfully to {remote_path}")

        return remote_path

    except paramiko.AuthenticationException as e:
        logger.error(f"Authentication failed: {e}")
        raise ValueError(f"SFTP authentication failed. Check username and password.")

    except paramiko.SSHException as e:
        logger.error(f"SSH connection error: {e}")
        raise ValueError(f"SFTP connection failed: {str(e)}. Check host, port, and firewall settings.")

    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        raise ValueError(f"Local file not found: {local_path}")

    except Exception as e:
        logger.error(f"Unexpected error during SFTP upload: {e}")
        raise ValueError(f"Upload failed: {str(e)}")

    finally:
        # Clean up connections
        if sftp:
            try:
                sftp.close()
            except:
                pass
        if transport:
            try:
                transport.close()
            except:
                pass


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
        response = requests.get(
            f"http://www.google.com/ping?sitemap={sitemap_url}",
            timeout=10
        )
        logger.info(f"Google pinged successfully. Status: {response.status_code}")
    except Exception as e:
        logger.warning(f"Failed to ping Google (non-critical): {e}")


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
    """
    Create a new article and upload to cPanel

    Requires valid JWT token for authentication
    """
    # Verify authentication
    verify_jwt_token(token)

    local_path = None

    try:
        logger.info(f"Creating article: {title} (slug: {slug})")

        # Render template
        template = env.get_template("article_template.html")
        html_content = template.render(
            title=title,
            slug=slug,
            category=category,
            tags=tags,
            extras=extras,
            cover_image=cover_image,
            content=content,
            created_date=datetime.utcnow().strftime("%Y-%m-%d")
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

        # Update sitemap
        file_url = f"{SITE_URL}/noutati/{filename}"
        try:
            update_sitemap(file_url)
            upload_to_cpanel(SITEMAP_FILE, "sitemap.xml")
            ping_google(f"{SITE_URL}/sitemap.xml")
        except Exception as e:
            logger.warning(f"Sitemap update failed (non-critical): {e}")
            # Don't fail the whole operation if sitemap fails

        logger.info(f"Article published successfully: {file_url}")

        return {
            "status": "success",
            "message": "Article created and published successfully",
            "file": filename,
            "url": file_url
        }

    except HTTPException:
        # Re-raise HTTP exceptions (auth, validation, etc.)
        raise

    except Exception as e:
        logger.error(f"Unexpected error creating article: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create article: {str(e)}"
        )

    finally:
        # Clean up local file
        if local_path and os.path.exists(local_path):
            try:
                os.remove(local_path)
                logger.info(f"Local file cleaned up: {local_path}")
            except Exception as e:
                logger.warning(f"Failed to remove local file: {e}")


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
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "config": {
            "cpanel_host": CPANEL_HOST,
            "cpanel_port": CPANEL_PORT,
            "site_url": SITE_URL,
            "upload_path_configured": bool(UPLOAD_PATH),
        }
    }


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