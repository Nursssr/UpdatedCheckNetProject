from typing import Any
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import httpx
import asyncio
import ssl
import aiosmtplib
import aioimaplib
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class CheckRequestHTTP(BaseModel):
    type: str = "HTTP"
    address: str
    port: int
    timeout: float = 5.0
    method: str = "GET" #POST, PUT, PATCH, DELETE, HEAD, OPTIONS
    ssl: bool = False

class CheckRequestIMAP(BaseModel):
    type: str = "IMAP"
    host: str
    port: int
    ssl: bool = True
    timeout: float = 5.0
    username: str | None = None
    password: str | None = None

class CheckRequestSMTP(BaseModel):
    type: str = "SMTP"
    host: str
    port: int
    timeout: float = 5.0
    use_tls: bool = False
    start_tls: bool = False
    validate_certs: bool = True
    username: str | None = None
    password: str | None = None


@app.post("/check")
async def check_connection(data: dict[str, Any]):
    type_ = data.get("type", "HTTP").upper()

    if type_ == "HTTP":
        req = CheckRequestHTTP(**data)
        return await handle_http(req)

    if type_ == "IMAP":
        req = CheckRequestIMAP(**data)
        return await handle_imap(req)

    if type_ == "SMTP":
        req = CheckRequestSMTP(**data)
        return await handle_smtp(req)

    return {"status": "fail", "error": f"Unsupported type {type_}"}


async def handle_http(data: CheckRequestHTTP):
    protocol = "https" if (data.port == 443 or data.ssl) else "http"
    url = f"{protocol}://{data.address}:{data.port}"
    try:
        async with httpx.AsyncClient(timeout=data.timeout) as client:
            response = await client.request(data.method.upper(), url)
        return {
            "status": "success",
            "protocol": protocol,
            "type": data.type,
            "code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text
        }
    except Exception as e:
        return {"status": "fail", "type": data.type, "error": str(e)}


async def handle_imap(data: CheckRequestIMAP):
    try:
        if data.ssl:
            client = aioimaplib.IMAP4_SSL(host=data.host, port=data.port)
        else:
            client = aioimaplib.IMAP4(host=data.host, port=data.port)

        await asyncio.wait_for(client.wait_hello_from_server(), timeout=data.timeout)

        if data.username and data.password:
            await asyncio.wait_for(client.login(data.username, data.password), timeout=data.timeout)

        try:
            await asyncio.wait_for(client.logout(), timeout=data.timeout)
        except Exception:
            pass

        return {
            "status": "success",
            "type": data.type,
            "protocol": "imap" + ("s" if data.ssl else ""),
            "message": "IMAP connected!"
        }

    except Exception as e:
        return {"status": "fail", "type": data.type, "error": str(e)}


async def handle_smtp(data: CheckRequestSMTP):
    if data.use_tls and data.start_tls:
        return {
            "status": "fail",
            "type": data.type,
            "error": "Нельзя одновременно use_tls=True и start_tls=True. Выберите один режим.",
        }

    tls_ctx = ssl.create_default_context()
    if not data.validate_certs:
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = ssl.CERT_NONE

    try:
        smtp = aiosmtplib.SMTP(
            hostname=data.host,
            port=data.port,
            use_tls=data.use_tls,
            timeout=data.timeout,
        )

        code, msg = await smtp.connect(tls_context=tls_ctx)

        if data.start_tls:
            await smtp.starttls(tls_context=tls_ctx)

        if data.username and data.password:
            await smtp.login(data.username, data.password)

        await smtp.quit()

        return {
            "status": "success",
            "type": data.type,
            "protocol": "smtp",
            "greeting_code": code,
            "greeting_message": msg.decode("utf-8", errors="ignore") if isinstance(msg, (bytes, bytearray)) else str(msg),
            "mode": "SMTPS" if data.use_tls else ("SMTP+STARTTLS" if data.start_tls else "PLAIN"),
            "validate_certs": data.validate_certs,
        }

    except Exception as e:
        return {"status": "fail", "type": data.type, "error": str(e)}