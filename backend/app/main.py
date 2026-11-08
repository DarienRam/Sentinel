from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from app.api import auth_router, scans_router
from app.api.anonymous import router as anonymous_router
from app.core.config import settings
from app.core.database import init_db
from app.core.response_headers import PrivateResponseHeadersMiddleware
from app.core.resource_protection import ResourceProtectionMiddleware, security_error
from app.core.security_store import BudgetExceeded, SecurityUnavailable, create_security_store


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail closed before touching any database if required security state is absent.
    store = create_security_store(settings)
    app.state.security_store = store
    try:
        try:
            init_db()
        except SQLAlchemyError:
            raise RuntimeError("Database startup unavailable; connection details are suppressed.") from None
        yield
    finally:
        store.close()


app = FastAPI(title="Sentinel API", lifespan=lifespan)


@app.exception_handler(HTTPException)
async def http_error_response(request: Request, exc: HTTPException):
    response = JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers)
    if (exc.status_code == 401 and exc.detail == "Invalid or expired authentication token."
            and not request.headers.get("authorization")):
        from app.core.account_sessions import clear_account_cookie
        clear_account_cookie(response)
    return response



@app.exception_handler(BudgetExceeded)
@app.exception_handler(SecurityUnavailable)
async def security_failure(request: Request, exc: Exception):
    return security_error(exc)


@app.exception_handler(RequestValidationError)
async def validation_error_response(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    # Pydantic's raw input/context can contain passwords, private scan text or
    # invalid Unicode that cannot be serialized into the response. Keep only
    # the stable, actionable error fields, never the submitted value.
    details = [
        {key: error[key] for key in ("type", "loc", "msg") if key in error}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": details})

app.add_middleware(ResourceProtectionMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.frontend_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Retry-After"],
)

app.add_middleware(PrivateResponseHeadersMiddleware)

app.include_router(auth_router)
app.include_router(anonymous_router)
app.include_router(scans_router)


@app.get("/")
def read_root() -> dict[str, str]:
    return {"message": "Sentinel backend is running."}


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}
