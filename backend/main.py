from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.api.health import router as health_router
from backend.services.analysis import IOC_TYPES, STATUS_OPTIONS
from backend.services.repository import (
    add_threat,
    generate_auto_feed,
    get_dashboard_context,
    get_feed_context,
    get_filtered_threats,
    get_high_risk_alerts,
    get_reports_context,
    get_threat_by_id,
    initialize_database,
    update_threat_status,
)

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="Centralized AI Threat Intelligence Dashboard")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.include_router(health_router)


@app.on_event("startup")
def startup() -> None:
    initialize_database()


@app.get("/", response_class=HTMLResponse)
def login_page(request: Request, error: Optional[str] = None):
    return templates.TemplateResponse(
        request,
        "login.html",
        {"request": request, "error": error, "page": "login"},
    )


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username == "admin" and password == "admin123":
        return RedirectResponse("/dashboard", status_code=302)
    return RedirectResponse("/?error=Invalid+credentials", status_code=302)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    search: str = Query("", alias="search"),
    ioc_type: str = Query("All", alias="type"),
    risk: str = Query("All"),
    status: str = Query("All"),
):
    context = get_dashboard_context(
        search=search,
        ioc_type=ioc_type,
        risk=risk,
        status=status,
    )
    context.update(
        {
            "request": request,
            "page": "dashboard",
            "filters": {
                "search": search,
                "type": ioc_type,
                "risk": risk,
                "status": status,
            },
            "ioc_types": ["All", *IOC_TYPES],
            "risk_options": ["All", "HIGH", "MEDIUM", "LOW"],
            "status_options": ["All", *STATUS_OPTIONS],
        }
    )
    return templates.TemplateResponse(request, "dashboard.html", context)


@app.get("/add", response_class=HTMLResponse)
def add_ioc_page(request: Request):
    return templates.TemplateResponse(
        request,
        "add_ioc.html",
        {
            "request": request,
            "page": "add",
            "ioc_types": IOC_TYPES,
            "status_options": STATUS_OPTIONS,
        },
    )


@app.post("/add")
def add_ioc(
    ioc: str = Form(...),
    ioc_type: str = Form("Auto Detect"),
    status: str = Form("Open"),
    source: str = Form("Manual Upload"),
):
    add_threat(ioc=ioc, selected_type=ioc_type, status=status, source=source)
    return RedirectResponse("/dashboard", status_code=302)


@app.get("/feed", response_class=HTMLResponse)
def feed_page(request: Request):
    context = get_feed_context()
    context.update(
        {
            "request": request,
            "page": "feed",
            "ioc_types": IOC_TYPES,
        }
    )
    return templates.TemplateResponse(request, "feed.html", context)


@app.post("/feed")
def add_feed_ioc(
    ioc: str = Form(...),
    source: str = Form("Threat Feed"),
):
    add_threat(ioc=ioc, selected_type="Auto Detect", status="Open", source=source)
    return RedirectResponse("/feed", status_code=302)


@app.post("/feed/auto")
def auto_feed(count: int = Form(8)):
    generate_auto_feed(count)
    return RedirectResponse("/feed", status_code=302)


@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(
    request: Request,
    status: str = Query("All"),
):
    alerts = get_high_risk_alerts(status=status)
    return templates.TemplateResponse(
        request,
        "alerts.html",
        {
            "request": request,
            "page": "alerts",
            "alerts": alerts,
            "status_filter": status,
            "status_options": ["All", *STATUS_OPTIONS],
            "open_count": len([alert for alert in alerts if alert["status"] == "Open"]),
            "critical_count": len([alert for alert in alerts if alert["score"] >= 85]),
        },
    )


@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request):
    context = get_reports_context()
    context.update(
        {
            "request": request,
            "page": "reports",
        }
    )
    return templates.TemplateResponse(request, "reports.html", context)


@app.get("/threats/{threat_id}", response_class=HTMLResponse)
def threat_detail_page(request: Request, threat_id: int):
    threat = get_threat_by_id(threat_id)
    if threat is None:
        raise HTTPException(status_code=404, detail="Threat not found")

    return templates.TemplateResponse(
        request,
        "threat_detail.html",
        {
            "request": request,
            "page": "alerts",
            "threat": threat,
            "related_threats": threat["related"],
            "status_options": STATUS_OPTIONS,
        },
    )


@app.post("/threats/{threat_id}/status")
def change_status(threat_id: int, status: str = Form(...), redirect_to: str = Form("/dashboard")):
    update_threat_status(threat_id, status)
    return RedirectResponse(redirect_to, status_code=302)


@app.get("/threats")
def threats_data(
    search: str = Query(""),
    ioc_type: str = Query("All", alias="type"),
    risk: str = Query("All"),
    status: str = Query("All"),
):
    return {
        "threats": get_filtered_threats(
            search=search,
            ioc_type=ioc_type,
            risk=risk,
            status=status,
        )
    }
