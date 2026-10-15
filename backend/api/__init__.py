from __future__ import annotations

import os

from flask import Flask, jsonify, request

from backend.api.common import ApiError
from backend.bootstrap import bootstrap
from backend.config import Config
from backend.db import remove_session
from backend.tenancy import current, reset


def create_app(cfg: Config | None = None, *, init: bool = True) -> Flask:
    cfg = cfg or Config.from_env()
    app = Flask(__name__)
    app.config["MSP"] = cfg
    app.config["MAX_CONTENT_LENGTH"] = 1_000_000
    if init:
        bootstrap(cfg)
    if os.environ.get("MSP_FAKE_CONNECTORS") == "1":
        if cfg.env == "production":
            raise RuntimeError("MSP_FAKE_CONNECTORS must not be enabled in production")
        from backend.connectors.base import set_connector_factory
        from backend.connectors.fake import FakeHost, FakeInfrastructure
        infra = FakeInfrastructure(auto=True)
        infra.hosts["demo-web.example"] = FakeHost(services={"nginx.service": "failed", "asterisk": "active"}, disk_pct=91)
        set_connector_factory(infra.factory)

    from backend.api import admin, inventory, tasks, webhooks
    for m in (admin, inventory, tasks, webhooks):
        app.register_blueprint(m.bp)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.errorhandler(ApiError)
    def _api_error(e: ApiError):
        return jsonify(error=e.message), e.status

    @app.errorhandler(404)
    def _404(_):
        return jsonify(error="not found"), 404

    @app.errorhandler(405)
    def _405(_):
        return jsonify(error="method not allowed"), 405

    @app.errorhandler(Exception)
    def _500(e):
        app.logger.exception("unhandled error")
        return jsonify(error="internal error"), 500

    @app.after_request
    def _headers(resp):
        resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                             "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
                             "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"})
        origin = request.headers.get("Origin")
        if origin and origin in cfg.cors_origins:
            resp.headers.update({"Access-Control-Allow-Origin": origin, "Vary": "Origin",
                                 "Access-Control-Allow-Headers": "Authorization, Content-Type",
                                 "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS"})
        return resp

    @app.teardown_request
    def _cleanup(_exc):
        from flask import g
        tok = g.pop("tenant_token", None)
        if tok is not None:
            reset(tok)
        remove_session()

    return app
