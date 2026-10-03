"""Supported Uvicorn entry point; assets stay outside the installed package."""

from gpt_rag_ui.config.resources import configure_asset_root

configure_asset_root(__file__)

from gpt_rag_ui.bootstrap import AuthState as AuthState, app as app, build_app as build_app
