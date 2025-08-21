#!/usr/bin/env python3
"""
Test script to check FastAPI app and generate Swagger docs
"""

try:
    from app import app
    print("✅ App loaded successfully")
    print(f"OpenAPI version: {app.openapi_version}")
    print(f"Docs URL: {app.docs_url}")
    print(f"Redoc URL: {app.redoc_url}")

    # Generate OpenAPI spec
    openapi_spec = app.openapi()
    print(f"\n📊 OpenAPI Spec Generated:")
    print(f"  - Title: {openapi_spec.get('info', {}).get('title', 'N/A')}")
    print(f"  - Version: {openapi_spec.get('info', {}).get('version', 'N/A')}")
    print(f"  - Paths: {len(openapi_spec.get('paths', {}))}")

    # List all paths
    print(f"\n🔗 Available Endpoints:")
    for path, methods in openapi_spec.get('paths', {}).items():
        for method in methods.keys():
            print(f"  {method.upper()} {path}")

    print(f"\n🎯 Swagger Docs available at: http://localhost:8000/docs")
    print(f"📖 ReDoc available at: http://localhost:8000/redoc")
    print(f"📄 OpenAPI JSON available at: http://localhost:8000/openapi.json")

except Exception as e:
    print(f"❌ Error loading app: {e}")
    import traceback
    traceback.print_exc()
