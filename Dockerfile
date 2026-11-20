FROM python:3.13-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.11.7 /uv /usr/local/bin/uv
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project \
    && useradd --uid 10001 --create-home study \
    && mkdir -p /data/workspaces /data/snapshots /data/results \
    && chown -R study:study /data
COPY agents/ agents/
COPY api/ api/
COPY models/ models/
COPY schemas/ schemas/
COPY services/ services/
COPY content/ content/
COPY starter/ starter/
COPY assessment/security_tests/ assessment/security_tests/
COPY migrations/ migrations/
COPY alembic.ini config.py db.py llm.py main.py export.py analyze_results.py assess_submissions.py withdraw.py ./
USER study
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips", "*"]
