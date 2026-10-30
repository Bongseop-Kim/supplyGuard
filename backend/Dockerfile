# 의존성만 담은 이미지. 소스는 compose가 저장소를 같은 절대 경로로 마운트해서 쓴다
# (스캐너 컨테이너를 docker.sock으로 띄울 때 호스트 경로가 그대로 맞아야 하므로)
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ripgrep git && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.8.5 /uv /bin/uv
WORKDIR /deps
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
ENV PATH=/deps/.venv/bin:$PATH PYTHONUNBUFFERED=1
