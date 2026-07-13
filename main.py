from contextlib import asynccontextmanager

from fastapi import FastAPI

from schemas import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="AegisPAM", version="0", lifespan=lifespan)


@app.get("/health")
def health() -> dict:
    return {"ok": True}
