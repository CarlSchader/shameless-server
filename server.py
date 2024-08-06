import os
from fastapi import FastAPI, HTTPException, UploadFile, File

from pydantic import BaseModel

from model import Log, file_bytes_to_logs
from store import LOGS_DIR, merge_logs_into_file, store_logs_locally

MAX_LOG_INPUT_FILE_SIZE: int = 1028 * 1028 * 1

app = FastAPI()

@app.get("/")
def read_root() -> str:
    return "healthy"

@app.get("/health")
def health_check() -> str:
    return "healthy"

@app.get("/logs")
def read_logs(user_id: str, limit: int = 32, offset: int = 0) -> list[Log]:
    return []

class LogsPostRequest(BaseModel):
    user_id: str
    logs: list[Log] = []

@app.post("/logs")
def write_logs(req: LogsPostRequest):
    pass
    
@app.post("/log-file")
async def ingest_log_file(user_id: str, file: UploadFile = File(...)):
    if file.content_type != "text/plain":
        raise HTTPException(400, "file content type must be text/plain")

    if file.size == None:
        raise HTTPException(400, "file size not readable")

    if file.size > MAX_LOG_INPUT_FILE_SIZE:
        raise HTTPException(400, f"file greater than maximum size: {MAX_LOG_INPUT_FILE_SIZE}")

    try:
        file_bytes = await file.read()
        new_logs: list[Log] = file_bytes_to_logs(file_bytes)
        new_logs.sort(key=lambda l: l[0])

        user_file = os.path.join(LOGS_DIR, user_id)
        if not os.path.exists(user_file):
            os.makedirs(LOGS_DIR)

        merge_logs_into_file(new_logs, user_file)
    except Exception as e:
        raise HTTPException(400, e)

