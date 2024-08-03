from fastapi import FastAPI, HTTPException, UploadFile, File

from pydantic import BaseModel

from log_cache import cache_sorted_encrypted_logs, get_cached_encrypted_logs
from model import EncryptedLog

MAX_LOG_INPUT_FILE_SIZE: int = 1028 * 1028 * 1

app = FastAPI()

@app.get("/")
def read_root() -> str:
    return "healthy"

@app.get("/health")
def health_check() -> str:
    return "healthy"

@app.get("/logs")
def read_logs(user_id: str, limit: int = 256, offset: int = 0) -> list[EncryptedLog]:
    return get_cached_encrypted_logs(cache_key=user_id, limit=limit, offset=offset)

class LogsPostRequest(BaseModel):
    user_id: str
    encrypted_logs: list[EncryptedLog] = []

@app.post("/logs")
def write_logs(req: LogsPostRequest):
    cache_sorted_encrypted_logs(cache_key=req.user_id, encrypted_logs=req.encrypted_logs)
    
@app.post("/log-file")
async def ingest_log_file(user_id: str, file: UploadFile = File(...)):
    if file.content_type != "text/plain":
        raise HTTPException(400, "file content type must be text/plain")

    if file.size == None:
        raise HTTPException(400, "file size not readable")

    if file.size > MAX_LOG_INPUT_FILE_SIZE:
        raise HTTPException(400, f"file greater than maximum size: {MAX_LOG_INPUT_FILE_SIZE}")

    lines = (await file.read()).decode('utf-8').strip().split('\n')
    
    if not lines[0].isdigit():
        raise HTTPException(400, "start date must be integer")
    
    start_date = int(lines[0])
    if start_date < 0:
        raise HTTPException(400, "start date must be positive") 

    if not lines[1].isdigit():
        raise HTTPException(400, "end date must be integer")

    end_date = int(lines[1])
    if end_date < 1:
        raise HTTPException(400, "end date must be positive")

    if not lines[2].isdigit():
        raise HTTPException(400, "log count must be integer")

    log_count = int(lines[2])
    if log_count < 2:
        raise HTTPException(400, "log count must be positive")

    log_lines = lines[3:]
    if log_count != len(log_lines):
        raise HTTPException(400, "log count does not match the number of logs in the file")

    new_logs: list[EncryptedLog] = []
    i = 0
    for line in log_lines:
        splits = line.split(' ')
        if len(splits) != 2:
            raise HTTPException(400, f"log number {i}: {line} -- has incorrect number ({2}) of words")

        timestamp_string = splits[0]
        encrypted_payload = splits[1]

        if not timestamp_string.isdigit():
            raise HTTPException(400, f"log number {i}: {line} -- has non-integer timestamp")

        timestamp = int(timestamp_string)
        if timestamp < 0:
            raise HTTPException(400, f"log number {i}: {line} -- has negative timestamp")

        encrypted_bytes = encrypted_payload.encode('utf-8')
        new_logs.append((timestamp, encrypted_bytes))

    new_logs.sort(key=lambda l: l[0])
    cache_sorted_encrypted_logs(user_id, new_logs)

