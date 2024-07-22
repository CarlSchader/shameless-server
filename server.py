from uuid import UUID, uuid4
import time
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException, Request
import os
import sys
import logging
import ndjson

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger()

LOG_FILE_PATH = os.getenv('LOG_FILE_PATH', './log.ndjson')


class Log(BaseModel):
    id: UUID = uuid4()
    timestamp: float = time.time() 
    text: str | None = None


app = FastAPI()


@app.get("/")
def read_root(req: Request) -> str:
    ip = ""
    if req.client:
        ip = req.client.host
    logger.info(f"healthcheck from {ip}")
    return "healthy"


@app.post("/log")
def write_log(log: Log) -> None:
    logger.debug(f"POST /log {log}")
    try:
        with open(LOG_FILE_PATH, 'w') as f:
            writer = ndjson.writer(f)
            writer.writerow(log.model_dump_json())
    except Exception as e:
        logger.error(e)
        raise HTTPException(500)


@app.get("/logs")
def read_log(limit: int = 100, offset: int = 0) -> list[Log]:
    res: list[Log] = []
    try:
        with open(LOG_FILE_PATH) as f:
            reader = ndjson.reader(f)
            i = 0
            for row in reader:
                if i < offset:
                    continue
                elif i >= limit:
                    break
                else:
                    res.append(Log.model_validate_json(row))
    except Exception as e:
        logger.error(e)
        raise HTTPException(500)

    logger.info(res)
    return res
