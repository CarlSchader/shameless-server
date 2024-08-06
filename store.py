from io import BufferedRandom
import os, fcntl
from uuid import UUID, uuid4

from model import Log, file_bytes_to_logs, logs_to_file_bytes

LOGS_DIR = os.getenv('LOGS_DIR', "./logs")

class FileMetadata:
    def __init__(
        self, start_timestamp: int, end_timestamp: int, log_count: int, identifier: UUID   
    ):
        self.start_timestamp = start_timestamp 
        self.end_timestamp = end_timestamp
        self.log_count = log_count
        self.identifier = identifier

    def to_filename(self) -> str:
        return f"{self.start_timestamp}_{self.end_timestamp}_{self.log_count}_{self.identifier}"


def file_metadata_from_filename(filename: str) -> FileMetadata:
    splits = filename.split('_')
    
    if len(splits) != 4:
        raise Exception('Filename has incorrect number of "_" delimeted sections. Should be <start>_<end>_<count>_<uuid>')

    if not splits[0].isdigit() or int(splits[0]) < 0:
        raise Exception('start timestamp must be a non-negative integer')
    start_timestamp = int(splits[0])

    if not splits[1].isdigit() or int(splits[1]) < 0:
        raise Exception('end timestamp must be a non-negative integer')
    end_timestamp = int(splits[1])

    if not splits[2].isdigit() or int(splits[2]) < 0:
        raise Exception('log count must be a non-negative integer')
    log_count = int(splits[2])

    identifier = UUID(splits[3])

    return FileMetadata(start_timestamp, end_timestamp, log_count, identifier)


def file_metadata_from_logs(logs: list[Log]) -> FileMetadata:
    if len(logs) == 0:
        raise Exception("cannot create file metadata from empty log array")
    start_timestamp = logs[0][0]
    end_timestamp = logs[0][0]
    
    for log in logs:
        if log[0] < start_timestamp:
            start_timestamp = log[0]
        if log[0] > end_timestamp:
            end_timestamp = log[0]

    return FileMetadata(start_timestamp, end_timestamp, len(logs), uuid4())


# user_id -> file_metadata
# sorted by end_timestamp
local_log_store_table: dict[str, list[FileMetadata]] = {}


def tail(f: BufferedRandom, lines: int=32) -> list[str]:
    found_lines: list[str] = []
    chunks = 0
    while len(found_lines) < lines:
        BUFFER_SIZE = 1024
        f.seek(BUFFER_SIZE, 2)
        byte_buffer = f.read(BUFFER_SIZE)
        byte_buffer.split(b'\n')
        

        


def find_user_file_metadata(user_id: str) -> list[FileMetadata]:
    user_dir = os.path.join(LOGS_DIR, user_id)
    if not os.path.isdir(user_dir):
        return []
    
    array = [file_metadata_from_filename(filename) for filename in os.listdir(user_dir)]
    array.sort(key=lambda m: m.end_timestamp)
    return array


def merge_logs_into_file(logs: list[Log], filename: str):
    with open(filename, 'rb+') as f:
        fcntl.lockf(f, fcntl.LOCK_EX)
        file_logs = file_bytes_to_logs(f.read())
        
        merged_logs = []
        i, j = 0, 0
        while i < len(logs) and j < len(merged_logs):
            if logs[i] < file_logs[j]:
                merged_logs.append(logs[i])
                i += 1
            else:
                merged_logs.append(file_logs[j])
                j += 1

        if i < len(logs):
            merged_logs += logs[i:]
        elif j < len(file_logs):
            merged_logs += file_logs[j:]

        f.seek(0)
        file_bytes = logs_to_file_bytes(merged_logs)
        f.write(file_bytes)
        f.truncate()
        fcntl.lockf(f, fcntl.LOCK_UN)


def store_logs_locally(user_id: str, logs: list[Log]):
    user_dir = os.path.join(LOGS_DIR, user_id)
    if not os.path.isdir(user_dir):
        os.makedirs(user_dir)

    metadata = file_metadata_from_logs(logs)
    file_bytes = logs_to_file_bytes(logs)

    with open(os.path.join(user_dir, metadata.to_filename()), 'wb') as f:
        f.write(file_bytes)

    if user_id not in local_log_store_table:
        # encrich log_store_table with user info
        pass

    new_metadata_list = local_log_store_table.get(user_id, [])
    new_metadata_list.append(metadata)
    new_metadata_list.sort(key=lambda m: m.end_timestamp)
    local_log_store_table[user_id] = new_metadata_list

def read_log_file_locally(file_name: str) -> list[Log]:
    with open(file_name, 'rb') as f:
        file_bytes = f.read()
    return file_bytes_to_logs(file_bytes)

# def top(user_id: str, limit: int = 32, offset: int = 0):
     

