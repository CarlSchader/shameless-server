Log = tuple[int, bytes]

def sort_logs(logs: list[Log]) -> list[Log]:
    logs.sort(key=lambda m: m[0])
    return logs

def log_from_line(line: str) -> Log:
    if len(line) == 0:
        raise Exception("line is empty")

    first_space = line.find(' ')
    timestamp_string: str = ""
    payload: bytes = b'' 
    if first_space < 1: # empty payload case
        timestamp_string = line
    else: # timestamp and payload
        if first_space == 0:
            raise Exception(f"line can't start with space -- {line}")
        
        timestamp_string = line[:first_space]
        payload = line[first_space+1:].encode('utf-8')

    if not timestamp_string.isdigit():
        raise Exception(f"non-integer timestamp -- {line}")

    timestamp = int(timestamp_string)
    if timestamp < 0:
        raise Exception(f"negative timestamp -- {line}")

    return (timestamp, payload)

def line_from_log(log: Log) -> str:
    return f"{log[0]} {log[1].decode('utf-8')}"

def file_bytes_to_logs(file_bytes: bytes) -> list[Log]:
    lines = (file_bytes).decode('utf-8').strip().split('\n')
    
    if not lines[0].isdigit():
        raise Exception("start date must be integer")
    
    start_timestamp = int(lines[0])
    if start_timestamp < 0:
        raise Exception("start date must be positive") 

    if not lines[1].isdigit():
        raise Exception("end date must be integer")

    end_timestamp = int(lines[1])
    if end_timestamp < 1:
        raise Exception("end date must be positive")

    if not lines[2].isdigit():
        raise Exception("log count must be integer")

    log_count = int(lines[2])
    if log_count < 2:
        raise Exception("log count must be positive")

    log_lines = lines[3:]
    if log_count != len(log_lines):
        raise Exception("log count does not match the number of logs in the file")

    return [log_from_line(line) for line in log_lines]
    
def is_sorted(logs: list[Log]) -> bool:
    """untested"""
    if len(logs) == 0:
        return True

    last_timestamp = logs[0][0]
    for log in logs:
        if log[0] < last_timestamp:
            return False
    return True

def logs_to_file_bytes(logs: list[Log]) -> bytes:
    if len(logs) == 0:
        raise Exception("logs list cannot be empty")
    
    start_timestamp: int = logs[0][0]
    end_timestamp: int = logs[0][0]
    log_count = len(logs)
    
    file_body_string = ""
    for log in logs:
        if log[0] < start_timestamp:
            start_timestamp = log[0]
        if log[0] > end_timestamp:
            end_timestamp = log[0]
        file_body_string += ('\n' + line_from_log(log))

    log_file_string = str(start_timestamp)
    log_file_string += ('\n' + str(end_timestamp))
    log_file_string += ('\n' + str(log_count))
    log_file_string += file_body_string
    
    return log_file_string.strip().encode('utf-8')
