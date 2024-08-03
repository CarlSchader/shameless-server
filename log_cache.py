from model import EncryptedLog

log_cache: dict[str, list[EncryptedLog]] = {}

def cache_sorted_encrypted_logs(cache_key: str, encrypted_logs: list[EncryptedLog]) -> None:
    cached_encrypted_logs: list[EncryptedLog] = log_cache.get(cache_key, [])
    new_encrypted_logs = []

    i, j = 0, 0
    while i < len(encrypted_logs) and j < len(cached_encrypted_logs):
        if encrypted_logs[i] < cached_encrypted_logs[j]:
            new_encrypted_logs.append(encrypted_logs[i])
            i += 1
        else:
            new_encrypted_logs.append(cached_encrypted_logs[j])
            j += 1

    if i < len(encrypted_logs):
        new_encrypted_logs += encrypted_logs[i:]
    
    if j < len(cached_encrypted_logs):
        new_encrypted_logs += cached_encrypted_logs[j:]
    
    log_cache[cache_key] = new_encrypted_logs


def get_cached_encrypted_logs(cache_key: str, limit: int = 256, offset: int = 0) -> list[EncryptedLog]:
    return log_cache.get(cache_key, [])[offset:limit]
    
