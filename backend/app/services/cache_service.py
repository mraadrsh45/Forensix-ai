import json
import logging
import urllib.request
import urllib.parse
from typing import Optional, Dict, Any
from app.config import settings

logger = logging.getLogger(__name__)

class UpstashRedisCacheService:
    def __init__(self):
        self.redis_client = None
        self._in_memory_cache: Dict[str, str] = {}
        self.rest_url = getattr(settings, "UPSTASH_REDIS_REST_URL", "")
        self.rest_token = getattr(settings, "UPSTASH_REDIS_REST_TOKEN", "")

        if settings.REDIS_URL:
            try:
                import redis
                self.redis_client = redis.from_url(
                    settings.REDIS_URL,
                    decode_responses=True,
                    socket_connect_timeout=3
                )
                self.redis_client.ping()
                logger.info("Upstash Redis cloud cache connected via TCP.")
            except Exception as e:
                logger.warning(f"Upstash Redis TCP fallback mode: {e}")
                self.redis_client = None

    def _rest_request(self, command: str, *args) -> Optional[Any]:
        if not self.rest_url or not self.rest_token:
            return None
        try:
            cmd_path = "/".join([command] + [urllib.parse.quote(str(a), safe="") for a in args])
            url = f"{self.rest_url.rstrip('/')}/{cmd_path}"
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.rest_token}"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode())
                return data.get("result")
        except Exception as e:
            logger.error(f"Upstash REST request error: {e}")
            return None

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        prefix_key = f"forensix:cache:{key}"
        if self.redis_client:
            try:
                data = self.redis_client.get(prefix_key)
                if data:
                    return json.loads(data)
            except Exception as e:
                logger.error(f"Redis get error: {e}")

        # REST fallback
        if self.rest_url and self.rest_token:
            res = self._rest_request("get", prefix_key)
            if res:
                try:
                    return json.loads(res)
                except Exception:
                    return None

        # Memory fallback
        if prefix_key in self._in_memory_cache:
            return json.loads(self._in_memory_cache[prefix_key])
        return None

    def set(self, key: str, value: Dict[str, Any], ttl: int = 3600) -> bool:
        prefix_key = f"forensix:cache:{key}"
        json_val = json.dumps(value)
        self._in_memory_cache[prefix_key] = json_val

        if self.redis_client:
            try:
                self.redis_client.setex(prefix_key, ttl, json_val)
                return True
            except Exception as e:
                logger.error(f"Redis set error: {e}")

        if self.rest_url and self.rest_token:
            self._rest_request("setex", prefix_key, ttl, json_val)

        return True

    def delete(self, key: str) -> bool:
        prefix_key = f"forensix:cache:{key}"
        if prefix_key in self._in_memory_cache:
            del self._in_memory_cache[prefix_key]

        if self.redis_client:
            try:
                self.redis_client.delete(prefix_key)
            except Exception as e:
                logger.error(f"Redis delete error: {e}")

        if self.rest_url and self.rest_token:
            self._rest_request("del", prefix_key)

        return True

cache_service = UpstashRedisCacheService()
