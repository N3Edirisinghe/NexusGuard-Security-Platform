import time
import redis
from fastapi import Request, HTTPException
from starlette.responses import JSONResponse

class RedisRateLimiter:
    def __init__(self, redis_url: str = "redis://localhost:6379", window: int = 60, limit: int = 100):
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.window = window
        self.limit = limit

    async def is_allowed(self, client_id: str) -> bool:
        try:
            now = time.time()
            key = f"rate_limit:{client_id}"
            
            # Sliding window implementation using Sorted Set
            pipeline = self.redis.pipeline()
            
            # Remove old requests
            pipeline.zremrangebyscore(key, 0, now - self.window)
            # Add current request
            pipeline.zadd(key, {str(now): now})
            # Count requests in current window
            pipeline.zcard(key)
            # Set expiration for the key
            pipeline.expire(key, self.window)
            
            results = pipeline.execute()
            count = results[2]
            
            return count <= self.limit
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
            # FAIL-OPEN: Allow request if Redis is down, but log the error
            print(f"RATE LIMITER FAIL-OPEN: Redis connection failed: {e}")
            return True

class RateLimitMiddleware:
    def __init__(self, app, redis_url: str = "redis://localhost:6379", window: int = 60, limit: int = 5):
        self.app = app
        self.limiter = RedisRateLimiter(redis_url, window, limit)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        client_ip = request.client.host
        
        if not await self.limiter.is_allowed(client_ip):
            response = JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "message": f"Rate limit exceeded. Max {self.limiter.limit} requests per {self.limiter.window}s."
                }
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)
