from typing import AsyncIterable,Iterable,List,Optional
import asyncio
import time
from config import SCAN_RATE_LIMIT,BATCH_SIZE  # 新增配置SCAN_RATE_LIMIT


class RateLimiter:
    #令牌桶速率限制器
    def __init__(self, rate_per_sec):
        self.rate = rate_per_sec # 令牌生成速率
        self.tokens = 0 # 当前令牌数
        self.last_update = time.time() #最后更新时间

    async def acquire(self, count=1):
        #获取令牌（count为包数）
        now = time.time()
        # 计算新增令牌
        self.tokens += (now - self.last_update) * self.rate
        self.tokens = min(self.tokens, self.rate * 2)  # 桶容量上限
        self.last_update = now

        # 检查是否需等待
        if self.tokens < count:
            deficit = count - self.tokens
            await asyncio.sleep(deficit / self.rate)
            self.tokens = 0
        else:
            self.tokens -= count


# 全局速率限制器实例对象
global_limiter = RateLimiter(SCAN_RATE_LIMIT)

async def batch_scheduler(ip_iter : Iterable[str],
                                custom_batch_size:Optional[int] = None) -> AsyncIterable[List[str]]:
    ip_list: List[str] = []
    batch_size = custom_batch_size or BATCH_SIZE
    for ip in ip_iter:
        ip_list.append(ip)
        if len(ip_list) >= batch_size:
            yield  ip_list
            print("scheduler已完成=========================")
            print("scheduler已完成=========================")
            ip_list =[]
    if ip_list:
        print("scheduler已完成=========================")
        print("scheduler已完成=========================")
        yield  ip_list

