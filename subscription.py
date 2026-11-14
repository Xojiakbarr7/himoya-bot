"""Membership checks fail closed and distinguish non-members from API failures."""
import asyncio
from collections import OrderedDict
import time


class SubscriptionGate:
    def __init__(self, channel: str):
        self.channel = channel
        self.bot_id = 0
        self.admin_state = (False, 0.0)
        self.cache = OrderedDict()

    async def admin_ready(self, call, force=False):
        if not self.channel:
            return True
        now = time.monotonic()
        if not force and now - self.admin_state[1] < 30:
            return self.admin_state[0]
        try:
            if not self.bot_id:
                me = await asyncio.wait_for(call("getMe", {}), timeout=8)
                self.bot_id = int(me["id"])
            member = await asyncio.wait_for(call("getChatMember", {"chat_id": self.channel, "user_id": self.bot_id}), timeout=8)
            ready = isinstance(member, dict) and member.get("status") in {"creator", "administrator"}
        except (RuntimeError, OSError, ValueError, TypeError, KeyError, asyncio.TimeoutError):
            ready = False
        self.admin_state = (ready, now)
        return ready

    async def check(self, call, owner: int, force=False):
        if not self.channel:
            return "member"
        now = time.monotonic()
        cached = self.cache.get(owner)
        if cached and not force and now - cached[1] < (60 if cached[0] == "member" else 5):
            return cached[0]
        if not await self.admin_ready(call, force=force):
            return "unavailable"
        try:
            member = await asyncio.wait_for(call("getChatMember", {"chat_id": self.channel, "user_id": owner}), timeout=8)
            if not isinstance(member, dict):
                return "unavailable"
            status = member.get("status")
            allowed = status in {"creator", "administrator", "member"} or (status == "restricted" and member.get("is_member") is True)
            if status not in {"creator", "administrator", "member", "restricted", "left", "kicked"}:
                return "unavailable"
            state = "member" if allowed else "not_member"
        except (RuntimeError, OSError, ValueError, TypeError, KeyError, asyncio.TimeoutError):
            return "unavailable"
        self.cache.pop(owner, None)
        self.cache[owner] = (state, now)
        while len(self.cache) > 10000:
            self.cache.popitem(last=False)
        return state
