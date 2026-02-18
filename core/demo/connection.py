"""
Mock async SSH connection for demo mode.

Provides DemoConnection and DemoResponse classes that duck-type
Scrapli's async driver and Response objects so callers do not need
to distinguish between real and simulated connections.
"""

from __future__ import annotations

from core.demo.device_simulator import DemoDeviceManager


class DemoResponse:
    """Mock Scrapli Response."""

    def __init__(
        self, result: str = "", failed: bool = False, channel_input: str = ""
    ):
        self.result = result
        self.failed = failed
        self.channel_input = channel_input

    def __repr__(self) -> str:
        status = "FAIL" if self.failed else "OK"
        return f"<DemoResponse {status} cmd={self.channel_input!r}>"


class DemoConnection:
    """Mock async SSH connection for demo mode.

    Implements the same interface as Scrapli's AsyncIOSXEDriver so it can
    be used as a drop-in replacement via ``get_ios_xe_connection()`` and
    the connection pool.
    """

    def __init__(self, device_name: str):
        self.device_name = device_name
        self._manager = DemoDeviceManager()

    # -- async context manager -------------------------------------------

    async def __aenter__(self) -> DemoConnection:
        return self

    async def __aexit__(self, *args: object) -> None:
        pass

    # -- command methods -------------------------------------------------

    async def send_command(self, command: str, **kwargs: object) -> DemoResponse:
        """Send a single command and return a DemoResponse."""
        result = self._manager.handle_command(self.device_name, command)
        return DemoResponse(result=result, channel_input=command)

    async def send_commands(
        self, commands: list[str], **kwargs: object
    ) -> list[DemoResponse]:
        """Send multiple commands sequentially."""
        return [await self.send_command(cmd) for cmd in commands]

    async def send_configs(
        self, configs: list[str], **kwargs: object
    ) -> DemoResponse:
        """Send configuration commands."""
        result = self._manager.handle_config(self.device_name, configs)
        return DemoResponse(result=result)

    async def send_config(
        self, config: str, **kwargs: object
    ) -> DemoResponse:
        """Send a single configuration command."""
        return await self.send_configs([config])

    # -- lifecycle methods -----------------------------------------------

    def isalive(self) -> bool:
        """Always alive — there is no real transport."""
        return True

    async def open(self) -> None:
        """No-op — nothing to open."""
        pass

    async def close(self) -> None:
        """No-op — nothing to close."""
        pass
