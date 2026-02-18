"""
Celery tasks for async network operations.
"""

from celery import shared_task
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def health_check(self, device_name: str):
    """Run health check on a single device."""
    try:
        # Import here to avoid circular imports
        from network_mcp_async import health_check as sync_health_check
        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(sync_health_check(device_name))
            return result
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"Health check failed for {device_name}: {e}")
        raise self.retry(exc=e)


@shared_task(bind=True, max_retries=2)
def send_command(self, device_name: str, command: str):
    """Send a show command to a device."""
    try:
        from network_mcp_async import send_command as sync_send_command
        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(sync_send_command(device_name, command))
            return result
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"Command failed on {device_name}: {e}")
        raise self.retry(exc=e)


@shared_task(bind=True, max_retries=1)
def send_config(self, device_name: str, commands: str):
    """Send configuration commands to a device."""
    try:
        from network_mcp_async import send_config as sync_send_config
        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(sync_send_config(device_name, commands))
            return result
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"Config failed on {device_name}: {e}")
        raise


@shared_task
def scheduled_health_check():
    """Periodic health check of all devices."""
    try:
        from network_mcp_async import health_check_all
        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(health_check_all())
            logger.info(f"Scheduled health check complete: {result.get('summary', {})}")
            return result
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"Scheduled health check failed: {e}")
        return {"error": str(e)}


@shared_task
def bulk_command(device_names: list, command: str):
    """Run same command on multiple devices."""
    results = {}
    for device in device_names:
        try:
            result = send_command.delay(device, command)
            results[device] = {"task_id": result.id, "status": "queued"}
        except Exception as e:
            results[device] = {"error": str(e)}
    return results
