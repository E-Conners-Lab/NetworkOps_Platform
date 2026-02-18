import discord
from discord.ext import commands
import os
import aiohttp
from dotenv import load_dotenv

load_dotenv()

# Bot configuration
API_URL = os.getenv("API_URL", "http://localhost:5001")


def _get_discord_token():
    """Get Discord bot token via SecretsManager (Vault -> env fallback)."""
    from config.vault_client import get_api_key
    return get_api_key("discord")
ADMIN_ROLE = "Network Admin"  # Role required for admin commands

# Set up bot with intents
intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)

def is_admin():
    """Check if user has Network Admin role"""
    async def predicate(ctx):
        if isinstance(ctx.channel, discord.DMChannel):
            return False
        role = discord.utils.get(ctx.author.roles, name=ADMIN_ROLE)
        return role is not None
    return commands.check(predicate)

async def api_get(endpoint: str) -> dict:
    """Mke GET request to API"""
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{API_URL}{endpoint}") as response:
            return await response.json()


async def api_post(endpoint: str, data: dict) -> dict:
    """Make POST request to API"""
    async with aiohttp.ClientSession() as session:
        async with session.post(f"{API_URL}{endpoint}", json=data) as response:
            return await response.json()


@bot.event
async def on_ready():
    print(f"Bot connected as {bot.user}")
    print(f"API URL: {API_URL}")


@bot.command(name="devices")
async def list_devices(ctx):
    """List all network devices"""
    try:
        data = await api_get("/api/devices")
        device_list = "\n".join([f"• {d}" for d in data])
        await ctx.send(f"**Network Devices ({len(data)}):**\n{device_list}")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")


@bot.command(name="health")
async def health_check(ctx, device: str = None):
    """Check device health. Usage: !health R1 or !health all"""
    if not device:
        await ctx.send("Usage: `!health <device>` or `!health all`")
        return

    await ctx.send(f"🔍 Checking health...")

    try:
        data = await api_get("/api/topology")
        nodes = data.get("nodes", [])

        if device.lower() == "all":
            # Summary of all devices
            healthy = sum(1 for n in nodes if n["status"] == "healthy")
            degraded = sum(1 for n in nodes if n["status"] == "degraded")
            critical = sum(1 for n in nodes if n["status"] == "critical")

            msg = f"**Network Health Summary:**\n"
            msg += f"🟢 Healthy: {healthy}\n"
            msg += f"🟡 Degraded: {degraded}\n"
            msg += f"🔴 Critical: {critical}\n"
            msg += f"**Total: {len(nodes)} devices**"
            await ctx.send(msg)
        else:
            # Single device
            node = next((n for n in nodes if n["id"].lower() == device.lower()), None)
            if node:
                status_emoji = "🟢" if node["status"] == "healthy" else "🟡" if node["status"] == "degraded" else "🔴"
                msg = f"**{node['id']}** {status_emoji}\n"
                msg += f"• IP: {node.get('ip', 'N/A')}\n"
                msg += f"• Platform: {node.get('platform', 'N/A')}\n"
                msg += f"• Status: {node['status']}"
                await ctx.send(msg)
            else:
                await ctx.send(f"❌ Device '{device}' not found")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")


@bot.command(name="bgp")
async def bgp_status(ctx, device: str = None):
    """Show BGP neighbors. Usage: !bgp R1"""
    if not device:
        await ctx.send("Usage: `!bgp <device>`")
        return

    await ctx.send(f"🔍 Checking BGP on {device}...")

    try:
        data = await api_get(f"/api/bgp-summary?device={device}")

        if data.get("status") == "success":
            neighbors = data.get("neighbors", [])
            if neighbors:
                msg = f"**BGP Neighbors on {device}:**\n"
                for n in neighbors:
                    state_emoji = "🟢" if n["state"] == "Established" else "🔴"
                    msg += f"{state_emoji} {n['neighbor']} - AS {n.get('remote_as', 'N/A')} - {n['state']}\n"
                await ctx.send(msg)
            else:
                await ctx.send(f"No BGP neighbors found on {device}")
        else:
            await ctx.send(f"❌ Error: {data.get('error', 'Unknown error')}")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")


@bot.command(name="ping")
async def ping_device(ctx, device: str = None, target: str = None):
    """Ping from a device. Usage: !ping R1 8.8.8.8"""
    if not device or not target:
        await ctx.send("Usage: `!ping <device> <target>`")
        return

    await ctx.send(f"🏓 Pinging {target} from {device}...")

    try:
        data = await api_post("/api/ping", {
            "device": device,
            "destination": target,
            "count": 5,
            "role": "operator"
        })

        if data.get("status") == "success":
            rate = data.get("success_rate", "unknown")
            emoji = "✅" if rate == "100%" else "⚠️" if rate != "0%" else "❌"
            await ctx.send(f"{emoji} **{device} → {target}:** {rate} success")
        else:
            await ctx.send(f"❌ Error: {data.get('error', 'Unknown error')}")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")


@bot.command(name="events")
async def show_events(ctx, limit: int = 5):
    """Show recent events. Usage: !events or !events 10"""
    try:
        data = await api_get(f"/api/events?limit={limit}")
        events = data.get("events", [])

        if events:
            msg = f"**Recent Events ({len(events)}):**\n"
            for e in events:
                timestamp = e["timestamp"].split("T")[1].split(".")[0]  # HH:MM:SS
                device = e.get("device") or "system"
                msg += f"`{timestamp}` **{e['action']}** on {device}\n"
            await ctx.send(msg)
        else:
            await ctx.send("No events recorded yet.")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")


@bot.command(name="topology")
async def topology_summary(ctx):
    """Show network topology summary"""
    try:
        data = await api_get("/api/topology")
        nodes = data.get("nodes", [])
        links = data.get("links", [])

        routers = sum(1 for n in nodes if not n["id"].lower().startswith("switch") and n.get("platform") != "Linux")
        switches = sum(1 for n in nodes if n["id"].lower().startswith("switch"))
        hosts = sum(1 for n in nodes if n.get("platform") == "Linux")

        msg = f"**Network Topology:**\n"
        msg += f"• Routers: {routers}\n"
        msg += f"• Switches: {switches}\n"
        msg += f"• Hosts: {hosts}\n"
        msg += f"• Links: {len(links)}\n"
        msg += f"**Total: {len(nodes)} devices**"
        await ctx.send(msg)
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")


@bot.command(name="run")
@is_admin()
async def run_command(ctx, device: str = None, *, command: str = None):
    """Run a command on a device (Admin only). Usage: !run R1 show ip route"""
    if not device or not command:
        await ctx.send("Usage: `!run <device> <command>`")
        return

    await ctx.send(f"⚙️ Running `{command}` on {device}...")

    try:
        data = await api_post("/api/command", {
            "device": device,
            "command": command,
            "role": "admin"
        })

        if data.get("status") == "success":
            output = data.get("output", "No output")
            # Truncate if too long
            if len(output) > 1800:
                output = output[:1800] + "\n... (truncated)"
            await ctx.send(f"```\n{output}\n```")
        else:
            await ctx.send(f"❌ Error: {data.get('error', 'Unknown error')}")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")


@run_command.error
async def run_command_error(ctx, error):
    if isinstance(error, commands.CheckFailure):
        await ctx.send(f"❌ You need the **{ADMIN_ROLE}** role to run commands.")


@bot.command(name="netops")
async def help_netops(ctx):
    """Show available commands"""
    msg = """**Network Bot Commands:**

`!devices` - List all network devices
`!health <device>` - Check device health
`!health all` - Check all devices
`!bgp <device>` - Show BGP neighbors
`!ping <device> <target>` - Ping from device
`!events [limit]` - Show recent events
`!topology` - Show topology summary

**Admin Commands** (requires Network Admin role):
`!run <device> <command>` - Run CLI command
"""
    await ctx.send(msg)


if __name__ == "__main__":
    token = _get_discord_token()
    if not token:
        print("Error: DISCORD_BOT_TOKEN not found in .env")
        exit(1)

    print("Starting Network Bot...")
    bot.run(token)


