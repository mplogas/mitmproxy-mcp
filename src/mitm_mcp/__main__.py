"""Allow running as: python -m mitm_mcp"""

from mitm_mcp.server import main

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
