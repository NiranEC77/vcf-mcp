"""Entry point.

`vcf-mcp` with no arguments speaks MCP over stdio, which is how an MCP client
launches it. The two subcommands exist so the server can be checked from a
terminal without an MCP client in the loop:

    vcf-mcp index    build/refresh the operation index and print spec stats
    vcf-mcp check    authenticate to every target and report what answers

A hosted copy serves Streamable HTTP instead of stdio. Either set $PORT
(every PaaS does) or ask for it:

    vcf-mcp serve-http
"""
from __future__ import annotations

import json
import os
import sys


def main() -> None:
    argv = sys.argv[1:]
    command = argv[0] if argv else "serve"

    if command == "index":
        from . import specs

        entries = specs.index()
        print(f"{len(entries)} operations indexed")
        for row in specs.stats():
            print(f"  {row['operations']:>5}  {row['spec']:<40} {row['api']}")
        return

    if command == "check":
        from . import tools

        print(json.dumps(tools.targets(check_reachability=True), indent=2, default=str))
        return

    if command in ("serve-http", "http"):
        os.environ.setdefault("VCF_MCP_HTTP", "1")
        from . import server

        server.main_http()
        return

    if command in ("-h", "--help", "help"):
        print(__doc__)
        return

    # Goes through server.main(), not mcp.run(), so the logging setup there
    # actually applies.
    from . import server

    server.main()


if __name__ == "__main__":
    main()
