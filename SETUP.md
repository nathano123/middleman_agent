# Setup (development, test account only)

Read THREAT_MODEL.md first. `broker approvals` is development-only: an agent with a shell can
approve its own requests.

1. Install: `uv sync` in this folder.
2. Config: copy `broker.example.yaml` to `~/.agent-broker/config.yaml` (mode 0600) and edit
   `own_address`. For a dry run without Google, set `backend: fake` and
   `fake_fixture: /ABSOLUTE/PATH/TO/agent-broker/tests/fixtures/mailbox.json`.
3. Register one agent per MCP client entry: `uv run broker agents add desktop`.
   It prints both snippets below with your real absolute paths.
4. Answer approvals while testing: `uv run broker approvals list`, `show <id>`, `approve <id>`.

## Claude Desktop

Settings → Developer → Edit Config opens `claude_desktop_config.json`
(macOS `~/Library/Application Support/Claude/claude_desktop_config.json`). Paths must be
absolute. Quit and restart Claude Desktop after editing. Server stderr is written to
`~/Library/Logs/Claude/mcp-server-agent-broker-desktop.log`.

```json
{
  "mcpServers": {
    "agent-broker-desktop": {
      "command": "/ABSOLUTE/PATH/TO/uv",
      "args": ["--directory", "/ABSOLUTE/PATH/TO/agent-broker", "run", "broker", "serve",
               "--agent", "desktop", "--config", "/ABSOLUTE/PATH/TO/.agent-broker/config.yaml"]
    }
  }
}
```

## Claude Code

```bash
claude mcp add --transport stdio agent-broker-code -- /ABSOLUTE/PATH/TO/uv --directory /ABSOLUTE/PATH/TO/agent-broker run broker serve --agent code --config /ABSOLUTE/PATH/TO/.agent-broker/config.yaml
```

Register `code` first with `uv run broker agents add code`. Claude Code has a shell, so it can
run `broker` commands itself; see THREAT_MODEL.md.

## Approvals and timeouts

A call needing approval waits `approval_wait_seconds` (default 45), then returns
`pending` with an id; the agent should repeat the identical call. Claude Desktop is
reported to cancel tool calls after about 60 seconds, which is why the wait is shorter.
