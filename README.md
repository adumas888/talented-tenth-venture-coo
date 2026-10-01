# Talented Tenth Venture COO v1.0

Private MCP operating system for four launch workstreams:
- GoVibe
- ACE Website Design
- Citadelle Law
- Liberation Law

## Core design
The COO uses persistent PostgreSQL projects, objectives, tasks, waiting-on state, Antoine-required flags, and an activity log. Objectives/tasks cannot be marked COMPLETE unless `detail.completion_verified=true` is supplied after the completion condition is actually verified.

The first write after installation should be `bootstrap_launch_system` with `approved=true`. It is idempotent and seeds the four projects from the uploaded launch checklists and their critical paths.

## MCP tools
- `coo_status`
- `list_projects`
- `get_dashboard`
- `list_objectives`
- `create_objective`
- `update_objective`
- `list_tasks`
- `create_task`
- `update_task`
- `log_activity`
- `bootstrap_launch_system`

## Render setup
Create this as a SEPARATE Render Web Service and preferably a separate Postgres database from the law-firm Clio bridge.

Required environment variables:
- `BASE_URL` — the Venture COO Render origin, no trailing slash
- `DATABASE_URL`
- `SESSION_SECRET`
- `OAUTH_ADMIN_SECRET`
- `BRIDGE_API_KEY`
- `ENABLE_VENTURE_WRITES=true`

No Clio credentials are required for the Venture COO MCP tools.

MCP URL: `https://YOUR-VENTURE-COO.onrender.com/mcp`

After deployment, create a new private ChatGPT MCP app named **Talented Tenth Venture COO**, connect with OAuth, refresh tools, then call `bootstrap_launch_system` with explicit approval.

## Safety model
Every persistent write requires both:
1. `ENABLE_VENTURE_WRITES=true`
2. `approved=true`

The COO is designed to execute internal work autonomously but to flag tasks requiring Antoine for signatures, credentials, material spending, legal judgment, personal recording/appearance, or consequential external commitments.
