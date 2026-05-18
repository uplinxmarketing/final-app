"""
skills_manager.py — Skills and quick commands management for Uplinx Meta Manager.

Manages the lifecycle of AI skills (.md files + DB records) and quick command
slash shortcuts that inject pre-built prompt templates into conversations.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import aiofiles
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from database import Skill, QuickCommand

logger = logging.getLogger("uplinx")

SKILLS_DIR = Path("skills")
GLOBAL_SKILLS_DIR = SKILLS_DIR / "global"
CLIENT_SKILLS_DIR = SKILLS_DIR / "clients"

# ---------------------------------------------------------------------------
# Default skill definitions — maps slug → (name, description, filename)
# ---------------------------------------------------------------------------

_DEFAULT_SKILLS: list[tuple[str, str, str]] = [
    (
        "Meta Ads Uploader",
        "Naming conventions, image matching rules, placement logic, and upload process for Meta ads.",
        "meta-ads-uploader.md",
    ),
    (
        "Analytics Reporter",
        "KPI thresholds, report format, anomaly detection rules for campaign performance analysis.",
        "analytics-reporter.md",
    ),
    (
        "Post Scheduler",
        "Default schedule times, platform rules, caption format, and scheduling logic for social posts.",
        "post-scheduler.md",
    ),
]

# ---------------------------------------------------------------------------
# Default quick command definitions
# ---------------------------------------------------------------------------

_DEFAULT_QUICK_COMMANDS: list[dict] = [
    {
        "trigger": "/upload-ads",
        "name": "Upload Ads",
        "description": "Upload all ads from the active folder using the latest shared copy document.",
        "prompt_template": (
            "Upload all ads from the active folder using copy from the last shared document. "
            "Use active client context. Publish when complete."
        ),
        "sort_order": 0,
    },
    {
        "trigger": "/weekly-report",
        "name": "Weekly Report",
        "description": "Pull last 7 days performance for all active campaigns.",
        "prompt_template": (
            "Pull last 7 days performance for all active campaigns on this client's accounts. "
            "Show spend, ROAS, CPM, CTR, CPC. Flag underperforming ads. Suggest 3 actions."
        ),
        "sort_order": 1,
    },
    {
        "trigger": "/monthly-report",
        "name": "Monthly Report",
        "description": "Pull last 30 days performance with week-over-week trend.",
        "prompt_template": (
            "Pull last 30 days performance. Include week-over-week trend. "
            "Compare campaigns. Give strategic recommendations."
        ),
        "sort_order": 2,
    },
    {
        "trigger": "/schedule-week",
        "name": "Schedule Week",
        "description": "Schedule uploaded images as posts across Facebook and Instagram for 5 working days.",
        "prompt_template": (
            "Schedule the uploaded images as posts across Facebook and Instagram "
            "for the next 5 working days at 10am client timezone."
        ),
        "sort_order": 3,
    },
    {
        "trigger": "/pause-all",
        "name": "Pause All Campaigns",
        "description": "List all active campaigns and ask for confirmation before pausing.",
        "prompt_template": (
            "List all active campaigns then ask for confirmation before pausing all of them."
        ),
        "sort_order": 4,
    },
    {
        "trigger": "/list-campaigns",
        "name": "List Campaigns",
        "description": "List all campaigns for the active ad account with key metrics.",
        "prompt_template": (
            "List all campaigns for active ad account with status, daily budget, "
            "spend today, and ROAS if available."
        ),
        "sort_order": 5,
    },
    {
        "trigger": "/refresh-context",
        "name": "Refresh Context",
        "description": "Re-fetch all pages, pixels, and ad accounts from Meta API.",
        "prompt_template": (
            "Re-fetch all pages, pixels, ad accounts from Meta API and update "
            "the context panel dropdowns."
        ),
        "sort_order": 6,
    },
    {
        "trigger": "/check-scheduled",
        "name": "Check Scheduled Posts",
        "description": "Show all scheduled posts for this week across all platforms.",
        "prompt_template": (
            "Show all scheduled posts for this week across all platforms for active client."
        ),
        "sort_order": 7,
    },
]


# ---------------------------------------------------------------------------
# Skill loading
# ---------------------------------------------------------------------------


async def load_skills_for_conversation(
    conversation_id: int,
    client_id: Optional[int],
    db: AsyncSession,
) -> list[dict]:
    """
    Load all active skills for a conversation.

    Returns global skills (ordered by sort_order) first, then any
    client-specific skills.  For each skill the .md file content is read
    from disk.  Skills whose file is missing are logged and skipped.
    """
    skills: list[dict] = []

    # Global skills (client_id IS NULL)
    global_stmt = (
        select(Skill)
        .where(Skill.is_active == True, Skill.client_id == None)  # noqa: E711
        .order_by(Skill.sort_order)
    )
    global_result = await db.execute(global_stmt)
    global_skills = global_result.scalars().all()

    skill_rows = list(global_skills)

    # Client-specific skills
    if client_id is not None:
        client_stmt = (
            select(Skill)
            .where(Skill.is_active == True, Skill.client_id == client_id)  # noqa: E711
            .order_by(Skill.sort_order)
        )
        client_result = await db.execute(client_stmt)
        skill_rows.extend(client_result.scalars().all())

    for row in skill_rows:
        file_path = Path(row.file_path)
        if not file_path.exists():
            logger.warning(
                "Skill '%s' (id=%d) file not found at %s — skipping",
                row.name,
                row.id,
                file_path,
            )
            continue
        try:
            async with aiofiles.open(file_path, "r", encoding="utf-8") as fh:
                content = await fh.read()
        except OSError as exc:
            logger.warning("Could not read skill file %s: %s", file_path, exc)
            continue

        skills.append(
            {
                "name": row.name,
                "description": row.description or "",
                "content": content,
            }
        )

    logger.debug(
        "Loaded %d skill(s) for conversation_id=%d client_id=%s",
        len(skills),
        conversation_id,
        client_id,
    )
    return skills


async def build_skills_system_prompt(skills: list[dict]) -> str:
    """
    Build the skills injection section for Claude's system prompt.

    Format::

        ## Active Skills

        ### {name}
        {content}

        ### {name}
        ...
    """
    if not skills:
        return ""

    lines: list[str] = ["## Active Skills", ""]
    for skill in skills:
        lines.append(f"### {skill['name']}")
        lines.append(skill["content"].strip())
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Skill CRUD
# ---------------------------------------------------------------------------


async def get_all_skills(
    db: AsyncSession,
    client_id: Optional[int] = None,
) -> list[dict]:
    """Return all skills: global ones plus optionally client-specific ones."""
    stmt = select(Skill).where(Skill.client_id == None).order_by(Skill.sort_order)  # noqa: E711
    result = await db.execute(stmt)
    rows = list(result.scalars().all())

    if client_id is not None:
        client_stmt = (
            select(Skill)
            .where(Skill.client_id == client_id)
            .order_by(Skill.sort_order)
        )
        client_result = await db.execute(client_stmt)
        rows.extend(client_result.scalars().all())

    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "file_path": r.file_path,
            "client_id": r.client_id,
            "is_active": r.is_active,
            "sort_order": r.sort_order,
        }
        for r in rows
    ]


async def create_skill(
    name: str,
    description: str,
    content: str,
    client_id: Optional[int],
    db: AsyncSession,
) -> dict:
    """
    Create a new skill: write the .md file to disk and create the DB record.

    Returns ``{"success": bool, "skill_id": int, "error": str}``.
    """
    result: dict = {"success": False, "skill_id": 0, "error": ""}

    try:
        if client_id is None:
            target_dir = GLOBAL_SKILLS_DIR
        else:
            # Fetch client name for directory label
            from database import Client
            client_row = await db.get(Client, client_id)
            client_name = client_row.name if client_row else f"client_{client_id}"
            target_dir = await get_client_skills_dir(client_name)

        target_dir.mkdir(parents=True, exist_ok=True)

        # Build filename from name
        slug = name.lower().replace(" ", "-").replace("/", "-")
        file_path = target_dir / f"{slug}.md"

        # Write .md file
        async with aiofiles.open(file_path, "w", encoding="utf-8") as fh:
            await fh.write(content)

        # Determine next sort_order
        count_stmt = select(Skill).where(Skill.client_id == client_id)  # type: ignore[arg-type]
        count_result = await db.execute(count_stmt)
        existing_count = len(count_result.scalars().all())

        skill = Skill(
            name=name,
            description=description,
            file_path=str(file_path),
            client_id=client_id,
            is_active=True,
            sort_order=existing_count,
        )
        db.add(skill)
        await db.flush()

        result["success"] = True
        result["skill_id"] = skill.id
        logger.info("Created skill '%s' (id=%d) at %s", name, skill.id, file_path)

    except Exception as exc:
        logger.error("create_skill failed: %s", exc, exc_info=True)
        result["error"] = str(exc)

    return result


async def update_skill(skill_id: int, content: str, db: AsyncSession) -> dict:
    """Update a skill's .md file and DB record (description via content header)."""
    result: dict = {"success": False, "error": ""}

    skill = await db.get(Skill, skill_id)
    if skill is None:
        result["error"] = f"Skill id={skill_id} not found"
        return result

    try:
        file_path = Path(skill.file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiofiles.open(file_path, "w", encoding="utf-8") as fh:
            await fh.write(content)

        # Mark the row as updated (SQLAlchemy will flush on commit)
        skill.file_path = str(file_path)  # no-op but triggers dirty tracking
        await db.flush()

        result["success"] = True
        logger.info("Updated skill id=%d at %s", skill_id, file_path)
    except Exception as exc:
        logger.error("update_skill id=%d failed: %s", skill_id, exc, exc_info=True)
        result["error"] = str(exc)

    return result


async def toggle_skill(skill_id: int, is_active: bool, db: AsyncSession) -> dict:
    """Enable or disable a skill by toggling its is_active flag."""
    result: dict = {"success": False, "error": ""}

    skill = await db.get(Skill, skill_id)
    if skill is None:
        result["error"] = f"Skill id={skill_id} not found"
        return result

    skill.is_active = is_active
    await db.flush()
    result["success"] = True
    logger.info("Skill id=%d is_active set to %s", skill_id, is_active)
    return result


async def delete_skill(skill_id: int, db: AsyncSession) -> dict:
    """Delete a skill from the DB and remove its .md file from disk."""
    result: dict = {"success": False, "error": ""}

    skill = await db.get(Skill, skill_id)
    if skill is None:
        result["error"] = f"Skill id={skill_id} not found"
        return result

    file_path = Path(skill.file_path)
    try:
        if file_path.exists():
            file_path.unlink()
            logger.debug("Deleted skill file: %s", file_path)
    except OSError as exc:
        logger.warning("Could not delete skill file %s: %s", file_path, exc)
        # Continue — DB record deletion is more important

    await db.delete(skill)
    await db.flush()
    result["success"] = True
    logger.info("Deleted skill id=%d ('%s')", skill_id, skill.name)
    return result


# ---------------------------------------------------------------------------
# Quick commands
# ---------------------------------------------------------------------------


async def get_quick_commands(
    client_id: Optional[int],
    db: AsyncSession,
) -> list[dict]:
    """
    Return active quick commands: global ones (client_id IS NULL) then
    client-specific ones, each group ordered by sort_order.
    """
    stmt = (
        select(QuickCommand)
        .where(QuickCommand.is_active == True, QuickCommand.client_id == None)  # noqa: E711
        .order_by(QuickCommand.sort_order)
    )
    result = await db.execute(stmt)
    rows = list(result.scalars().all())

    if client_id is not None:
        client_stmt = (
            select(QuickCommand)
            .where(
                QuickCommand.is_active == True,  # noqa: E711
                QuickCommand.client_id == client_id,
            )
            .order_by(QuickCommand.sort_order)
        )
        client_result = await db.execute(client_stmt)
        rows.extend(client_result.scalars().all())

    return [
        {
            "id": r.id,
            "trigger": r.trigger,
            "name": r.name,
            "description": r.description,
            "prompt_template": r.prompt_template,
            "client_id": r.client_id,
            "is_active": r.is_active,
            "sort_order": r.sort_order,
        }
        for r in rows
    ]


async def create_quick_command(
    trigger: str,
    name: str,
    description: str,
    prompt_template: str,
    client_id: Optional[int],
    db: AsyncSession,
) -> dict:
    """
    Create a new quick command.

    Returns ``{"success": bool, "command_id": int, "error": str}``.
    """
    result: dict = {"success": False, "command_id": 0, "error": ""}

    # Enforce unique trigger
    existing_stmt = select(QuickCommand).where(QuickCommand.trigger == trigger)
    existing_result = await db.execute(existing_stmt)
    if existing_result.scalar_one_or_none() is not None:
        result["error"] = f"Quick command with trigger '{trigger}' already exists"
        return result

    try:
        count_stmt = select(QuickCommand).where(QuickCommand.client_id == client_id)  # type: ignore[arg-type]
        count_result = await db.execute(count_stmt)
        existing_count = len(count_result.scalars().all())

        cmd = QuickCommand(
            trigger=trigger,
            name=name,
            description=description,
            prompt_template=prompt_template,
            client_id=client_id,
            is_active=True,
            sort_order=existing_count,
        )
        db.add(cmd)
        await db.flush()

        result["success"] = True
        result["command_id"] = cmd.id
        logger.info("Created quick command '%s' (id=%d)", trigger, cmd.id)
    except Exception as exc:
        logger.error("create_quick_command failed: %s", exc, exc_info=True)
        result["error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Initialisation helpers
# ---------------------------------------------------------------------------


async def initialize_default_skills(db: AsyncSession) -> None:
    """
    Seed the DB with the built-in global skills if they do not already exist.

    Each skill points to a .md file in ``skills/global/``.  The function is
    idempotent — existing records are left untouched.
    """
    GLOBAL_SKILLS_DIR.mkdir(parents=True, exist_ok=True)

    for sort_order, (name, description, filename) in enumerate(_DEFAULT_SKILLS):
        # Check whether a skill with this name already exists (global)
        stmt = select(Skill).where(Skill.name == name, Skill.client_id == None)  # noqa: E711
        result = await db.execute(stmt)
        if result.scalar_one_or_none() is not None:
            logger.debug("Default skill '%s' already exists — skipping", name)
            continue

        file_path = GLOBAL_SKILLS_DIR / filename
        if not file_path.exists():
            logger.warning(
                "Default skill file missing: %s — creating empty placeholder",
                file_path,
            )
            try:
                async with aiofiles.open(file_path, "w", encoding="utf-8") as fh:
                    await fh.write(f"# {name}\n\n{description}\n")
            except OSError as exc:
                logger.error("Cannot write placeholder skill file %s: %s", file_path, exc)
                continue

        skill = Skill(
            name=name,
            description=description,
            file_path=str(file_path),
            client_id=None,
            is_active=True,
            sort_order=sort_order,
        )
        db.add(skill)
        logger.info("Seeded default skill '%s' → %s", name, file_path)

    await db.flush()


async def initialize_default_quick_commands(db: AsyncSession) -> None:
    """
    Seed the DB with the built-in global quick commands if they do not exist.

    The function is idempotent — existing triggers are skipped.
    """
    for cmd_def in _DEFAULT_QUICK_COMMANDS:
        trigger: str = cmd_def["trigger"]
        stmt = select(QuickCommand).where(QuickCommand.trigger == trigger)
        result = await db.execute(stmt)
        if result.scalar_one_or_none() is not None:
            logger.debug("Quick command '%s' already exists — skipping", trigger)
            continue

        cmd = QuickCommand(
            trigger=trigger,
            name=cmd_def["name"],
            description=cmd_def["description"],
            prompt_template=cmd_def["prompt_template"],
            client_id=None,
            is_active=True,
            sort_order=cmd_def["sort_order"],
        )
        db.add(cmd)
        logger.info("Seeded quick command '%s'", trigger)

    await db.flush()


# ---------------------------------------------------------------------------
# Directory helper
# ---------------------------------------------------------------------------


async def get_client_skills_dir(client_name: str) -> Path:
    """
    Return (and create if absent) the skills directory for a specific client.

    The directory is ``skills/clients/{slugified_client_name}/``.
    """
    slug = client_name.lower().replace(" ", "_").replace("/", "_")
    client_dir = CLIENT_SKILLS_DIR / slug
    client_dir.mkdir(parents=True, exist_ok=True)
    return client_dir
