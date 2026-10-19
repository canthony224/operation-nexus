#!/usr/bin/env python3
"""Owner-run setup for the community Discord server (docs/specs/DISCORD-SERVER-SETUP.md).

Creates or updates the roles, categories, channels and permission overwrites in blueprint.json.
It never deletes, kicks, bans or sends messages, uses only the standard library, and defaults to a
dry run. The bot token is read from DISCORD_BOT_TOKEN and is never printed or stored.

  python3 setup.py --show-blueprint                      no network, no token
  DISCORD_BOT_TOKEN=... python3 setup.py --guild ID      dry run against the real server
  DISCORD_BOT_TOKEN=... python3 setup.py --guild ID --apply --confirm-guild-name NAME

Checked against Discord's developer docs on 2026-10-19 (docs.discord.com/developers): API v10, the
endpoints used (GET and POST for roles and channels, PATCH for a role and a channel), the Bot
authorization header, the User-Agent format, the retry_after wait on HTTP 429, the permission
values, channel type numbers and overwrite types. The dry run prints every permission as a name
and a hex value.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

# API v10 is listed "Available", checked 2026-10-19 (docs.discord.com/developers/reference).
API_BASE = "https://discord.com/api/v10"
USER_AGENT = "DiscordBot (https://github.com/operation-nexus/operation-nexus, 0.1)"
EVERYONE = "@everyone"
CHANNEL_TEXT = 0  # GUILD_TEXT, checked 2026-10-19 (docs.discord.com/developers/resources/channel)
CHANNEL_CATEGORY = 4  # GUILD_CATEGORY, same source
OVERWRITE_ROLE = 0  # overwrite type 0 = role, same source
MAX_RETRIES = 5
MAX_WAIT_SECONDS = 60.0

# Permission flag values, checked 2026-10-19 against docs.discord.com/developers/topics/permissions.
PERMISSIONS: dict[str, int] = {
    "MANAGE_CHANNELS": 1 << 4,
    "MANAGE_ROLES": 1 << 28,
    "VIEW_CHANNEL": 1 << 10,
    "SEND_MESSAGES": 1 << 11,
    "MANAGE_MESSAGES": 1 << 13,
    "EMBED_LINKS": 1 << 14,
    "ATTACH_FILES": 1 << 15,
    "READ_MESSAGE_HISTORY": 1 << 16,
    "ADD_REACTIONS": 1 << 6,
    "MODERATE_MEMBERS": 1 << 40,
}
ADMINISTRATOR = 1 << 3  # never used in the blueprint; the community stage needs it (DS-11)
COMMUNITY_FEATURE = "COMMUNITY"
MAX_MESSAGE_CHARS = 2000  # Discord message limit, checked 2026-10-19
MIN_DEFAULT_CHANNELS = 7  # onboarding constraints, Discord docs: Modify Guild Onboarding
MIN_WRITABLE_DEFAULT_CHANNELS = 5
ONBOARDING_DEFAULT_MODE = 0
PROMPT_MULTIPLE_CHOICE = 0

Json = dict[str, Any]
# transport(method, url, headers, body) -> (status, response headers, response body bytes)
Transport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, dict[str, str], bytes]]


class SetupError(Exception):
    """A problem the owner can act on. Never contains the token."""


def perm_value(names: list[str]) -> int:
    value = 0
    for name in names:
        if name not in PERMISSIONS:
            raise SetupError(f"unknown permission name: {name}")
        value |= PERMISSIONS[name]
    return value


def bot_needs(bp: Json) -> int:
    """Permissions the bot itself must hold. Discord only lets a bot allow, deny or give a role
    permissions the bot has (docs.discord.com: Create Guild Channel, Permission Hierarchy), so
    this is every permission the blueprint uses, plus managing roles and channels."""
    value = PERMISSIONS["MANAGE_ROLES"] | PERMISSIONS["MANAGE_CHANNELS"]
    for role in bp["roles"]:
        value |= perm_value(role["permissions"])
    for cat in bp["categories"]:
        for ow in [cat["overwrites"], *[ch.get("overwrites", {}) for ch in cat["channels"]]]:
            for perms in ow.values():
                value |= perm_value(perms["allow"] + perms["deny"])
    return value


def perm_text(value: int) -> str:
    names = [n for n, bit in PERMISSIONS.items() if value & bit]
    return f"{'|'.join(names) or 'none'} = {value:#x}"


def validate_blueprint(bp: Json) -> None:
    """DS-10: names unique, permission names known, STAFF unreachable for everyone else."""
    roles = [r["name"] for r in bp["roles"]]
    cats = [c["name"] for c in bp["categories"]]
    chans = [ch["name"] for c in bp["categories"] for ch in c["channels"]]
    for label, names in (("role", roles), ("category", cats), ("channel", chans)):
        if len(names) != len(set(names)):
            raise SetupError(f"duplicate {label} names in the blueprint")
    known = set(roles) | {EVERYONE}
    for cat in bp["categories"]:
        if not cat.get("overwrites"):
            raise SetupError(f"category {cat['name']} has no permission overwrites")
        for ow in [cat["overwrites"], *[ch.get("overwrites", {}) for ch in cat["channels"]]]:
            for principal, perms in ow.items():
                if principal not in known:
                    raise SetupError(f"unknown role in overwrites: {principal}")
                perm_value(perms["allow"] + perms["deny"])
    for role in bp["roles"]:
        perm_value(role["permissions"])
    staff = next((c for c in bp["categories"] if c["name"] == "STAFF"), None)
    if staff is None:
        raise SetupError("the blueprint needs a STAFF category")
    for principal in (EVERYONE, "Operator"):
        if "VIEW_CHANNEL" not in staff["overwrites"].get(principal, {}).get("deny", []):
            raise SetupError(f"STAFF must deny VIEW_CHANNEL to {principal}")
    if "community" in bp:
        validate_community(bp)


def everyone_access(bp: Json) -> tuple[list[str], list[str]]:
    """(readable, writable) channel names for @everyone, from the blueprint's overwrites."""
    view, send = PERMISSIONS["VIEW_CHANNEL"], PERMISSIONS["SEND_MESSAGES"]
    readable: list[str] = []
    writable: list[str] = []
    for cat in bp["categories"]:
        for chan in cat["channels"]:
            allow, deny = merged_overwrites(cat, chan).get(EVERYONE, (0, 0))
            if allow & view and not deny & view:
                readable.append(chan["name"])
                if allow & send and not deny & send:
                    writable.append(chan["name"])
    return readable, writable


def validate_community(bp: Json) -> None:
    """DS-11, DS-12: names exist, the settings are known values, onboarding can be enabled."""
    community = bp["community"]
    chans = {ch["name"] for c in bp["categories"] for ch in c["channels"]}
    roles = {r["name"] for r in bp["roles"]}
    for key in ("rules_channel", "updates_channel", "safety_alerts_channel"):
        if community[key] not in chans:
            raise SetupError(f"community.{key} is not a channel in the blueprint")
    for item in community["welcome_screen"]["channels"]:
        if item["channel"] not in chans:
            raise SetupError(f"welcome screen links an unknown channel: {item['channel']}")
    onboarding = community["onboarding"]
    if onboarding["role"] not in roles:
        raise SetupError("onboarding assigns a role that is not in the blueprint")
    default = onboarding["default_channels"]
    if len(default) != len(set(default)) or not set(default) <= chans:
        raise SetupError("onboarding default channels must be unique channels in the blueprint")
    readable, writable = everyone_access(bp)
    if not set(default) <= set(readable):
        raise SetupError("every onboarding default channel must be readable by @everyone")
    if len(default) < MIN_DEFAULT_CHANNELS:
        raise SetupError(f"onboarding needs at least {MIN_DEFAULT_CHANNELS} default channels")
    if len(set(default) & set(writable)) < MIN_WRITABLE_DEFAULT_CHANNELS:
        raise SetupError(
            f"at least {MIN_WRITABLE_DEFAULT_CHANNELS} default channels must let @everyone send"
        )
    for key, allowed in (
        ("verification_level", range(0, 5)),
        ("default_message_notifications", range(0, 2)),
        ("explicit_content_filter", range(0, 3)),
    ):
        if community[key] not in allowed:
            raise SetupError(f"community.{key} is not a Discord value")


def merged_overwrites(cat: Json, chan: Json) -> dict[str, tuple[int, int]]:
    """Category overwrites with the channel's own on top, as (allow, deny) per role name."""
    out: dict[str, tuple[int, int]] = {}
    for principal, perms in cat["overwrites"].items():
        out[principal] = (perm_value(perms["allow"]), perm_value(perms["deny"]))
    for principal, perms in chan.get("overwrites", {}).items():
        allow, deny = out.get(principal, (0, 0))
        extra_allow, extra_deny = perm_value(perms["allow"]), perm_value(perms["deny"])
        out[principal] = ((allow | extra_allow) & ~extra_deny, (deny | extra_deny) & ~extra_allow)
    return out


_ID = r"[0-9]+"
# The only requests this tool can make (DS-5). Anything else is refused before it is sent: there is
# no DELETE, no member, ban, kick or direct-message path, and messages only in guild channels.
ALLOWED_REQUESTS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (method, re.compile(f"^{pattern}$"))
    for method, pattern in (
        ("GET", rf"/guilds/{_ID}"),
        ("GET", rf"/guilds/{_ID}/(roles|channels|welcome-screen|onboarding)"),
        ("GET", r"/users/@me"),
        ("GET", rf"/channels/{_ID}/messages\?limit=[0-9]+"),
        ("POST", rf"/guilds/{_ID}/(roles|channels)"),
        ("POST", rf"/channels/{_ID}/messages"),
        ("PATCH", rf"/guilds/{_ID}"),
        ("PATCH", rf"/guilds/{_ID}/welcome-screen"),
        ("PATCH", rf"/guilds/{_ID}/roles/{_ID}"),
        ("PATCH", rf"/channels/{_ID}"),
        ("PATCH", rf"/channels/{_ID}/messages/{_ID}"),
        ("PUT", rf"/guilds/{_ID}/onboarding"),
    )
)


class Api:
    """Thin Discord REST client limited to ALLOWED_REQUESTS (DS-5)."""

    def __init__(
        self,
        token: str,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._token = token
        self._transport = transport or _urllib_transport
        self._sleep = sleep

    def call(self, method: str, path: str, body: Json | None = None) -> Any:
        if not any(m == method and rx.match(path) for m, rx in ALLOWED_REQUESTS):
            raise SetupError(f"request not allowed: {method} {path}")
        headers = {
            "Authorization": f"Bot {self._token}",
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        }
        data = json.dumps(body).encode() if body is not None else None
        for _ in range(MAX_RETRIES):
            status, _hdrs, raw = self._transport(method, API_BASE + path, headers, data)
            if status == 429:
                wait = min(
                    float(json.loads(raw or b"{}").get("retry_after", 1.0)), MAX_WAIT_SECONDS
                )
                self._sleep(wait)
                continue
            if status >= 400:
                detail = ""
                try:
                    detail = str(json.loads(raw).get("message", ""))
                except ValueError:
                    pass
                raise SetupError(f"Discord returned {status} for {method} {path}: {detail}")
            return json.loads(raw) if raw else None
        raise SetupError(f"still rate limited after {MAX_RETRIES} tries: {method} {path}")


def _urllib_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310  fixed https URL
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read()


class Setup:
    def __init__(
        self, api: Api | None, guild_id: str, apply: bool, out: Callable[[str], None]
    ) -> None:
        self.api, self.guild, self.apply, self.out = api, guild_id, apply, out
        self.changes = 0
        self.roles: dict[str, Json] = {}
        self.channels: list[Json] = []

    def _write(self, method: str, path: str, body: Json, label: str, fake_id: str) -> Json:
        self.changes += 1
        self.out(f"{'DO' if self.apply else 'WOULD'}: {label}")
        if not self.apply or self.api is None:
            return {**body, "id": fake_id}
        return dict(self.api.call(method, path, body))

    def load(self) -> None:
        if self.api is None:  # --show-blueprint: plan against an empty server
            return
        self.roles = {r["name"]: r for r in self.api.call("GET", f"/guilds/{self.guild}/roles")}
        self.channels = list(self.api.call("GET", f"/guilds/{self.guild}/channels"))

    def ensure_role(self, spec: Json) -> None:
        body = {
            "name": spec["name"],
            "color": int(spec["color"].lstrip("#"), 16),
            "hoist": spec["hoist"],
            "mentionable": spec["mentionable"],
            "permissions": str(perm_value(spec["permissions"])),
        }
        label = f"role {spec['name']} ({perm_text(perm_value(spec['permissions']))})"
        have = self.roles.get(spec["name"])
        if have is None:
            self.roles[spec["name"]] = self._write(
                "POST",
                f"/guilds/{self.guild}/roles",
                body,
                f"create {label}",
                f"new:{spec['name']}",
            )
        elif any(str(have.get(k)) != str(v) for k, v in body.items()):
            self.roles[spec["name"]] = self._write(
                "PATCH",
                f"/guilds/{self.guild}/roles/{have['id']}",
                body,
                f"update {label}",
                have["id"],
            )

    def _principal_id(self, name: str) -> str:
        return self.guild if name == EVERYONE else str(self.roles[name]["id"])

    def _overwrite_list(
        self, desired: dict[str, tuple[int, int]], existing: list[Json]
    ) -> list[Json]:
        """Desired overwrites plus any existing ones for principals we do not manage."""
        managed = {self._principal_id(n) for n in desired}
        keep = [o for o in existing if str(o["id"]) not in managed]
        mine = [
            {"id": self._principal_id(n), "type": OVERWRITE_ROLE, "allow": str(a), "deny": str(d)}
            for n, (a, d) in desired.items()
        ]
        return sorted(keep + mine, key=lambda o: str(o["id"]))

    def ensure_channel(
        self,
        name: str,
        kind: int,
        parent: str | None,
        topic: str | None,
        desired: dict[str, tuple[int, int]],
    ) -> Json:
        found = next(
            (
                c
                for c in self.channels
                if c["name"] == name
                and c["type"] == kind
                and (c.get("parent_id") or None) == parent
            ),
            None,
        )
        want = self._overwrite_list(desired, (found or {}).get("permission_overwrites", []))
        body: Json = {"name": name, "type": kind, "permission_overwrites": want}
        if parent:
            body["parent_id"] = parent
        if topic and kind == CHANNEL_TEXT:
            body["topic"] = topic
        shown = ", ".join(
            f"{n}: allow {perm_text(a)}; deny {perm_text(d)}" for n, (a, d) in desired.items()
        )
        label = f"{'category' if kind == CHANNEL_CATEGORY else 'channel'} {name} [{shown}]"
        if found is None:
            made = self._write(
                "POST", f"/guilds/{self.guild}/channels", body, f"create {label}", f"new:{name}"
            )
            self.channels.append(made)
            return made
        have_ow = sorted(
            (
                {**o, "id": str(o["id"]), "allow": str(o["allow"]), "deny": str(o["deny"])}
                for o in found.get("permission_overwrites", [])
            ),
            key=lambda o: o["id"],
        )
        want_ow = sorted(({**o, "id": str(o["id"])} for o in want), key=lambda o: o["id"])
        same_ow = [(o["id"], o["allow"], o["deny"]) for o in have_ow] == [
            (o["id"], o["allow"], o["deny"]) for o in want_ow
        ]
        same_topic = kind != CHANNEL_TEXT or not topic or found.get("topic") == topic
        if not (same_ow and same_topic):
            found.update(
                self._write(
                    "PATCH", f"/channels/{found['id']}", body, f"update {label}", found["id"]
                )
            )
        return found

    def run(self, bp: Json) -> None:
        self.load()
        for spec in bp["roles"]:
            self.ensure_role(spec)
        for cat in bp["categories"]:
            cat_desired = {
                n: (perm_value(p["allow"]), perm_value(p["deny"]))
                for n, p in cat["overwrites"].items()
            }
            made = self.ensure_channel(cat["name"], CHANNEL_CATEGORY, None, None, cat_desired)
            for chan in cat["channels"]:
                self.ensure_channel(
                    chan["name"],
                    CHANNEL_TEXT,
                    str(made["id"]),
                    chan.get("topic"),
                    merged_overwrites(cat, chan),
                )


class Community:
    """The community stage (DS-11 to DS-13): server settings, welcome screen, onboarding, messages.

    Reads are always made; writes only when `apply` is set. Existing features, onboarding
    prompts and default channels are kept and added to, never replaced or removed.
    """

    def __init__(
        self,
        api: Api,
        guild_id: str,
        apply: bool,
        out: Callable[[str], None],
        skip_onboarding: bool = False,
    ) -> None:
        self.api, self.guild, self.apply, self.out = api, guild_id, apply, out
        self.skip_onboarding = skip_onboarding
        self.changes = 0
        self.roles: dict[str, str] = {}
        self.channels: dict[str, str] = {}

    def _write(self, method: str, path: str, body: Json, label: str) -> Any:
        self.changes += 1
        self.out(f"{'DO' if self.apply else 'WOULD'}: {label}")
        return self.api.call(method, path, body) if self.apply else None

    def load(self, bp: Json) -> None:
        roles = self.api.call("GET", f"/guilds/{self.guild}/roles")
        self.roles = {r["name"]: str(r["id"]) for r in roles}
        # category and channel names can repeat across kinds; channels only (type 0) are ours
        chans = self.api.call("GET", f"/guilds/{self.guild}/channels")
        self.channels = {c["name"]: str(c["id"]) for c in chans if c["type"] == CHANNEL_TEXT}
        wanted = {ch["name"] for c in bp["categories"] for ch in c["channels"]}
        missing = sorted(wanted - set(self.channels))
        if missing or any(r["name"] not in self.roles for r in bp["roles"]):
            raise SetupError(
                "the server does not have the roles and channels yet: run the structure stage "
                f"first (without --community). Missing channels: {', '.join(missing) or 'none'}"
            )

    def run(self, bp: Json) -> None:
        community = bp["community"]
        self.load(bp)
        guild = self.api.call("GET", f"/guilds/{self.guild}")
        on = COMMUNITY_FEATURE in guild.get("features", [])
        self.ensure_guild(guild, community)
        if not self.apply and not on:
            self.out("(not yet a Community server: the next two stages are planned as if it were)")
        self.ensure_welcome(community, on)
        if not self.skip_onboarding:
            self.ensure_onboarding(community, on)

    def ensure_guild(self, guild: Json, community: Json) -> None:
        want: Json = {
            "description": community["description"],
            "preferred_locale": community["preferred_locale"],
            "verification_level": community["verification_level"],
            "default_message_notifications": community["default_message_notifications"],
            "explicit_content_filter": community["explicit_content_filter"],
            "rules_channel_id": self.channels[community["rules_channel"]],
            "public_updates_channel_id": self.channels[community["updates_channel"]],
            "safety_alerts_channel_id": self.channels[community["safety_alerts_channel"]],
        }
        features = sorted(set(guild.get("features", [])) | {COMMUNITY_FEATURE})
        differs = [k for k, v in want.items() if str(guild.get(k)) != str(v)]
        if features != sorted(guild.get("features", [])):
            differs.append("features")
        if differs:
            self._write(
                "PATCH",
                f"/guilds/{self.guild}",
                {**want, "features": features},
                f"update server settings ({', '.join(differs)}); keeps features "
                f"{', '.join(guild.get('features', [])) or 'none'}, adds {COMMUNITY_FEATURE}",
            )

    def ensure_welcome(self, community: Json, on: bool) -> None:
        screen = community["welcome_screen"]
        want = {
            "enabled": True,
            "description": screen["description"],
            "welcome_channels": [
                {
                    "channel_id": self.channels[i["channel"]],
                    "description": i["description"],
                    "emoji_id": None,
                    "emoji_name": None,
                }
                for i in screen["channels"]
            ],
        }
        have = self.api.call("GET", f"/guilds/{self.guild}/welcome-screen") if on else {}
        have_channels = [
            {
                "channel_id": str(c["channel_id"]),
                "description": c["description"],
                "emoji_id": c.get("emoji_id"),
                "emoji_name": c.get("emoji_name"),
            }
            for c in have.get("welcome_channels", [])
        ]
        if (
            not have.get("enabled", True)
            or have.get("description") != want["description"]
            or have_channels != want["welcome_channels"]
        ):
            self._write(
                "PATCH", f"/guilds/{self.guild}/welcome-screen", want, "set the welcome screen"
            )

    @staticmethod
    def _clean_prompt(prompt: Json) -> Json:
        """An existing prompt in the shape Discord accepts back (emoji object to emoji fields)."""
        options = []
        for option in prompt.get("options", []):
            clean = {k: v for k, v in option.items() if k != "emoji"}
            emoji = option.get("emoji") or {}
            clean.setdefault("emoji_id", emoji.get("id"))
            clean.setdefault("emoji_name", emoji.get("name"))
            clean.setdefault("emoji_animated", emoji.get("animated", False))
            options.append(clean)
        return {**prompt, "options": options}

    def ensure_onboarding(self, community: Json, on: bool) -> None:
        spec = community["onboarding"]
        have = self.api.call("GET", f"/guilds/{self.guild}/onboarding") if on else {}
        role_id = self.roles[spec["role"]]
        default_ids = [self.channels[n] for n in spec["default_channels"]]
        existing_default = [str(i) for i in have.get("default_channel_ids", [])]
        merged_default = existing_default + [i for i in default_ids if i not in existing_default]
        prompts = [self._clean_prompt(p) for p in have.get("prompts", [])]
        ours = next((p for p in prompts if p.get("title") == spec["prompt_title"]), None)
        option = {
            "title": spec["option_title"],
            "description": spec["option_description"],
            "role_ids": [role_id],
            "channel_ids": [],
        }
        prompt: Json = {
            "type": PROMPT_MULTIPLE_CHOICE,
            "title": spec["prompt_title"],
            "single_select": True,
            "required": True,
            "in_onboarding": True,
            "options": [option],
        }
        if ours is None:
            prompts.append(prompt)
            ours_ok = False
        else:
            current = ours.get("options", [])
            ours_ok = (
                len(current) == 1
                and current[0].get("title") == option["title"]
                and [str(r) for r in current[0].get("role_ids", [])] == [role_id]
                and ours.get("required") is True
                and ours.get("in_onboarding") is True
            )
            if not ours_ok:
                prompts[prompts.index(ours)] = {
                    **ours,
                    **prompt,
                    "options": [{**(current[0] if current else {}), **option}],
                }
        if have.get("enabled") and merged_default == existing_default and ours_ok:
            return
        self._write(
            "PUT",
            f"/guilds/{self.guild}/onboarding",
            {
                "enabled": True,
                "mode": ONBOARDING_DEFAULT_MODE,
                "default_channel_ids": merged_default,
                "prompts": prompts,
            },
            "set onboarding: default channels and a required prompt that gives "
            f"{spec['role']} (existing prompts and channels are kept)",
        )


NOTE_LINE = re.compile(r"^\[(NOTE|HOLD)\b")


def read_text_file(path: str, what: str) -> str:
    """The text to post, from a local file. Never printed in full (DS-13).

    A vault draft file (front matter between `---` lines) is accepted directly: it must be
    APPROVED or POSTED, only its body is used, and its internal `[NOTE ...]` and `[HOLD ...]`
    lines are dropped. A plain text file has the same note lines dropped.
    """
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as err:
        raise SetupError(f"cannot read the {what} file: {err.strerror}") from None
    if lines and lines[0].strip() == "---":
        end = next((n for n, line in enumerate(lines[1:], 1) if line.strip() == "---"), None)
        if end is None:
            raise SetupError(f"the {what} file has front matter that never ends")
        status = next(
            (x.partition(":")[2].strip() for x in lines[1:end] if x.startswith("status:")), ""
        )
        if status not in ("APPROVED", "POSTED"):
            raise SetupError(f"the {what} draft is {status or 'missing a status'}, not APPROVED")
        lines = lines[end + 1 :]
    text = "\n".join(line for line in lines if not NOTE_LINE.match(line.strip())).strip()
    if not text:
        raise SetupError(f"the {what} file is empty")
    if len(text) > MAX_MESSAGE_CHARS:
        raise SetupError(
            f"the {what} text is {len(text)} characters; Discord allows {MAX_MESSAGE_CHARS}"
        )
    return text


def post_text(
    api: Api,
    channels: dict[str, str],
    apply: bool,
    out: Callable[[str], None],
    items: list[tuple[str, str]],
) -> int:
    """Post or edit the bot's own message in each channel: (channel name, text). Returns changes."""
    changes = 0
    me = str(api.call("GET", "/users/@me")["id"])
    for name, text in items:
        cid = channels[name]
        recent = api.call("GET", f"/channels/{cid}/messages?limit=50")
        mine = [m for m in recent if str(m["author"]["id"]) == me]
        if any(m["content"] == text for m in mine):
            continue
        changes += 1
        body = {"content": text, "allowed_mentions": {"parse": []}}
        verb = "edit the bot's message in" if mine else "post a message in"
        out(f"{'DO' if apply else 'WOULD'}: {verb} #{name} ({len(text)} characters)")
        if apply:
            if mine:
                api.call("PATCH", f"/channels/{cid}/messages/{mine[0]['id']}", body)
            else:
                api.call("POST", f"/channels/{cid}/messages", body)
    return changes


def run_community(
    api: Api,
    args: argparse.Namespace,
    bp: Json,
    out: Callable[[str], None],
    texts: list[tuple[str, str]],
) -> int:
    out("This stage needs the bot to hold the Administrator permission (Discord requires it to")
    out("change the Community feature). Remove it again when you are done.")
    stage = Community(api, args.guild, args.apply, out, args.skip_onboarding)
    stage.run(bp)
    changes = stage.changes
    if texts:
        changes += post_text(api, stage.channels, args.apply, out, texts)
    outcome = "made" if args.apply else "planned; nothing was written (dry run)"
    out(f"{changes} change(s) {outcome}.")
    return 0


def main(
    argv: list[str] | None = None,
    env: Mapping[str, str] | None = None,
    transport: Transport | None = None,
    out: Callable[[str], None] = print,
) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--blueprint", default=str(Path(__file__).with_name("blueprint.json")))
    parser.add_argument("--guild", help="server (guild) id")
    parser.add_argument("--apply", action="store_true", help="write changes (default is a dry run)")
    parser.add_argument(
        "--confirm-guild-name", help="must equal the real server name when --apply is used"
    )
    parser.add_argument("--show-blueprint", action="store_true", help="print the plan, no network")
    parser.add_argument(
        "--community",
        action="store_true",
        help="the community stage: Community, welcome screen, onboarding (needs Administrator)",
    )
    parser.add_argument(
        "--skip-onboarding", action="store_true", help="community stage without onboarding"
    )
    parser.add_argument(
        "--post-text",
        action="store_true",
        help="community stage: post the welcome and rules text (needs both file options)",
    )
    parser.add_argument("--welcome-file", help="local file with the welcome text (never committed)")
    parser.add_argument("--rules-file", help="local file with the rules text (never committed)")
    args = parser.parse_args(argv)
    environment: Mapping[str, str] = os.environ if env is None else env
    try:
        bp = json.loads(Path(args.blueprint).read_text(encoding="utf-8"))
        validate_blueprint(bp)
        if args.show_blueprint:
            Setup(None, "<guild>", False, out).run(bp)
            out(f"The bot must hold these permissions: {perm_text(bot_needs(bp))}")
            out("Dry run only: nothing was sent anywhere.")
            return 0
        if (args.post_text or args.skip_onboarding) and not args.community:
            raise SetupError("--post-text and --skip-onboarding belong to the --community stage")
        if args.community and "community" not in bp:
            raise SetupError("the blueprint has no community section")
        texts: list[tuple[str, str]] = []
        if args.post_text:
            if not (args.welcome_file and args.rules_file):
                raise SetupError("--post-text needs --welcome-file and --rules-file")
            texts = [
                ("welcome", read_text_file(args.welcome_file, "welcome")),
                ("rules", read_text_file(args.rules_file, "rules")),
            ]
        token = environment.get("DISCORD_BOT_TOKEN", "")
        if not args.guild or not token:
            raise SetupError("need --guild and the DISCORD_BOT_TOKEN environment variable")
        api = Api(token, transport)
        real = str(api.call("GET", f"/guilds/{args.guild}")["name"])
        out(f"Server: {real}")
        if args.apply and args.confirm_guild_name != real:
            raise SetupError(f"--confirm-guild-name must be exactly the server name, {real!r}")
        if args.community:
            return run_community(api, args, bp, out, texts)
        setup = Setup(api, args.guild, args.apply, out)
        setup.run(bp)
        if not args.apply:
            out(f"The bot must hold these permissions: {perm_text(bot_needs(bp))}")
        outcome = "made" if args.apply else "planned; nothing was written (dry run)"
        out(f"{setup.changes} change(s) {outcome}.")
        return 0
    except SetupError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
