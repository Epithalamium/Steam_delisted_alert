import base64
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

# Data source: the "Games at risk of removal" Steam curator (clan 31857481),
# via the same filtered-recommendations endpoint the curator page itself
# loads on scroll. steam-tracker.com/apps/at-risk (the previous source)
# has served an empty table since 2026-11-06.
CURATOR_API = (
    "https://store.steampowered.com/curator/31857481"
    "/ajaxgetfilteredrecommendations/"
)
CURATOR_URL = (
    "https://store.steampowered.com/curator/31857481"
    "-Games-at-risk-of-removal/"
)
# Hybrid fetching, because neither view is complete on its own:
# - Anonymous sessions honour the cc parameter (per-region catalogues)
#   but always exclude content descriptors 3 and 4 (sexual content).
# - A logged-in session returns the adult content allowed by the
#   account's store preferences, but ignores cc entirely: its catalogue
#   is locked to the account's own store country.
# So fetch the logged-in view once (adult content, account region) plus
# the anonymous view for each region below (regional coverage), and merge.
REGIONS = ("ua", "us", "jp")
# When regions disagree on a game's name, prefer the earlier region here.
NAME_PRIORITY = ("us", "ua", "jp")
PAGE_SIZE = 100
PAGE_DELAY = 0.5  # seconds between page requests

REFRESH_TOKEN_ENV = "STEAM_REFRESH_TOKEN"
LOGIN_ENV = "STEAMLOGINSECURE"
SESSION_ENV = "STEAMSESSIONID"
ACCOUNT_URL = "https://store.steampowered.com/account/"
TOKEN_REFRESH_API = (
    "https://api.steampowered.com/IAuthenticationService"
    "/GenerateAccessTokenForApp/v1/"
)


class ConfigError(Exception):
    """Missing or unusable login configuration; the run must fail loudly."""


ROOT = Path(__file__).parent.parent
LIST_FILE = ROOT / "games_list.txt"
README_FILE = ROOT / "README.md"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "en-US,en;q=0.9",
    "X-Requested-With": "XMLHttpRequest",
    "Referer": "https://store.steampowered.com/curator/31857481/",
}


def _decode_jwt_payload(token: str) -> dict:
    """Decode the payload section of a Steam JWT without external dependencies."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ConfigError("STEAM_REFRESH_TOKEN is not a valid JWT format.")
    payload_b64 = parts[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload_b64)
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ConfigError(f"Failed to decode STEAM_REFRESH_TOKEN payload: {exc}") from exc


def _encode_varint(value: int) -> bytes:
    """Encode an integer as a Protobuf base-128 varint."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def _decode_varint(buf: bytes, pos: int) -> tuple[int, int]:
    """Decode a Protobuf base-128 varint starting at pos."""
    result = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    raise ValueError("Truncated varint in protobuf response")


def _build_refresh_protobuf(refresh_token: str, steam_id: int) -> str:
    """Build base64-encoded CAuthentication_RefreshToken_GenerateAccessToken_Request."""
    token_bytes = refresh_token.encode("utf-8")
    # field 1 (refresh_token): wire type 2 (length-delimited) -> tag (1 << 3) | 2 = 0x0A
    msg = b"\x0a" + _encode_varint(len(token_bytes)) + token_bytes
    # field 2 (steamid, fixed64): wire type 1 (64-bit) -> tag (2 << 3) | 1 = 0x11
    msg += b"\x11" + steam_id.to_bytes(8, "little", signed=False)
    return base64.b64encode(msg).decode("ascii")


def _extract_access_token_from_protobuf(buf: bytes) -> str:
    """Extract field 1 (access_token) from CAuthentication_RefreshToken_GenerateAccessToken_Response."""
    pos = 0
    while pos < len(buf):
        tag, pos = _decode_varint(buf, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 2:  # length-delimited (string / bytes)
            length, pos = _decode_varint(buf, pos)
            val = buf[pos : pos + length]
            pos += length
            if field_num == 1:
                return val.decode("utf-8")
        elif wire_type == 0:  # varint
            _, pos = _decode_varint(buf, pos)
        elif wire_type == 1:  # 64-bit
            pos += 8
        elif wire_type == 5:  # 32-bit
            pos += 4
        else:
            raise ValueError(f"Unsupported protobuf wire type: {wire_type}")
    return ""


def mint_steam_login_secure(refresh_token: str) -> str:
    """Exchange a long-lived Steam refresh_token for a fresh steamLoginSecure cookie."""
    payload = _decode_jwt_payload(refresh_token)
    steam_id = payload.get("sub")
    if not steam_id:
        raise ConfigError("STEAM_REFRESH_TOKEN payload is missing 'sub' (SteamID).")

    exp = payload.get("exp")
    if exp and time.time() > exp:
        raise ConfigError(
            "STEAM_REFRESH_TOKEN has expired. Generate a new refresh token."
        )

    encoded_proto = _build_refresh_protobuf(refresh_token, int(steam_id))

    try:
        resp = requests.post(
            TOKEN_REFRESH_API,
            data={"input_protobuf_encoded": encoded_proto},
            headers={
                "User-Agent": HEADERS["User-Agent"],
                "Referer": "https://steamcommunity.com/",
                "Origin": "https://steamcommunity.com",
            },
            timeout=30,
        )
        eresult = resp.headers.get("x-eresult")
        resp.raise_for_status()
    except Exception as exc:
        raise ConfigError(f"Failed to exchange refresh_token via Steam API: {exc}") from exc

    access_token = _extract_access_token_from_protobuf(resp.content)
    if not access_token:
        aud = payload.get("aud", [])
        raise ConfigError(
            f"Steam API returned empty access_token (x-eresult={eresult}, token aud={aud}). "
            "Ensure the token was issued for 'web' (not desktop client) and has not been revoked."
        )

    return f"{steam_id}||{access_token}"


def build_session() -> requests.Session:
    refresh_token = os.environ.get(REFRESH_TOKEN_ENV, "").strip()
    if refresh_token:
        print("Minting fresh steamLoginSecure from STEAM_REFRESH_TOKEN...")
        token = mint_steam_login_secure(refresh_token)
    else:
        token = os.environ.get(LOGIN_ENV, "").strip()

    if not token:
        raise ConfigError(
            f"Neither {REFRESH_TOKEN_ENV} nor {LOGIN_ENV} is set. "
            "Add a valid Steam refresh_token as a repository secret."
        )

    session = requests.Session()
    session.cookies.set("steamLoginSecure", token, domain="store.steampowered.com")
    sessionid = os.environ.get(SESSION_ENV, "").strip()
    if sessionid:
        session.cookies.set("sessionid", sessionid, domain="store.steampowered.com")
    return session


def verify_login(session: requests.Session) -> None:
    """Fail loudly if the token is dead or adult content is still filtered.

    Anonymous or expired sessions silently return a list with all adult
    apps removed, so never let a run proceed on an unverified session.
    """
    resp = session.get(ACCOUNT_URL, headers=HEADERS, timeout=60)
    resp.raise_for_status()
    if "/login" in resp.url:
        raise ConfigError(
            "steamLoginSecure is invalid or expired (redirected to login). "
            "Check your STEAM_REFRESH_TOKEN repository secret."
        )

    page = session.get(CURATOR_URL, headers=HEADERS, timeout=60)
    page.raise_for_status()
    m = re.search(
        r"excluded_content_descriptors(?:\"|&quot;):\[([0-9,]*)\]", page.text
    )
    if m:
        excluded = {int(x) for x in m.group(1).split(",") if x}
        if excluded & {3, 4}:
            raise ConfigError(
                f"Account store preferences still exclude content descriptors "
                f"{sorted(excluded & {3, 4})}. Enable all adult content "
                "categories at https://store.steampowered.com/account/preferences"
            )
        print(f"Login verified; excluded descriptors: {sorted(excluded) or 'none'}")
    else:
        print(
            "Login verified; descriptor config not found in page, continuing.",
            file=sys.stderr,
        )


def fetch_region(session: requests.Session, cc: str | None) -> dict[str, str]:
    """Fetch a full recommendation list, page by page.

    cc=None fetches the session's own view (for a logged-in session that
    is the account's store country; the cc parameter is ignored then).
    """
    games: dict[str, str] = {}
    start = 0
    total: int | None = None
    while total is None or start < total:
        data = _get_page(session, cc, start)
        total = int(data["total_count"])
        games.update(parse_results_html(data.get("results_html", "")))
        start += PAGE_SIZE
        if start < total:
            time.sleep(PAGE_DELAY)
    return games


def _get_page(session: requests.Session, cc: str | None, start: int) -> dict:
    params: dict[str, object] = {"start": start, "count": PAGE_SIZE}
    if cc is not None:
        params["cc"] = cc
    last_exc: Exception | None = None
    for attempt in range(3):
        if attempt:
            time.sleep(15 * attempt)
        try:
            resp = session.get(
                CURATOR_API,
                params=params,
                headers=HEADERS,
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("success") != 1:
                raise ValueError(f"API returned success={data.get('success')!r}")
            return data
        except Exception as exc:
            print(
                f"cc={cc} start={start}: attempt {attempt + 1} failed: {exc}",
                file=sys.stderr,
            )
            last_exc = exc
    raise last_exc  # type: ignore[misc]


def parse_results_html(html: str) -> dict[str, str]:
    soup = BeautifulSoup(html, "html.parser")
    games: dict[str, str] = {}
    for capsule in soup.select("a.store_capsule[data-ds-appid]"):
        appid = capsule["data-ds-appid"]
        img = capsule.find("img", alt=True)
        name = img["alt"].strip() if img else ""
        if not name:
            # Fall back to the app slug in the capsule link.
            m = re.search(r"/app/\d+/([^/]+)/", capsule.get("href", ""))
            if m:
                name = m.group(1).replace("_", " ")
        if name:
            games[appid] = name
    return games


def fetch_games() -> dict[str, str]:
    """Fetch the logged-in view plus all anonymous regions and merge."""
    # Logged-in pass: adult content, but locked to the account's region.
    with build_session() as session:
        verify_login(session)
        logged = fetch_region(session, None)
    print(f"logged-in view: {len(logged)} apps")

    # Anonymous pass: no adult content, but cc selects each region freely.
    per_region: dict[str, dict[str, str]] = {}
    with requests.Session() as anon:
        for cc in REGIONS:
            per_region[cc] = fetch_region(anon, cc)
            print(f"anonymous cc={cc}: {len(per_region[cc])} apps")

    # Merge in reverse priority order so the preferred source's name wins:
    # anonymous regions first (NAME_PRIORITY order), logged-in view last.
    merged: dict[str, str] = {}
    for cc in reversed(NAME_PRIORITY):
        merged.update(per_region[cc])
    merged.update(logged)
    return merged


def load_previous() -> dict[str, str]:
    if not LIST_FILE.exists():
        return {}
    games: dict[str, str] = {}
    for line in LIST_FILE.read_text(encoding="utf-8").splitlines():
        if "\t" in line:
            appid, name = line.split("\t", 1)
            games[appid.strip()] = name.strip()
    return games


def save_games(games: dict[str, str]) -> None:
    lines = [
        f"{appid}\t{name}"
        for appid, name in sorted(games.items(), key=lambda x: int(x[0]))
    ]
    LIST_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def update_readme(current: dict[str, str], new_appids: set[str]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if new_appids:
        new_lines = [
            f"- [{current[a]}](https://store.steampowered.com/app/{a}/) (AppID: {a})"
            for a in sorted(new_appids, key=int)
        ]
        new_section = "## Newly Added Since Last Check\n\n" + "\n".join(new_lines)
    else:
        new_section = "## Newly Added Since Last Check\n\n_(No new entries this run)_"

    readme = f"""\
# Steam At-Risk Games Tracker

Automatically tracks apps listed on the [Games at risk of removal]({CURATOR_URL}) Steam curator page.

Updated every 2 days via GitHub Actions. Last updated: **{now}**

**Source:** Steam curator recommendations, hybrid fetch: a logged-in session (adult content enabled in the account's store preferences; catalogue locked to the account's store region) merged with anonymous fetches from the UA · US · JP store regions (cc=ua/us/jp) for regional coverage.

**Total tracked:** {len(current)} apps

---

{new_section}

---

*For the full list of tracked games, please refer to [games_list.txt](games_list.txt).*
"""
    README_FILE.write_text(readme, encoding="utf-8")


def main() -> None:
    previous = load_previous()
    try:
        current = fetch_games()
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("Keeping existing data unchanged.", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        # Never overwrite the list with partial data: if any region fails,
        # the merged list would falsely drop that region's exclusive apps.
        print(f"ERROR fetching curator data after retries: {exc}", file=sys.stderr)
        print("Keeping existing data unchanged.", file=sys.stderr)
        sys.exit(0)

    if not current:
        print("ERROR: parsed 0 games — the API response may have changed", file=sys.stderr)
        sys.exit(1)

    new_appids = set(current) - set(previous)

    save_games(current)
    update_readme(current, new_appids)

    print(f"Total: {len(current)}  |  New this run: {len(new_appids)}")
    for appid in sorted(new_appids, key=int):
        print(f"  + {current[appid]} (AppID {appid})")


if __name__ == "__main__":
    main()
