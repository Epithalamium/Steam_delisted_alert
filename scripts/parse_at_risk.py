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
# The anonymous store session filters some apps out per store region
# (region-locked or content-filtered titles), and no single region
# returns the curator's full list, so query each region once and merge.
REGIONS = ("ua", "us", "jp")
# When regions disagree on a game's name, prefer the earlier region here.
NAME_PRIORITY = ("us", "ua", "jp")
PAGE_SIZE = 100
PAGE_DELAY = 0.5  # seconds between page requests

# Logged-in fetching: the anonymous store session always excludes content
# descriptors 3 and 4 (sexual content), so adult-only curator picks are
# invisible without a login. The session token comes from the repository
# secret STEAMLOGINSECURE (the steamLoginSecure cookie of an account whose
# store preferences allow all adult content). STEAMSESSIONID is optional;
# the store issues a fresh sessionid on its own when it is absent.
LOGIN_ENV = "STEAMLOGINSECURE"
SESSION_ENV = "STEAMSESSIONID"
ACCOUNT_URL = "https://store.steampowered.com/account/"


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


def build_session() -> requests.Session:
    token = os.environ.get(LOGIN_ENV, "").strip()
    if not token:
        raise ConfigError(
            f"{LOGIN_ENV} is not set. Add the steamLoginSecure cookie of an "
            "account with adult content enabled as a repository secret."
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
            "Refresh the STEAMLOGINSECURE repository secret."
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


def fetch_region(session: requests.Session, cc: str) -> dict[str, str]:
    """Fetch one store region's full recommendation list, page by page."""
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


def _get_page(session: requests.Session, cc: str, start: int) -> dict:
    last_exc: Exception | None = None
    for attempt in range(3):
        if attempt:
            time.sleep(15 * attempt)
        try:
            resp = session.get(
                CURATOR_API,
                params={"start": start, "count": PAGE_SIZE, "cc": cc},
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
    """Fetch all regions and merge them into one {appid: name} dict."""
    per_region: dict[str, dict[str, str]] = {}
    with build_session() as session:
        verify_login(session)
        for cc in REGIONS:
            per_region[cc] = fetch_region(session, cc)
            print(f"cc={cc}: {len(per_region[cc])} apps")
    # Merge in reverse priority order so the preferred region's name wins.
    merged: dict[str, str] = {}
    for cc in reversed(NAME_PRIORITY):
        merged.update(per_region[cc])
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

**Source:** Steam curator recommendations, fetched with a logged-in session (adult content enabled in the account's store preferences) and merged from the UA · US · JP store regions (cc=ua/us/jp).

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
