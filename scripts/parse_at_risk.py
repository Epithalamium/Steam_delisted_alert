import base64
import json
import os
import re
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

# ==================== 数据源与抓取参数 ====================
CURATOR_API = (
    "https://store.steampowered.com/curator/31857481"
    "/ajaxgetfilteredrecommendations/"
)
CURATOR_URL = (
    "https://store.steampowered.com/curator/31857481"
    "-Games-at-risk-of-removal/"
)
REGIONS = ("ua", "us", "jp")
NAME_PRIORITY = ("us", "ua", "jp")
PAGE_SIZE = 100
PAGE_DELAY = 0.5

# ==================== 认证配置 ====================
REFRESH_TOKEN_ENV = "STEAM_REFRESH_TOKEN"
LOGIN_ENV = "STEAMLOGINSECURE"
SESSION_ENV = "STEAMSESSIONID"
ACCOUNT_URL = "https://store.steampowered.com/account/"
FINALIZE_LOGIN_API = "https://login.steampowered.com/jwt/finalizelogin"

# 只针对 store.steampowered.com 执行 Transfer
TARGET_DOMAIN = "store.steampowered.com"


class ConfigError(Exception):
    """登录配置缺失或不可用，必须显式中断运行。"""


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


# ==================== JWT 解析（纯 Python，无外部依赖） ====================
def _decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ConfigError("STEAM_REFRESH_TOKEN 不是有效的 JWT 格式。")
    payload_b64 = parts[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload_b64)
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ConfigError(f"无法解码 STEAM_REFRESH_TOKEN 载荷: {exc}") from exc


# ==================== finalizelogin + Transfer 兑换 steamLoginSecure ====================
def _extract_cookie_from_set_cookie(set_cookie_headers: list[str], name: str) -> str | None:
    """从一组 Set-Cookie 头中提取指定 cookie 的值（不含属性）。"""
    for header in set_cookie_headers:
        for part in header.split(","):  # 极少数网关会合并多个 Set-Cookie
            part = part.strip()
            if part.startswith(f"{name}="):
                # 取 = 之后、第一个 ; 之前的部分
                value = part.split("=", 1)[1].split(";")[0].strip()
                return value
    return None


def mint_steam_login_secure(refresh_token: str) -> tuple[str, str]:
    """
    通过 finalizelogin 将 refresh_token 兑换为 steamLoginSecure。

    返回 (steamLoginSecure, sessionid)。
    steamLoginSecure 的格式已经是 steamid||access_token，无需再拼接。
    """
    payload = _decode_jwt_payload(refresh_token)
    steam_id = payload.get("sub")
    if not steam_id:
        raise ConfigError("STEAM_REFRESH_TOKEN 载荷中缺少 'sub' (SteamID)。")

    exp = payload.get("exp")
    if exp and time.time() > exp:
        raise ConfigError("STEAM_REFRESH_TOKEN 已过期，请重新生成。")

    # 每个会话使用独立的 sessionid，避免与 transfer 响应的 cookie 冲突
    session_id = secrets.token_hex(12)

    # ---------- 第 1 步：调用 finalizelogin，获取 transfer_info ----------
    try:
        finalize_resp = requests.post(
            FINALIZE_LOGIN_API,
            data={
                "nonce": refresh_token,
                "sessionid": session_id,
                "redir": "https://store.steampowered.com/",
            },
            headers={
                "User-Agent": HEADERS["User-Agent"],
                "Accept": "application/json, text/plain, */*",
                "Origin": "https://store.steampowered.com",
                "Referer": "https://store.steampowered.com/",
            },
            timeout=30,
        )
        finalize_resp.raise_for_status()
        finalize_data = finalize_resp.json()
    except Exception as exc:
        raise ConfigError(f"调用 finalizelogin 失败: {exc}") from exc

    if not finalize_data.get("success", True) and finalize_data.get("error"):
        raise ConfigError(
            f"finalizelogin 返回错误: {finalize_data}. "
            "请确认 refresh_token 是纯 Web Token（aud 不含 'client'）。"
        )

    transfer_info = finalize_data.get("transfer_info") or []
    if not transfer_info:
        raise ConfigError(
            f"finalizelogin 未返回 transfer_info (响应: {finalize_data})。"
        )

    # ---------- 第 2 步：逐个 POST transfer_info，从 Set-Cookie 提取凭证 ----------
    steam_login_secure: str | None = None
    minted_session_id: str | None = None

    for entry in transfer_info:
        url = entry.get("url", "")
        params = entry.get("params") or {}

        # 只处理 store.steampowered.com 对应的 transfer
        if TARGET_DOMAIN not in url:
            continue

        # 请求体 = {steamID: steamID64, ...params}
        # DoctorMcKay 的参考实现：body = {steamID: this.steamID.getSteamID64(), ...params}
        body = {"steamID": steam_id, **params}

        try:
            transfer_resp = requests.post(
                url,
                data=body,
                headers={
                    "User-Agent": HEADERS["User-Agent"],
                    "Accept": "application/json, text/plain, */*",
                    "Origin": "https://store.steampowered.com",
                    "Referer": "https://store.steampowered.com/",
                },
                allow_redirects=False,
                timeout=30,
            )
            transfer_resp.raise_for_status()
        except Exception as exc:
            print(
                f"Transfer 请求失败 ({url}): {exc}，尝试下一个...",
                file=sys.stderr,
            )
            continue

        # 从 Set-Cookie 中提取 steamLoginSecure
        set_cookies = transfer_resp.raw.headers.getlist("Set-Cookie")
        cookie_value = _extract_cookie_from_set_cookie(
            set_cookies, "steamLoginSecure"
        )
        if not cookie_value:
            # 有些情况下 cookie 会被 urllib 解码，尝试从 cookie jar 取
            cookie_value = transfer_resp.cookies.get("steamLoginSecure")

        if cookie_value:
            steam_login_secure = cookie_value
            # transfer 响应通常也会下发 sessionid，但为保持一致，使用自己生成的
            minted_session_id = session_id
            break

    if not steam_login_secure:
        raise ConfigError(
            "所有 Transfer 请求都未返回 steamLoginSecure。"
            "请检查 refresh_token 是否已失效，或账号是否要求额外验证。"
        )

    # steamLoginSecure 的值已经包含 steamid||access_token，不要二次拼接
    return steam_login_secure, minted_session_id or session_id


# ==================== 构建已登录 Session ====================
def build_session() -> requests.Session:
    refresh_token = os.environ.get(REFRESH_TOKEN_ENV, "").strip()

    if refresh_token:
        print("正在通过 STEAM_REFRESH_TOKEN 兑换 steamLoginSecure...")
        token, sessionid = mint_steam_login_secure(refresh_token)
        print("steamLoginSecure 兑换成功。")
    else:
        # 回退：直接读取静态 Cookie（仅用于本地调试或临时应急）
        token = os.environ.get(LOGIN_ENV, "").strip()
        sessionid = os.environ.get(SESSION_ENV, "").strip()
        if not token:
            raise ConfigError(
                f"未设置 {REFRESH_TOKEN_ENV}，也未设置 {LOGIN_ENV}。"
                "请将纯 Web refresh_token 存入仓库 Secret。"
            )

    session = requests.Session()
    session.cookies.set("steamLoginSecure", token, domain=TARGET_DOMAIN)
    if sessionid:
        session.cookies.set("sessionid", sessionid, domain=TARGET_DOMAIN)
    return session


# ==================== 登录验证（保持原有逻辑） ====================
def verify_login(session: requests.Session) -> None:
    resp = session.get(ACCOUNT_URL, headers=HEADERS, timeout=60)
    resp.raise_for_status()
    if "/login" in resp.url:
        raise ConfigError(
            "steamLoginSecure 无效或已过期（被重定向到登录页）。"
            "请检查 STEAM_REFRESH_TOKEN 是否仍有效。"
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
                f"账号商店偏好仍排除了内容描述符 {sorted(excluded & {3, 4})}。"
                "请在 https://store.steampowered.com/account/preferences 启用所有成人内容类别。"
            )
        print(f"登录验证通过；排除的描述符: {sorted(excluded) or '无'}")
    else:
        print("登录验证通过；未在页面中找到描述符配置，继续运行。", file=sys.stderr)


# ==================== 以下抓取逻辑保持不变 ====================
def fetch_region(session: requests.Session, cc: str | None) -> dict[str, str]:
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
            resp = session.get(CURATOR_API, params=params, headers=HEADERS, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            if data.get("success") != 1:
                raise ValueError(f"API 返回 success={data.get('success')!r}")
            return data
        except Exception as exc:
            print(
                f"cc={cc} start={start}: 第 {attempt + 1} 次尝试失败: {exc}",
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
            m = re.search(r"/app/\d+/([^/]+)/", capsule.get("href", ""))
            if m:
                name = m.group(1).replace("_", " ")
        if name:
            games[appid] = name
    return games


def fetch_games() -> dict[str, str]:
    with build_session() as session:
        verify_login(session)
        logged = fetch_region(session, None)
    print(f"登录视图: {len(logged)} 个应用")

    per_region: dict[str, dict[str, str]] = {}
    with requests.Session() as anon:
        for cc in REGIONS:
            per_region[cc] = fetch_region(anon, cc)
            print(f"匿名 cc={cc}: {len(per_region[cc])} 个应用")

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
        new_section = "## 自上次检查以来新增\n\n" + "\n".join(new_lines)
    else:
        new_section = "## 自上次检查以来新增\n\n_(本次运行无新增条目)_"

    readme = f"""\
# Steam 下架风险游戏追踪

自动追踪 [Games at risk of removal]({CURATOR_URL}) Steam 鉴赏家页面上列出的应用。

通过 GitHub Actions 每 2 天更新一次。最后更新: **{now}**

**来源:** Steam 鉴赏家推荐，混合抓取: 一个已登录会话（账号商店偏好已启用成人内容；目录锁定为账号所在商店区域）与 UA · US · JP 商店区域的匿名抓取（cc=ua/us/jp）合并，以实现区域覆盖。

**总计追踪:** {len(current)} 个应用

---

{new_section}

---

*完整追踪列表请参阅 [games_list.txt](games_list.txt)。*
"""
    README_FILE.write_text(readme, encoding="utf-8")


def main() -> None:
    previous = load_previous()
    try:
        current = fetch_games()
    except ConfigError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        print("保持现有数据不变。", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"重试后仍无法抓取鉴赏家数据: {exc}", file=sys.stderr)
        print("保持现有数据不变。", file=sys.stderr)
        sys.exit(0)

    if not current:
        print("错误: 解析到 0 个游戏 — API 响应可能已变更", file=sys.stderr)
        sys.exit(1)

    new_appids = set(current) - set(previous)

    save_games(current)
    update_readme(current, new_appids)

    print(f"总计: {len(current)}  |  本次新增: {len(new_appids)}")
    for appid in sorted(new_appids, key=int):
        print(f"  + {current[appid]} (AppID {appid})")


if __name__ == "__main__":
    main()
