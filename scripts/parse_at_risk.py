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

# ==================== 資料來源與抓取參數 ====================
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

# ==================== 認證設定 ====================
REFRESH_TOKEN_ENV = "STEAM_REFRESH_TOKEN"
LOGIN_ENV = "STEAMLOGINSECURE"
SESSION_ENV = "STEAMSESSIONID"
ACCOUNT_URL = "https://store.steampowered.com/account/"
FINALIZE_LOGIN_API = "https://login.steampowered.com/jwt/finalizelogin"

# 僅針對 store.steampowered.com 執行 Transfer
TARGET_DOMAIN = "store.steampowered.com"


class ConfigError(Exception):
    """登入設定缺失或不可用，必須顯式中斷執行。"""


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


# ==================== JWT 解析（純 Python，無外部依賴） ====================
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
        raise ConfigError(f"無法解碼 STEAM_REFRESH_TOKEN 載荷: {exc}") from exc


# ==================== finalizelogin + Transfer 兌換 steamLoginSecure ====================
def _extract_cookie_from_set_cookie(set_cookie_headers: list[str], name: str) -> str | None:
    """從一組 Set-Cookie 標頭中取出指定 cookie 的值（不含屬性）。"""
    for header in set_cookie_headers:
        for part in header.split(","):  # 極少數閘道會合併多個 Set-Cookie
            part = part.strip()
            if part.startswith(f"{name}="):
                # 取 = 之後、第一個 ; 之前的部分
                value = part.split("=", 1)[1].split(";")[0].strip()
                return value
    return None


def mint_steam_login_secure(refresh_token: str) -> tuple[str, str]:
    """
    透過 finalizelogin 將 refresh_token 兌換為 steamLoginSecure。

    回傳 (steamLoginSecure, sessionid)。
    steamLoginSecure 的格式已經是 steamid||access_token，無需再拼接。
    """
    payload = _decode_jwt_payload(refresh_token)
    steam_id = payload.get("sub")
    if not steam_id:
        raise ConfigError("STEAM_REFRESH_TOKEN 載荷中缺少 'sub' (SteamID)。")

    exp = payload.get("exp")
    if exp and time.time() > exp:
        raise ConfigError("STEAM_REFRESH_TOKEN 已過期，請重新產生。")

    # 每個工作階段使用獨立的 sessionid，避免與 transfer 回應的 cookie 衝突
    session_id = secrets.token_hex(12)

    # ---------- 第 1 步：呼叫 finalizelogin，取得 transfer_info ----------
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
        raise ConfigError(f"呼叫 finalizelogin 失敗: {exc}") from exc

    if not finalize_data.get("success", True) and finalize_data.get("error"):
        raise ConfigError(
            f"finalizelogin 回傳錯誤: {finalize_data}. "
            "請確認 refresh_token 是純 Web Token（aud 不含 'client'）。"
        )

    transfer_info = finalize_data.get("transfer_info") or []
    if not transfer_info:
        raise ConfigError(
            f"finalizelogin 未回傳 transfer_info (回應: {finalize_data})。"
        )

    # ---------- 第 2 步：逐一 POST transfer_info，從 Set-Cookie 取出憑證 ----------
    steam_login_secure: str | None = None
    minted_session_id: str | None = None

    for entry in transfer_info:
        url = entry.get("url", "")
        params = entry.get("params") or {}

        # 僅處理 store.steampowered.com 對應的 transfer
        if TARGET_DOMAIN not in url:
            continue

        # 請求體 = {steamID: steamID64, ...params}
        # 參考 DoctorMcKay 的實作：body = {steamID: this.steamID.getSteamID64(), ...params}
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
                f"Transfer 請求失敗 ({url}): {exc}，嘗試下一個...",
                file=sys.stderr,
            )
            continue

        # 從 Set-Cookie 取出 steamLoginSecure
        set_cookies = transfer_resp.raw.headers.getlist("Set-Cookie")
        cookie_value = _extract_cookie_from_set_cookie(
            set_cookies, "steamLoginSecure"
        )
        if not cookie_value:
            # 部分情況下 cookie 會被 urllib 解碼，嘗試從 cookie jar 取值
            cookie_value = transfer_resp.cookies.get("steamLoginSecure")

        if cookie_value:
            steam_login_secure = cookie_value
            # transfer 回應通常也會下發 sessionid，但為保持一致，使用自行產生的值
            minted_session_id = session_id
            break

    if not steam_login_secure:
        raise ConfigError(
            "所有 Transfer 請求都未回傳 steamLoginSecure。"
            "請檢查 refresh_token 是否已失效，或帳號是否要求額外驗證。"
        )

    # steamLoginSecure 的值已包含 steamid||access_token，請勿二次拼接
    return steam_login_secure, minted_session_id or session_id


# ==================== 建構已登入 Session ====================
def build_session() -> requests.Session:
    refresh_token = os.environ.get(REFRESH_TOKEN_ENV, "").strip()

    if refresh_token:
        print("正在透過 STEAM_REFRESH_TOKEN 兌換 steamLoginSecure...")
        token, sessionid = mint_steam_login_secure(refresh_token)
        print("steamLoginSecure 兌換成功。")
    else:
        # 回退：直接讀取靜態 Cookie（僅供本機除錯或臨時應急）
        token = os.environ.get(LOGIN_ENV, "").strip()
        sessionid = os.environ.get(SESSION_ENV, "").strip()
        if not token:
            raise ConfigError(
                f"未設定 {REFRESH_TOKEN_ENV}，也未設定 {LOGIN_ENV}。"
                "請將純 Web refresh_token 存入倉庫 Secret。"
            )

    session = requests.Session()
    session.cookies.set("steamLoginSecure", token, domain=TARGET_DOMAIN)
    if sessionid:
        session.cookies.set("sessionid", sessionid, domain=TARGET_DOMAIN)
    return session


# ==================== 登入驗證（維持原有邏輯） ====================
def verify_login(session: requests.Session) -> None:
    resp = session.get(ACCOUNT_URL, headers=HEADERS, timeout=60)
    resp.raise_for_status()
    if "/login" in resp.url:
        raise ConfigError(
            "steamLoginSecure 無效或已過期（被重新導向至登入頁）。"
            "請檢查 STEAM_REFRESH_TOKEN 是否仍有效。"
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
                f"帳號商店偏好仍排除了內容描述符 {sorted(excluded & {3, 4})}。"
                "請在 https://store.steampowered.com/account/preferences 啟用所有成人內容類別。"
            )
        print(f"登入驗證通過；排除的描述符: {sorted(excluded) or '無'}")
    else:
        print("登入驗證通過；未在頁面中找到描述符設定，繼續執行。", file=sys.stderr)


# ==================== 以下抓取邏輯維持不變 ====================
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
                raise ValueError(f"API 回傳 success={data.get('success')!r}")
            return data
        except Exception as exc:
            print(
                f"cc={cc} start={start}: 第 {attempt + 1} 次嘗試失敗: {exc}",
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
    print(f"登入檢視: {len(logged)} 個應用程式")

    per_region: dict[str, dict[str, str]] = {}
    with requests.Session() as anon:
        for cc in REGIONS:
            per_region[cc] = fetch_region(anon, cc)
            print(f"匿名 cc={cc}: {len(per_region[cc])} 個應用程式")

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
        new_section = "## 自上次檢查以來新增\n\n" + "\n".join(new_lines)
    else:
        new_section = "## 自上次檢查以來新增\n\n_(本次執行無新增條目)_"

    readme = f"""\
# Steam 下架風險遊戲追蹤

自動追蹤 [Games at risk of removal]({CURATOR_URL}) Steam 鑑賞家頁面上列出的應用程式。

透過 GitHub Actions 每 2 天更新一次。最後更新: **{now}**

**來源:** Steam 鑑賞家推薦，混合抓取: 一個已登入工作階段（帳號商店偏好已啟用成人內容；目錄鎖定為帳號所在商店區域）與 UA · US · JP 商店區域的匿名抓取（cc=ua/us/jp）合併，以實現區域覆蓋。

**總計追蹤:** {len(current)} 個應用程式

---

{new_section}

---

*完整追蹤清單請參閱 [games_list.txt](games_list.txt)。*
"""
    README_FILE.write_text(readme, encoding="utf-8")


def main() -> None:
    previous = load_previous()
    try:
        current = fetch_games()
    except ConfigError as exc:
        print(f"錯誤: {exc}", file=sys.stderr)
        print("保持現有資料不變。", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"重試後仍無法抓取鑑賞家資料: {exc}", file=sys.stderr)
        print("保持現有資料不變。", file=sys.stderr)
        sys.exit(0)

    if not current:
        print("錯誤: 解析到 0 個遊戲 — API 回應可能已變更", file=sys.stderr)
        sys.exit(1)

    new_appids = set(current) - set(previous)

    save_games(current)
    update_readme(current, new_appids)

    print(f"總計: {len(current)}  |  本次新增: {len(new_appids)}")
    for appid in sorted(new_appids, key=int):
        print(f"  + {current[appid]} (AppID {appid})")


if __name__ == "__main__":
    main()
