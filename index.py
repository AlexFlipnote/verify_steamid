import json
import sys
import os
import re
import requests
import time

from urllib import parse
from quart import Quart, session, redirect, url_for, render_template, request, abort
from utils.postgresql import Table
from bs4 import BeautifulSoup
from quart_discord import DiscordOAuth, NotSignedIn

with open("./config.json", "r") as f:
    config = json.load(f)

app = Quart(__name__)
app.discord = DiscordOAuth(
    app, config["discord_client_id"], config["discord_client_secret"],
    config["discord_redirect_uri"]
)

app.config["SECRET_KEY"] = config["discord_client_secret"]
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "true"


@app.before_serving
async def startup():
    try:
        pool = await Table.create_pool(config["postgres_url"], command_timeout=60)
        app.pool = pool
        print("PostgreSQL has been connected successfully.")
    except Exception as e:
        print(f"\nPostgreSQL failed...\n\tError: {e}")
        sys.exit(0)


def discord_info():
    if not session.get("oauth2_state", None):
        return None
    return app.discord.user()


def steam_info():
    return session.get("steam", None)


def commid_to_steamid(commid: int):
    y = int(commid) - 76561197960265728
    x = y % 2
    return "STEAM_0:{}:{}".format(x, (y - x) // 2)


def fetch_steam_session(data: dict):
    re_steamid = re.compile(r"https:\/\/steamcommunity\.com\/openid\/id\/([0-9]{1,20})")
    if "openid.claimed_id" not in data:
        return None

    steamid_64 = re_steamid.search(data["openid.claimed_id"])
    if not steamid_64:
        return None

    try:
        r = requests.get(
            "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/"
            f"v2/?key={config['steam_web_api_key']}&format=json&steamids={steamid_64.group(1)}"
        )

        data = r.json()
    except Exception:
        abort(500, "Steam API failed.")

    profile_bg = None
    try:
        r_steam = requests.get(data["response"]["players"][0]["profileurl"])
        html = BeautifulSoup(r_steam.text, "html.parser")
        get_video = html.find("video")
        if get_video:
            profile_bg = get_video.attrs.get("poster", None)
    except Exception:
        pass

    session["steam"] = {
        "commid": int(steamid_64.group(1)),
        "steamid": commid_to_steamid(steamid_64.group(1)),
        "name": data["response"]["players"][0]["personaname"],
        "avatar": data["response"]["players"][0]["avatarfull"],
        "background": profile_bg
    }


async def is_verified():
    verify_data = None
    discord_user = discord_info()
    steam_user = steam_info()

    discord_id = discord_user.id if discord_user else None
    steam_id = steam_user["commid"] if steam_user else None

    if discord_id or steam_id:
        verify_data = await app.pool.fetchrow(
            "SELECT * FROM users WHERE user_id=$1 or steamid_64=$2",
            discord_id, steam_id
        )

    return verify_data


@app.route("/")
async def index():
    verify_data = await is_verified()

    return await render_template(
        "index.html", discord=discord_info(), steam=steam_info(),
        verify_data=verify_data
    )


@app.route("/finalize")
async def request_verification():
    session_verify_timer = session.get("verify_timer", 0)
    if not session_verify_timer:
        session["verify_timer"] = time.time()

    if time.time() < session_verify_timer:
        return await render_template(
            "onepage.html",
            title="Ratelimited",
            message=" ".join([
                "You are trying to verify too fast... ",
                f"Wait {round(session_verify_timer - time.time(), 2)} more seconds."
            ])
        )

    session["verify_timer"] = time.time() + 60

    verify_data = await is_verified()
    if verify_data:
        return await render_template(
            "onepage.html",
            title="Duplicate",
            message="You are already verified on the Discord server..."
        )

    discord_user = discord_info()
    steam_user = steam_info()

    if not discord_user and not steam_user:
        return await render_template(
            "onepage.html",
            title="Error",
            message="You are not logged in on Discord or Steam..."
        )

    headers = {
        "Authorization": f"Bot {config['discord_bot_token']}",
        "Content-Type": "application/json"
    }

    r = requests.delete(
        f"https://discord.com/api/v10/guilds/{config['discord_guild_id']}/members/{discord_user.id}/roles/{config['discord_role_id']}",
        headers=headers
    )

    if r.status_code != 204:
        return await render_template(
            "onepage.html",
            title="Error",
            message="Failed to remove the role from the Discord server... Are you inside the Discord server even?"
        )

    try:
        await app.pool.execute(
            "INSERT INTO users (user_id, steamid_32, steamid_64) VALUES ($1, $2, $3)",
            discord_user.id, steam_user["steamid"], steam_user["commid"]
        )
    except Exception:
        return await render_template(
            "onepage.html",
            title="Verified..? 🎉",
            message="You're probably already verified..."
        )

    requests.post(
        f"https://discord.com/api/v10/channels/{config['discord_channel_id']}/messages",
        headers=headers, json={
            "content": f"User <@!{discord_user.id}> has joined **Festive World** <a:cookiee:993317674815856742>",
            "allowed_mentions": {"parse": ["users"]}
        }
    )

    return await render_template(
        "onepage.html",
        title="Verified 🎉",
        message="Your verification has been completed successfully, enjoy the server!"
    )


@app.route("/logout")
async def logout():
    app.discord.clear_session()
    return redirect(url_for(".index"))


@app.route("/login/discord")
async def discord_login():
    if discord_info():
        return redirect(url_for(".index"))

    return app.discord.prepare_login("identify")


@app.route("/login/steam")
async def login_steam():
    if steam_info():
        return redirect(url_for(".index"))

    prepare_args = {
        'openid.ns': config["openid_ns"],
        'openid.identity': config["openid_identity"],
        'openid.claimed_id': config["openid_claimed_id"],
        'openid.mode': config["openid_mode"],
        'openid.return_to': config["openid_return_to"],
        'openid.realm': config["openid_realm"]
    }

    query_string = parse.urlencode(prepare_args)
    auth_url = f"{config['steam_openid_url']}?{query_string}"

    return redirect(auth_url)


@app.route("/callback/steam")
async def steam_callback():
    data = request.args.to_dict()

    params = {
        "openid.assoc_handle": data["openid.assoc_handle"],
        "openid.sig": data["openid.sig"],
        "openid.ns": data["openid.ns"],
        "openid.mode": "check_authentication"
    }

    data.update(params)

    data["openid.mode"] = "check_authentication"
    data["openid.signed"] = data["openid.signed"]

    r = requests.post(config["steam_openid_url"], data=data)

    if "is_valid:true" not in r.text:
        return abort(400, "Invalid steam login.")

    fetch_steam_session(data)

    return redirect(url_for(".index"))


@app.route("/callback/discord")
async def discord_callback():
    app.discord.callback()
    if "redirect_url" in session:
        return redirect(session["redirect_url"])
    return redirect(url_for(".index"))


@app.errorhandler(NotSignedIn)
async def redirect_unauthorized(e):
    session["redirect_url"] = request.url
    return redirect(url_for(".discord_login"))


app.run(port=config["port"])
