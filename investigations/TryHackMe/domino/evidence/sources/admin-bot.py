#!/usr/bin/env python3
import time, re, base64 as b64, json, logging, hmac, hashlib
import requests
import pymysql
import pymysql.cursors

logging.basicConfig(filename="/var/log/admin_bot.log", level=logging.INFO,
                    format="%(asctime)s %(message)s")

DB_CONFIG = dict(host="localhost", database="nexusdb",
                 user="app_user", password="D3v0ps!2024",
                 cursorclass=pymysql.cursors.DictCursor)

APP_SECRET = "nexus_app_k3y_2024"

def make_session_cookie():
    data = b64.b64encode(json.dumps(dict(user_id=1, username="laura.hayes",
                                         role="admin")).encode()).decode()
    sig = hmac.new(APP_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()
    return data + "." + sig

COOKIE = dict(nexus_session=make_session_cookie())


def get_unviewed(db):
    with db.cursor() as c:
        c.execute("SELECT id, message FROM tickets WHERE viewed = 0")
        return c.fetchall()


def mark_viewed(db, tid):
    with db.cursor() as c:
        c.execute("UPDATE tickets SET viewed = 1 WHERE id = %s", (tid,))
    db.commit()


def process(t):
    msg = t["message"]
    logging.info("Admin reviewing ticket #%s", t["id"])
    url_pat = r"https?://[A-Za-z0-9./_?&=:%+-]+"
    urls = re.findall(url_pat, msg)
    for url in set(urls):
        try:
            logging.info("  -> %s", url[:120])
            requests.get(url, cookies=COOKIE, timeout=5)
        except Exception:
            pass


def main():
    logging.info("Admin bot started")
    while True:
        try:
            db = pymysql.connect(**DB_CONFIG)
            for t in get_unviewed(db):
                process(t)
                mark_viewed(db, t["id"])
            db.close()
        except Exception as e:
            logging.error("Error: %s", e)
        time.sleep(15)


if __name__ == "__main__":
    main()
