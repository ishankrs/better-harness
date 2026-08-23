import json
import os
import pathlib
import sqlite3

DB_PATH = pathlib.Path(os.path.expanduser("~/.local/share/opencode/opencode.db"))
OUT_DIR = pathlib.Path(os.environ.get("TRAJECTORY_EXPORT_DIR", "/logs/agent/raw_trajectory"))


def _rows(conn: sqlite3.Connection, query: str):
    cur = conn.execute(query)
    cols = [d[0] for d in cur.description]
    for row in cur:
        yield dict(zip(cols, row))


def _safe_json(raw) -> object:
    try:
        return json.loads(raw or "null")
    except ValueError:
        return None


def main() -> None:
    if not DB_PATH.exists():
        return
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)

    sessions: dict[str, dict] = {}
    for s in _rows(conn, "SELECT * FROM session ORDER BY time_created"):
        s["messages"] = []
        sessions[s["id"]] = s

    messages_by_session: dict[str, list[dict]] = {sid: [] for sid in sessions}
    session_of_message: dict[str, str] = {}
    for m in _rows(conn, "SELECT * FROM message ORDER BY time_created"):
        sid = m.get("session_id")
        if sid not in messages_by_session:
            continue
        m["data"] = _safe_json(m.get("data"))
        messages_by_session[sid].append(m)
        session_of_message[m["id"]] = sid

    parts_by_message: dict[str, list[dict]] = {}
    for p in _rows(conn, "SELECT * FROM part ORDER BY time_created"):
        mid = p.get("message_id")
        if mid in session_of_message:
            p["data"] = _safe_json(p.get("data"))
            parts_by_message.setdefault(mid, []).append(p)

    for sid, msgs in messages_by_session.items():
        for m in msgs:
            m["parts"] = parts_by_message.pop(m.get("id"), [])
        s = sessions[sid]
        s["messages"] = msgs
        role = "subagent" if s.get("parent_id") else "orchestrator"
        final = OUT_DIR / f"{role}_{sid}.json"
        tmp = final.with_name(final.name + ".tmp")
        try:
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(s, f, default=str)
            tmp.replace(final)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass


if __name__ == "__main__":
    main()
