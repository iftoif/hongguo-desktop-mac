"""One upstream page per call; opaque, expiring, in-memory continuation state."""
import secrets
import threading
import time


class SearchPager:
    def __init__(self, request, parse_cell, clock=time.monotonic, ttl=600, capacity=128):
        self.request, self.parse_cell, self.clock = request, parse_cell, clock
        self.ttl, self.capacity = ttl, capacity
        self.states = {}
        self.lock = threading.Lock()

    def page(self, query, cursor=None):
        query = query.strip()
        if not query or len(query) > 80:
            raise ValueError("Invalid search query")
        with self.lock:
            now = self.clock()
            self.states = {key: state for key, state in self.states.items() if state["expires"] > now}
            state = self.states.get(cursor) if cursor else None
            if cursor and (state is None or state["query"] != query):
                raise ValueError("Search cursor expired or mismatched")
            if state and "result" in state:
                return state["result"]  # Replayed UI request never repeats an upstream call.
            if len(self.states) >= self.capacity:
                raise ValueError("Search session capacity reached")
            offset, passback, search_id = state["upstream"] if state else (0, "", "")
            params = {"query": query, "tab_name": "feed", "search_source": "1",
                      "offset": str(offset), "count": "0", "use_correct": "true"}
            if passback:
                params["passback"] = passback
            if search_id:
                params["search_id"] = search_id
            payload = self.request(params)  # No retry, phone refresh, or eager next-page fetch.
            tabs = payload.get("search_tabs") if isinstance(payload, dict) else None
            if not isinstance(tabs, list) or len(tabs) != 1 or not isinstance(tabs[0], dict):
                raise ValueError("Unverified search tab shape")
            tab = tabs[0]
            more = tab.get("has_more")
            if type(more) not in (bool, int) or more not in (False, True, 0, 1):
                raise ValueError("Missing search pagination state")
            cells = tab.get("data")
            if not isinstance(cells, list):
                raise ValueError("Invalid search cells")
            seen = set(state["seen"]) if state else set()
            rows = []
            for cell in cells:
                row = self.parse_cell(cell)
                if row and str(row["series_id"]) not in seen:
                    seen.add(str(row["series_id"]))
                    rows.append(row)
            token = None
            if more:
                nxt = tab.get("next_offset")
                pb, sid = tab.get("passback", passback), tab.get("search_id", search_id)
                if type(nxt) is not int or nxt <= offset or not isinstance(pb, str) or not isinstance(sid, str):
                    raise ValueError("Search cursor did not advance")
                token = secrets.token_urlsafe(24)
                self.states[token] = {"query": query, "upstream": (nxt, pb, sid),
                                      "seen": seen, "expires": now + self.ttl}
            result = {"query": query, "results": rows, "has_more": bool(more),
                      "next_cursor": token, "coverage": "unverified", "unique_results_seen": len(seen)}
            if state is not None:
                state["result"] = result
            return result
