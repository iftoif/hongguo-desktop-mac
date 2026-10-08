# -*- coding: utf-8 -*-
"""本地维护: 红果账号同步的 HTTP 路由。

单独成文件，server.py 只需要两行（import + register），
这样上游换版本时补丁面最小、最容易自动重注入。
"""
import re

from fastapi import HTTPException, Query


def register(app):
    import desktop_account as A

    def _sid(value):
        text = str(value or "").strip()
        if not re.fullmatch(r"[0-9]{8,24}", text):
            raise HTTPException(400, "Invalid series id")
        return text

    @app.get("/desktop/account/status")
    def desktop_account_status():
        result = A.public_session()
        result["restorable"] = A.has_restorable()
        return result

    @app.post("/desktop/account/restore")
    def desktop_account_restore():
        """恢复上一次退出登录前的登录态。"""
        result = A.restore_session()
        if not result.get("ok"):
            raise HTTPException(400, str(result.get("error") or "恢复失败"))
        return result["session"]

    @app.post("/desktop/account/send_code")
    def desktop_account_send_code(mobile: str = Query(..., min_length=11, max_length=11)):
        result = A.send_code(mobile)
        if not result.get("ok"):
            raise HTTPException(400, str(result.get("error") or "验证码发送失败"))
        return {"sent": True, "hasTicket": bool(result.get("hasTicket")),
                "retryTime": result.get("retryTime")}

    @app.post("/desktop/account/login")
    def desktop_account_login(mobile: str = Query(..., min_length=11, max_length=11),
                              code: str = Query(..., min_length=4, max_length=8),
                              ticket: str = Query("", max_length=2000)):
        result = A.sms_login(mobile, code, ticket)
        # 2046：不是失败，是要求先做身份验证。返回 200 + mfaRequired，
        # 前端据此显示验证页；当失败处理会让这条路永远走不通。
        if result.get("mfaRequired"):
            return result
        if not result.get("ok"):
            detail = str(result.get("error") or "登录失败")
            if result.get("error_code") is not None:
                detail = "%s（错误码 %s）" % (detail, result["error_code"])
            raise HTTPException(400, detail)
        return result["session"]

    @app.post("/desktop/account/verify_mfa")
    def desktop_account_verify_mfa(mobile: str = Query(..., min_length=11, max_length=11),
                                   code: str = Query("", min_length=4, max_length=8)):
        """完成安全验证（2046 之后那一步）。

        两步：① 轮询 /passport/upsms/verify/ 确认服务端收到上行短信；
              ② 重发 sms_login 并带上 2046 返回的 biz_params —— 这一步才是
                 真正「完成验证并登录」（反编译 com.bytedance.sdk.account 确认）。
        code 是**同一条短信验证码**，重发登录时必须带，所以这里是必填。
        """
        result = A.verify_mfa(mobile, code)
        if not result.get("ok"):
            # 「还没收到上行短信」是可重试状态，不是错误：返回 200 + pending，
            # 前端据此继续轮询。当成 400 会让 UI 显示失败并停止重试。
            if result.get("pending"):
                return {"verified": False, "pending": True,
                        "error": str(result.get("error") or "还没收到你的上行短信"),
                        "error_code": result.get("error_code")}
            detail = str(result.get("error") or "验证失败")
            if result.get("error_code") is not None:
                detail = "%s（错误码 %s）" % (detail, result["error_code"])
            raise HTTPException(400, detail)
        # 重放成功时已经完成登录，直接把会话交给前端（省一次往返，
        # 也避免验证码被消费两次）。
        if result.get("replayed") and result.get("session"):
            return {"verified": True, "loggedIn": True, "session": result["session"]}
        return {"verified": True, "ticket": result.get("ticket") or ""}

    @app.get("/desktop/account/log")
    def desktop_account_log(limit: int = Query(30, ge=1, le=200)):
        """排查用：返回最近的账号操作记录（不含任何凭据）。"""
        return {"path": A.LOG_PATH, "items": A.read_log(limit)}

    @app.post("/desktop/account/logout")
    def desktop_account_logout():
        A.clear_session()
        return {"loggedIn": False}

    @app.post("/desktop/account/sync_emulator")
    def desktop_account_sync_emulator():
        """从已登录的模拟器同步登录态（验证码登录不可用时的备用路径）。"""
        result = A.sync_from_emulator()
        if not result.get("ok"):
            raise HTTPException(400, str(result.get("error") or "同步失败"))
        return result.get("session") or {}

    @app.get("/desktop/account/raw_history")
    def desktop_account_raw_history(limit: int = Query(30, ge=1, le=200),
                                    series_id: str = Query("")):
        """排查用：返回云端历史的原始字段（不脱敏、不改写）。

        为什么需要它：/desktop/account/remote 只挑了几个字段返回，
        排查「PC 写了但手机看不到」这类问题时必须看到云端原样返回什么。
        """
        j = A._history_raw(limit=limit)
        data = j.get("data") or {}
        items = data.get("data_list") or []
        if series_id:
            items = [x for x in items
                     if str(x.get("book_id_str") or x.get("book_id") or "") == series_id]
        return {"code": j.get("code"), "total": data.get("total"),
                "count": len(items), "items": items}

    @app.get("/desktop/account/remote")
    def desktop_account_remote(limit: int = Query(30, ge=1, le=200)):
        history = A.remote_history(limit=limit)
        favorites = A.remote_favorites()
        return {
            "history": history.get("items") or [],
            "historyTotal": history.get("total") or 0,
            "favorites": favorites.get("items") or [],
            "historyOk": bool(history.get("ok")),
            "favoritesOk": bool(favorites.get("ok")),
            "error": history.get("error") or favorites.get("error") or "",
        }

    @app.post("/desktop/account/progress")
    def desktop_account_progress(series_id: str = Query(...), ep: int = Query(..., ge=1, le=100000),
                                 total: int = Query(0, ge=0, le=100000),
                                 position: int = Query(0, ge=0),
                                 duration: int = Query(0, ge=0),
                                 title: str = Query("", max_length=120),
                                 cover: str = Query("", max_length=500)):
        series = {"title": title, "cover": cover} if (title or cover) else None
        result = A.sync_progress(_sid(series_id), ep, total=total, position=position,
                                 duration=duration, series=series)
        if not result.get("ok"):
            raise HTTPException(502, str(result.get("error") or "进度同步失败"))
        return {"synced": True, "episode": result.get("episode")}

    @app.post("/desktop/account/favorite")
    def desktop_account_favorite(series_id: str = Query(...), favorite: bool = Query(...)):
        result = A.set_favorite(_sid(series_id), favorite)
        if not result.get("ok"):
            raise HTTPException(502, str(result.get("error") or "收藏同步失败"))
        return {"synced": True, "favorite": bool(favorite)}


def register_update(app):
    """本地维护: 更新检测路由（指向本分支自己的仓库）。"""
    import desktop_update as U

    @app.get("/desktop/update/check")
    def desktop_update_check(force: bool = Query(False)):
        if force:
            U._cache["at"] = 0.0
            U._cache["data"] = None
        return U.public()


def register_update_download(app):
    """本地维护: 应用内下载新版安装包 + 打开安装包（国内走 Gitee）。"""
    import desktop_update_download as D

    @app.post("/desktop/update/download")
    def desktop_update_download_start(version: str = Query(..., max_length=32),
                                      sha256: str = Query("", max_length=64)):
        result = D.start(version, sha256)
        if not result.get("ok"):
            raise HTTPException(400, str(result.get("error") or "无法开始下载"))
        return result["task"]

    @app.get("/desktop/update/download/{task_id}")
    def desktop_update_download_status(task_id: str):
        result = D.status(task_id)
        if not result.get("ok"):
            raise HTTPException(404, str(result.get("error") or "任务不存在"))
        return result["task"]

    @app.post("/desktop/update/download/{task_id}/launch")
    def desktop_update_download_launch(task_id: str):
        result = D.launch(task_id)
        if not result.get("ok"):
            raise HTTPException(400, str(result.get("error") or "无法打开"))
        return result

    @app.post("/desktop/update/download/{task_id}/cancel")
    def desktop_update_download_cancel(task_id: str):
        return D.cancel(task_id)
