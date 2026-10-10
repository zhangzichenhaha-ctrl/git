from hashlib import sha256
from datetime import datetime
import os
import re
import sys
import time
import textwrap
from html import escape
from pathlib import Path
from urllib.parse import urlencode

import requests
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared_ui import (  # noqa: E402
    inject_theme,
    render_brand_lockup,
    render_dimension_bars,
    render_empty_state,
    render_metric_tile,
    render_page_intro,
    render_score_ring,
    render_skeleton,
    render_status_badge,
)
from shared_ui.feedback import render_request_error  # noqa: E402


BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")


def show_post_error(
    message: str,
    path: str,
    *,
    retryable: bool = False,
    status_code: int | None = None,
) -> None:
    action_labels = {
        "/api/parse_profile": "AI 解析",
        "/api/parse_project": "AI 解析",
        "/api/save_profile": "保存画像",
        "/api/create_project": "发布项目",
        "/api/feedback": "提交反馈",
        "/api/interest": "感兴趣",
        "/api/register": "注册",
        "/api/login": "登录",
        "/api/profile/contact": "保存联系方式设置",
    }
    render_request_error(
        message, method="POST", identity=path, retryable=retryable,
        status_code=status_code, action_label=action_labels.get(path, "原操作按钮"),
    )


def post_api(
    path: str,
    payload: dict,
    error_messages: dict[str, str] | None = None,
    token: str | None = None,
) -> dict | None:
    """Call a backend POST endpoint and show user-friendly errors."""
    try:
        response = requests.post(
            f"{BACKEND_URL}{path}",
            json=payload,
            headers={"Authorization": f"Bearer {token}"} if token else None,
            timeout=60,
        )
        response.raise_for_status()
        result = response.json()
    except requests.HTTPError as error:
        try:
            error_data = error.response.json()
            error_code = (
                error_data.get("error", "request_failed")
                if isinstance(error_data, dict) else "request_failed"
            )
        except (AttributeError, ValueError):
            error_code = "request_failed"
        if error_code == "account_banned":
            reason = ""
            if isinstance(error_data, dict):
                reason = str(error_data.get("reason") or "未说明")
            st.error(
                f"账号已被封禁，原因：{reason}。如有疑问请联系管理员。"
            )
            return None
        if error_messages and error_code in error_messages:
            message = error_messages[error_code]
        else:
            message = "服务暂时不可用，请稍后重试" if error.response.status_code >= 500 else "请求未能完成，请核对输入内容"
        show_post_error(message, path, retryable=error.response.status_code >= 500,
                        status_code=error.response.status_code)
        return None
    except requests.RequestException:
        show_post_error("网络异常，请稍后重试", path, retryable=True)
        return None
    except ValueError:
        show_post_error("后端返回的数据格式不正确", path, retryable=True)
        return None

    if not isinstance(result, dict):
        show_post_error("后端返回的数据格式不正确", path, retryable=True)
        return None
    if not result.get("success") and result.get("status") != "ok":
        show_post_error(result.get("message", "操作失败，请重试"), path)
        return None
    return result


def get_api(
    path: str,
    show_error: bool = True,
    timeout: int = 15,
    expected_empty: str | None = None,
    token: str | None = None,
) -> dict | None:
    """Call a backend GET endpoint."""
    try:
        response = requests.get(
            f"{BACKEND_URL}{path}",
            headers={"Authorization": f"Bearer {token}"} if token else None,
            timeout=timeout,
        )
        response.raise_for_status()
        result = response.json()
    except requests.HTTPError as error:
        if show_error:
            render_request_error(
                "服务暂时不可用，请稍后重试" if error.response.status_code >= 500 else "请求未能完成，请核对访问条件",
                method="GET", identity=path, retryable=error.response.status_code >= 500,
                status_code=error.response.status_code,
            )
        return None
    except requests.RequestException:
        if show_error:
            render_request_error("网络异常，请稍后重试", method="GET", identity=path, retryable=True)
        return None
    except ValueError:
        if show_error:
            render_request_error("后端返回的数据格式不正确", method="GET", identity=path, retryable=True)
        return None

    if not isinstance(result, dict):
        if show_error:
            render_request_error("后端返回的数据格式不正确", method="GET", identity=path, retryable=True)
        return None
    if not result.get("success") and show_error and result.get("message") != expected_empty:
        render_request_error(result.get("message", "读取失败，请重试"), method="GET", identity=path)
    return result


def enforce_current_account_status() -> None:
    """End an existing UI session after the account is banned or deleted."""
    user_id = st.session_state.get("user_id")
    if not user_id:
        return
    try:
        response = requests.get(
            f"{BACKEND_URL}/api/account_status/{user_id}",
            timeout=5,
        )
        response.raise_for_status()
        result = response.json()
    except (requests.RequestException, ValueError):
        return
    if not isinstance(result, dict) or not result.get("success"):
        return

    if not result.get("exists", True):
        st.session_state.clear()
        st.error("账号不存在或已被删除，请重新注册或联系管理员。")
        st.stop()
    if result.get("is_banned"):
        reason = str(result.get("reason") or "未说明")
        st.session_state.clear()
        st.error(f"账号已被封禁，原因：{reason}。如有疑问请联系管理员。")
        st.stop()


def delete_api(path: str, params: dict | None = None) -> dict | None:
    try:
        response = requests.delete(
            f"{BACKEND_URL}{path}", params=params, timeout=30
        )
        response.raise_for_status()
        result = response.json()
    except requests.RequestException:
        render_request_error("网络异常，请稍后重试", method="DELETE", identity=path,
                             retryable=True, action_label="取消收藏")
        return None
    except ValueError:
        render_request_error("后端返回的数据格式不正确", method="DELETE", identity=path,
                             retryable=True, action_label="取消收藏")
        return None
    if not isinstance(result, dict):
        render_request_error("后端返回的数据格式不正确", method="DELETE", identity=path,
                             retryable=True, action_label="取消收藏")
        return None
    if not result.get("success"):
        st.error(result.get("message", "操作失败，请重试"))
        return None
    return result


def queue_success(message: str) -> None:
    st.session_state["success_message"] = message


def show_success(message: str) -> None:
    st.success(message)
    st.toast(message, icon=":material/check_circle:")


def show_queued_success() -> None:
    message = st.session_state.pop("success_message", None)
    if message:
        show_success(message)


def list_to_text(values: list | None) -> str:
    return "\n".join(str(value) for value in (values or []))


def text_to_list(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[,，\n]", value) if item.strip()]


def render_skill_level_editor(skills: list[str]) -> dict[str, str]:
    levels = st.session_state.get("profile_skill_levels", {})
    levels = dict(levels) if isinstance(levels, dict) else {}
    selected = {}
    st.markdown("**技能等级**")
    if not skills:
        st.caption("暂无技能")
    for skill in skills:
        current = str(levels.get(skill) or "")
        options = ["", "熟练", "掌握", "了解"]
        if current and current not in options:
            options.append(current)
        key = "profile_level_" + sha256(skill.encode("utf-8")).hexdigest()[:20]
        value = st.selectbox(
            skill, options, index=options.index(current), key=key,
            format_func=lambda item: item or "未填写",
        )
        levels[skill] = value
        if value:
            selected[skill] = value
    st.session_state["profile_skill_levels"] = levels
    return selected


def set_profile_draft(data: dict, include_raw_text: bool = True) -> None:
    st.session_state["profile_draft"] = True
    if include_raw_text:
        st.session_state["profile_raw_text"] = data.get("raw_text", "") or ""
    st.session_state["profile_skills"] = list_to_text(data.get("skills"))
    levels = data.get("skill_levels")
    st.session_state["profile_skill_levels"] = dict(levels) if isinstance(levels, dict) else {}
    for key in list(st.session_state):
        if key.startswith("profile_level_"):
            del st.session_state[key]
    st.session_state["profile_experience"] = list_to_text(data.get("experience"))
    st.session_state["profile_interests"] = list_to_text(data.get("interests"))
    st.session_state["profile_preference"] = data.get("preference", "") or ""
    st.session_state["profile_time"] = data.get("time_commitment", "未知") or "未知"


def set_project_draft(data: dict) -> None:
    st.session_state["project_draft"] = True
    st.session_state["project_required_skills"] = list_to_text(
        data.get("required_skills")
    )
    st.session_state["project_time"] = data.get("time_requirement", "未知") or "未知"
    st.session_state["project_priority"] = list_to_text(data.get("priority"))
    st.session_state["project_type"] = data.get("project_type", "") or ""
    st.session_state["project_background"] = data.get("background", "") or ""


def set_current_user(
    user_id: int,
    username: str,
    school: str | None,
    token: str | None = None,
    email: str | None = None,
) -> None:
    st.session_state["user_id"] = user_id
    st.session_state["username"] = username
    st.session_state["school"] = school or ""
    st.session_state["email"] = email or ""
    if token:
        st.session_state["token"] = token
    else:
        st.session_state.pop("token", None)


def navigate_to(page: str) -> None:
    st.session_state["_pending_page"] = page
    st.session_state.pop("selected_project_id", None)
    st.session_state.pop("project_return_page", None)


def open_project_detail(project_id: int, return_page: str) -> None:
    st.session_state["selected_project_id"] = project_id
    st.session_state["project_return_page"] = return_page


def _notification_time_label(value: object) -> str:
    raw_value = str(value or "").replace("Z", "+00:00")
    try:
        created_at = datetime.fromisoformat(raw_value)
        now = datetime.now(created_at.tzinfo) if created_at.tzinfo else datetime.now()
        seconds = max(0, int((now - created_at).total_seconds()))
    except ValueError:
        return str(value or "时间未知").replace("T", " ")[:16]

    if seconds < 60:
        return "刚刚"
    if seconds < 3600:
        return f"{seconds // 60} 分钟前"
    if seconds < 86400:
        return f"{seconds // 3600} 小时前"
    if seconds < 604800:
        return f"{seconds // 86400} 天前"
    return created_at.strftime("%Y-%m-%d %H:%M")


def _notification_preview(value: object, max_length: int = 100) -> str:
    preview = " ".join(str(value or "").split())
    if len(preview) > max_length:
        return preview[: max_length - 1] + "…"
    return preview or "暂无内容"


def _mark_notification_read(notification_id: int, user_id: int) -> bool:
    result = post_api(
        f"/api/notifications/{notification_id}/read",
        {"user_id": user_id},
    )
    return bool(result and result.get("success"))


@st.dialog("双方匹配成功")
def show_notification_match_dialog(
    match_detail: dict,
    counterpart_school: str = "",
) -> None:
    counterpart = match_detail.get("counterpart") or {}
    st.markdown(f"**用户名**：{counterpart.get('username') or '未提供'}")
    st.markdown(f"**学校**：{counterpart_school or '未提供'}")

    contact_value = counterpart.get("contact_value") or ""
    contact_method = counterpart.get("contact_method") or ""
    if contact_value:
        method_labels = {
            "wechat": "微信",
            "qq": "QQ",
            "phone": "手机号",
            "other": "其他联系方式",
        }
        st.markdown(
            f"**{method_labels.get(contact_method, '联系方式')}**："
            f"{contact_value}"
        )
    else:
        st.info("对方暂未公开联系方式")


def _handle_notification_click(item: dict, user_id: int) -> None:
    notification_id = item.get("notification_id")
    if notification_id is None:
        return
    if not _mark_notification_read(int(notification_id), user_id):
        return

    notification_type = item.get("type")
    project_id = item.get("related_project_id")
    related_user_id = item.get("related_user_id")

    if notification_type == "candidate_interested":
        st.session_state["selected_project_id"] = project_id
        st.session_state["notification_target_candidate_id"] = related_user_id
        st.session_state["_pending_page"] = "我的项目"
        st.rerun()
    elif notification_type == "mutual_match":
        if not project_id:
            st.toast("匹配项目不存在")
            return
        match_user_id = user_id
        project_snapshot = get_api(
            f"/api/project/{project_id}?user_id={user_id}",
            show_error=False,
        )
        if (
            project_snapshot
            and project_snapshot.get("owner_id") == user_id
            and related_user_id
        ):
            match_user_id = int(related_user_id)
        match_detail = get_api(
            f"/api/match/{match_user_id}/{project_id}?viewer_id={user_id}",
            show_error=False,
        )
        if match_detail and match_detail.get("mutual"):
            counterpart_school = ""
            if match_user_id != user_id and project_snapshot:
                counterpart_school = str(project_snapshot.get("owner_school") or "")
            show_notification_match_dialog(match_detail, counterpart_school)
        else:
            st.toast("匹配详情暂时不可用")
    elif notification_type == "candidate_declined":
        navigate_to("匹配推荐")
        st.rerun()
    elif notification_type in {
        "project_moderated",
        "project_restored",
        "project_status_changed",
    }:
        if project_id:
            open_project_detail(int(project_id), "通知")
            st.session_state["_pending_page"] = "通知"
            st.rerun()
    elif notification_type == "project_deleted":
        st.toast("该项目已删除")
        st.rerun()
    elif notification_type == "feedback_reply":
        navigate_to("意见反馈")
        st.rerun()
    else:
        st.rerun()


def render_page_heading(title: str, description: str) -> None:
    render_page_intro(title, description)


def profile_completeness(profile: dict | None) -> int:
    if not profile or not profile.get("success"):
        return 0
    checks = [
        bool(profile.get("skills")),
        bool(profile.get("experience")),
        bool(profile.get("interests")),
        bool(profile.get("preference")),
        bool(profile.get("time_commitment") and profile.get("time_commitment") != "未知"),
    ]
    return round(sum(checks) / len(checks) * 100)


def load_home_overview(force: bool = False) -> dict:
    user_id = st.session_state["user_id"]
    cache_key = f"home_overview_{user_id}"
    if force or cache_key not in st.session_state:
        profile = get_api(f"/api/profile/{user_id}", show_error=False)
        projects = get_api(f"/api/my_projects/{user_id}", show_error=False)
        matches = get_api(
            f"/api/match_list/{user_id}?scope=cross_school",
            show_error=False,
            timeout=120,
        )
        st.session_state[cache_key] = {
            "profile": profile or {},
            "projects": (projects or {}).get("projects", []),
            "matches": (matches or {}).get("matches", []),
            "load_failed": (
                any(item is None for item in (profile, projects, matches))
                or bool(profile and not profile.get("success") and profile.get("message") != "画像不存在")
                or bool(projects and not projects.get("success"))
                or bool(matches and not matches.get("success") and matches.get("message") != "请先填写画像")
            ),
        }
    return st.session_state[cache_key]


def render_skill_pills(skills: list | None) -> None:
    values = [str(skill) for skill in (skills or []) if str(skill).strip()]
    if not values:
        st.caption("暂未填写技能")
        return
    pills = "".join(
        f"<span class='zl-pill'>{escape(skill)}</span>" for skill in values[:8]
    )
    st.markdown(pills, unsafe_allow_html=True)


def render_project_status(status: str) -> None:
    render_status_badge(status)


def render_match_breakdown(match: dict, key: str) -> None:
    """Show the three scoring dimensions as a compact visual analysis."""
    values = [
        {"维度": "技能", "得分": round(max(0.0, min(float(match.get("skill_match", 0)), 1.0)) * 100, 1)},
        {"维度": "时间", "得分": round(max(0.0, min(float(match.get("time_match", 0)), 1.0)) * 100, 1)},
        {"维度": "经验", "得分": round(max(0.0, min(float(match.get("experience_match", 0)), 1.0)) * 100, 1)},
    ]
    st.vega_lite_chart(
        {
            "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
            "data": {"values": values},
            "mark": {"type": "bar", "cornerRadiusEnd": 5},
            "encoding": {
                "y": {"field": "维度", "type": "nominal", "sort": ["技能", "时间", "经验"], "title": None},
                "x": {"field": "得分", "type": "quantitative", "scale": {"domain": [0, 100]}, "title": "得分（%）"},
                "color": {
                    "field": "维度",
                    "type": "nominal",
                    "scale": {
                        "domain": ["技能", "时间", "经验"],
                        "range": ["#2563EB", "#0891B2", "#7C3AED"],
                    },
                    "legend": None,
                },
                "tooltip": [
                    {"field": "维度", "type": "nominal"},
                    {"field": "得分", "type": "quantitative", "format": ".1f"},
                ],
            },
            "height": 110,
        },
        use_container_width=True,
        key=key,
    )


def render_mutual_contact(candidate_user_id: int, project_id: int) -> None:
    with st.spinner("正在读取已解锁的联系方式..."):
        result = get_api(
            f"/api/match/{candidate_user_id}/{project_id}"
            f"?viewer_id={st.session_state['user_id']}"
        )
    if not result or not result.get("mutual"):
        return

    counterpart = result.get("counterpart") or {}
    method_labels = {
        "wechat": "微信",
        "qq": "QQ",
        "phone": "手机号",
        "other": "其他联系方式",
    }
    with st.expander(
        f"联系 {counterpart.get('username') or '对方'}",
        expanded=True,
    ):
        st.markdown("**账号邮箱**")
        if counterpart.get("email_verified"):
            st.code(counterpart.get("email") or "未提供")
        else:
            st.caption("对方尚未验证邮箱，暂不展示邮箱地址。")
        contact_value = counterpart.get("contact_value") or ""
        if contact_value:
            method = method_labels.get(
                counterpart.get("contact_method"), "自选联系方式"
            )
            st.markdown(f"**{method}**")
            st.code(contact_value)
        else:
            st.caption("对方未开放额外联系方式，可先通过账号邮箱联系。")
        st.caption("联系方式仅向互选成功的双方展示，请尊重对方隐私。")


def render_candidate_card(candidate: dict, project_id: int) -> None:
    user_id = candidate.get("user_id")
    owner_status = candidate.get("owner_status", "pending")
    mutual = bool(candidate.get("mutual"))
    with st.container(border=True, key=f"candidate_card_{project_id}_{user_id}"):
        heading, score_column = st.columns([4, 1])
        with heading:
            st.subheader(candidate.get("username") or "未命名用户")
            st.caption(
                f"{candidate.get('school') or '学校未填写'} · "
                f"{candidate.get('major') or '专业未填写'} · "
                f"{candidate.get('grade') or '年级未填写'}"
            )
        with score_column:
            render_score_ring(candidate.get("total_score", 0), size="small")

        render_dimension_bars(
            (
                ("技能匹配", candidate.get("skill_match", 0), "blue"),
                ("时间匹配", candidate.get("time_match", 0), "cyan"),
                ("经验匹配", candidate.get("experience_match", 0), "violet"),
            )
        )

        profile_left, profile_right = st.columns(2)
        with profile_left:
            st.markdown("**技能**")
            render_skill_pills(candidate.get("skills"))
            st.markdown("**时间投入**")
            st.write(candidate.get("time_commitment") or "未知")
        with profile_right:
            st.markdown("**经历**")
            st.write("、".join(candidate.get("experience") or []) or "未填写")
            st.markdown("**兴趣方向**")
            st.write("、".join(candidate.get("interests") or []) or "未填写")

        st.info(candidate.get("explanation") or "暂无匹配解释")
        if mutual:
            st.success("双方已匹配，联系方式已解锁")
            render_mutual_contact(user_id, project_id)
        elif owner_status == "rejected":
            st.warning("当前标记为暂不考虑，你可以随时重新选择")
        else:
            st.caption("候选人已表达合作意向，待你确认")

        accept_column, decline_column = st.columns(2)
        with accept_column:
            accept_clicked = st.button(
                "已感兴趣" if owner_status == "interested" else "感兴趣",
                key=(
                    f"interested_owner_accept_{project_id}_{user_id}"
                    if owner_status == "interested"
                    else f"owner_accept_{project_id}_{user_id}"
                ),
                type="primary",
                disabled=owner_status == "interested",
                use_container_width=True,
                icon=":material/favorite:",
            )
        with decline_column:
            decline_clicked = st.button(
                "已暂不考虑" if owner_status == "rejected" else "暂不考虑",
                key=f"danger_owner_decline_{project_id}_{user_id}",
                disabled=owner_status == "rejected",
                use_container_width=True,
                icon=":material/block:",
            )
        action = "interested" if accept_clicked else ("rejected" if decline_clicked else None)
        if action:
            with st.spinner("正在保存候选人状态..."):
                result = post_api(
                    "/api/owner_candidate_action",
                    {
                        "owner_id": st.session_state["user_id"],
                        "project_id": project_id,
                        "user_id": user_id,
                        "action": action,
                    },
                )
            if result:
                queue_success("候选人状态已更新")
                st.rerun()


def render_my_match_card(match: dict) -> None:
    project_id = match.get("project_id")
    relationship_status = match.get("relationship_status", "user_interested")
    status_labels = {
        "user_interested": ("等待发起人处理", "info"),
        "mutual": ("双方已匹配", "success"),
        "owner_declined": ("发起人暂不考虑", "warning"),
    }
    status_text, status_kind = status_labels.get(
        relationship_status, ("状态待确认", "info")
    )
    with st.container(border=True, key=f"my_match_card_{project_id}"):
        heading, score_column = st.columns([4, 1])
        with heading:
            st.subheader(match.get("project_name") or "未命名项目")
            st.caption(
                f"发起人：{match.get('owner_username') or '未填写'} · "
                f"{match.get('owner_school') or '学校未填写'}"
            )
        with score_column:
            render_score_ring(match.get("total_score", 0), size="small")

        getattr(st, status_kind)(status_text)
        render_dimension_bars(
            (
                ("技能匹配", match.get("skill_match", 0), "blue"),
                ("时间匹配", match.get("time_match", 0), "cyan"),
                ("经验匹配", match.get("experience_match", 0), "violet"),
            )
        )
        with st.expander("查看匹配分析", expanded=False):
            render_match_breakdown(match, f"my_match_chart_{project_id}")
            st.info(match.get("explanation") or "暂无匹配解释")
        if relationship_status == "mutual":
            render_mutual_contact(
                st.session_state["user_id"],
                project_id,
            )
        st.button(
            "查看项目详情",
            key=f"my_match_detail_{project_id}",
            on_click=open_project_detail,
            args=(project_id, "我的匹配"),
            icon=":material/arrow_forward:",
        )


def show_project_detail() -> None:
    project_id = st.session_state.get("selected_project_id")
    return_page = st.session_state.get("project_return_page", "发现项目")
    if st.button(
        "返回项目列表",
        key=f"back_project_{project_id}",
        icon=":material/arrow_back:",
    ):
        st.session_state.pop("selected_project_id", None)
        st.session_state.pop("project_return_page", None)
        st.rerun()

    with st.spinner("正在读取项目详情..."):
        project = get_api(
            f"/api/project/{project_id}?user_id={st.session_state['user_id']}"
        )
    if not project or not project.get("success"):
        return

    heading_left, heading_right = st.columns([4, 1])
    with heading_left:
        render_page_heading(
            project.get("name", "未命名项目"),
            f"由 {project.get('owner_username') or '匿名用户'} 发起",
        )
    with heading_right:
        render_project_status(project.get("status", ""))

    scope_label = (
        "同校优先" if project.get("scope") == "same_school" else "跨校开放"
    )
    created_at = str(project.get("created_at") or "")[:10] or "未知"
    st.markdown(
        f"<div class='zl-detail-band'>"
        f"{escape(project.get('owner_school') or '学校未填写')} · "
        f"{escape(scope_label)} · 发布于 {escape(created_at)}</div>",
        unsafe_allow_html=True,
    )

    summary_left, summary_right = st.columns([2, 1])
    with summary_left:
        st.subheader("项目背景与目标")
        st.write(project.get("background") or project.get("raw_text") or "暂未填写")
        if project.get("background") and project.get("raw_text"):
            st.markdown("**需求描述**")
            st.write(project.get("raw_text"))
    with summary_right:
        st.markdown("**项目类型**")
        st.write(project.get("project_type") or "未填写")
        st.markdown("**时间要求**")
        st.write(project.get("time_requirement") or "未知")
        st.markdown("**所需技能**")
        render_skill_pills(project.get("required_skills"))

    st.subheader("优先条件")
    priorities = project.get("priority") or []
    if priorities:
        for item in priorities:
            st.markdown(f"- {item}")
    else:
        st.caption("暂无额外优先条件")

    st.subheader("发起人公开信息")
    owner_columns = st.columns(3)
    owner_columns[0].metric("学校", project.get("owner_school") or "未填写")
    owner_columns[1].metric("专业", project.get("owner_major") or "未填写")
    owner_columns[2].metric("年级", project.get("owner_grade") or "未填写")

    is_owner = project.get("owner_id") == st.session_state.get("user_id")
    is_interested = bool(project.get("interested"))
    can_apply = (
        project.get("status") == "recruiting" and not is_owner and not is_interested
    )
    if st.button(
        (
            "感兴趣"
            if can_apply
            else (
                "已感兴趣"
                if is_interested
                else ("这是我发布的项目" if is_owner else "当前不可申请")
            )
        ),
        key=f"detail_interest_{project_id}_{return_page}",
        type="primary",
        disabled=not can_apply,
        icon=":material/favorite:",
    ):
        with st.spinner("正在保存感兴趣状态..."):
            result = post_api(
                "/api/interest",
                {"user_id": st.session_state["user_id"], "project_id": project_id},
            )
        if result:
            show_success("已记录你的意向")

    favorited = bool(project.get("favorited"))
    if st.button(
        "已收藏" if favorited else "收藏项目",
        key=f"detail_favorite_{project_id}_{return_page}",
        disabled=favorited,
        icon=":material/bookmark:",
    ):
        with st.spinner("正在保存收藏..."):
            result = post_api(
                "/api/favorites",
                {"user_id": st.session_state["user_id"], "project_id": project_id},
            )
        if result and result.get("favorited"):
            queue_success("已加入收藏")
            st.rerun()


def render_match_card(match: dict, *, source: str) -> None:
    project_id = match.get("project_id")
    is_interested = bool(match.get("interested")) or match.get("status") == "interested"
    total_score = max(0.0, min(float(match.get("total_score", 0)), 1.0))
    skill_match = max(0.0, min(float(match.get("skill_match", 0)), 1.0))
    time_match = max(0.0, min(float(match.get("time_match", 0)), 1.0))
    experience_match = max(0.0, min(float(match.get("experience_match", 0)), 1.0))

    score_accent = "green" if total_score >= 0.8 else "blue" if total_score >= 0.6 else "slate"
    with st.container(border=True, key=f"match_card_{source}_{project_id}_score_{score_accent}"):
        title_column, score_column = st.columns([4, 1])
        with title_column:
            st.subheader(match.get("project_name", "未命名项目"))
            school = match.get("owner_school") or "学校未填写"
            scope = "同校优先" if match.get("scope") == "same_school" else "跨校开放"
            st.caption(f"{school} · {scope}")
            render_project_status(match.get("project_status", "recruiting"))
        with score_column:
            render_score_ring(total_score, size="small")

        render_dimension_bars(
            (
                ("技能匹配", skill_match, "blue"),
                ("时间匹配", time_match, "cyan"),
                ("经验匹配", experience_match, "violet"),
            )
        )

        with st.expander("查看匹配分析", expanded=False):
            render_match_breakdown(match, f"{source}_match_chart_{project_id}")
            st.info(match.get("explanation") or "暂无匹配解释")
        action_left, action_right = st.columns([1, 3])
        with action_left:
            if st.button(
                "已感兴趣" if is_interested else "感兴趣",
                key=f"interested_{source}_{project_id}",
                type="primary",
                disabled=is_interested,
                use_container_width=True,
                icon=":material/favorite:",
            ):
                if project_id is None:
                    st.error("项目信息不完整，请刷新后重试")
                else:
                    with st.spinner("正在保存感兴趣状态..."):
                        result = post_api(
                            "/api/interest",
                            {
                                "user_id": st.session_state["user_id"],
                                "project_id": project_id,
                            },
                        )
                    if result and result.get("interested"):
                        match["interested"] = True
                        match["status"] = "interested"
                        queue_success("已记录你的意向")
                        st.rerun()
        with action_right:
            st.button(
                "查看详情",
                key=f"{source}_detail_{project_id}",
                on_click=open_project_detail,
                args=(project_id, "首页" if source == "home" else "匹配推荐"),
                use_container_width=True,
                icon=":material/arrow_forward:",
            )


def render_project_card(project: dict) -> None:
    project_id = project.get("project_id")
    status_accent = {"recruiting": "green", "full": "amber", "removed": "red"}.get(project.get("status"), "slate")
    with st.container(border=True, key=f"project_card_{project_id}_state_{status_accent}"):
        heading, score_column = st.columns([4, 1])
        with heading:
            st.subheader(project.get("name") or "未命名项目")
            scope_label = (
                "同校优先"
                if project.get("scope") == "same_school"
                else "跨校开放"
            )
            project_type = project.get("project_type") or "类型未填写"
            st.caption(
                f"{project.get('owner_school') or '学校未填写'} · "
                f"{project_type} · {scope_label}"
            )
        with score_column:
            if project.get("total_score") is not None:
                st.metric("匹配度", f"{float(project['total_score']):.0%}")
            else:
                render_project_status(project.get("status", ""))

        description = project.get("background") or project.get("raw_text") or "暂无项目描述"
        st.write(description[:180] + ("..." if len(description) > 180 else ""))
        render_skill_pills(project.get("required_skills"))
        st.caption(
            f"时间要求：{project.get('time_requirement') or '未知'} · "
            f"发布于 {str(project.get('created_at') or '')[:10] or '未知'}"
        )

        detail_column, interest_column, favorite_column, status_column = st.columns([1, 1, 1, 2])
        with detail_column:
            st.button(
                "查看详情",
                key=f"discover_detail_{project_id}",
                on_click=open_project_detail,
                args=(project_id, "发现项目"),
                use_container_width=True,
                icon=":material/arrow_forward:",
            )
        with interest_column:
            is_owner = project.get("owner_id") == st.session_state.get("user_id")
            is_interested = bool(project.get("interested"))
            can_apply = project.get("status") == "recruiting" and not is_owner
            if st.button(
                "已感兴趣" if is_interested else "感兴趣",
                key=f"discover_interest_{project_id}",
                type="primary",
                disabled=is_interested or not can_apply,
                use_container_width=True,
                icon=":material/favorite:",
            ):
                with st.spinner("正在保存感兴趣状态..."):
                    result = post_api(
                        "/api/interest",
                        {
                            "user_id": st.session_state["user_id"],
                            "project_id": project_id,
                        },
                    )
                if result:
                    queue_success("已记录你的意向")
                    st.rerun()
        with favorite_column:
            favorited = bool(project.get("favorited"))
            if st.button(
                "已收藏" if favorited else "收藏",
                key=f"discover_favorite_{project_id}",
                disabled=favorited,
                use_container_width=True,
                icon=":material/bookmark:",
            ):
                with st.spinner("正在保存收藏..."):
                    result = post_api(
                        "/api/favorites",
                        {
                            "user_id": st.session_state["user_id"],
                            "project_id": project_id,
                        },
                    )
                if result and result.get("favorited"):
                    queue_success("已加入收藏")
                    st.rerun()
        with status_column:
            if project.get("total_score") is not None:
                render_project_status(project.get("status", ""))


def show_home_page() -> None:
    if (
        st.session_state.get("selected_project_id")
        and st.session_state.get("project_return_page") == "首页"
    ):
        show_project_detail()
        return

    username = st.session_state.get("username", "同学")
    school = st.session_state.get("school") or "高校科研社区"
    st.markdown(
        textwrap.dedent(
            f"""
        <section class="zl-hero">
            <div class="zl-eyebrow" style="color:#83c9ff">RESEARCH COLLABORATION</div>
            <h1>你好，{escape(username)}<span class="zl-hero-status">已登录</span></h1>
            <p>{escape(school)} · 寻找契合的科研项目，结识志同道合的伙伴。</p>
        </section>
        """,
        ),
        unsafe_allow_html=True,
    )

    with st.spinner("正在整理你的协作概览..."):
        overview = load_home_overview()
    if overview.get("load_failed"):
        st.warning("协作概览暂未完整加载，请重新读取。")
        st.button(
            "重新加载概览", key="retry_home_overview", icon=":material/refresh:",
            on_click=lambda: st.session_state.pop(f"home_overview_{st.session_state['user_id']}", None),
        )
        return
    completeness = profile_completeness(overview["profile"])
    projects = overview["projects"]
    matches = overview["matches"]
    interested_count = sum(
        1 for item in matches if item.get("interested") or item.get("status") == "interested"
    )

    metric_columns = st.columns(4)
    metrics = (
        ("画像完整度", f"{completeness}%", "blue", "person_search", "完善资料，丰富匹配依据"),
        ("推荐项目", str(len(matches)), "cyan", "recommend", "根据当前画像生成"),
        ("我发布的项目", str(len(projects)), "violet", "science", "由你发起的合作机会"),
        ("已表达意向", str(interested_count), "green", "handshake", "已提交合作意向的项目"),
    )
    for column, (label, value, accent, icon, caption) in zip(metric_columns, metrics):
        with column:
            render_metric_tile(
                label,
                value,
                accent=accent,
                icon=icon,
                caption=caption,
            )

    st.markdown(
        "<div class='zl-section'><div class='zl-section-title'>快速开始</div>"
        "<div class='zl-section-caption'>完善画像，发现项目，发起合作。</div></div>",
        unsafe_allow_html=True,
    )
    quick_columns = st.columns(3)
    quick_actions = (
        (quick_columns[0], "完善能力画像", "记录专业技能与研究经历", "我的画像", "badge"),
        (quick_columns[1], "发现科研项目", "浏览同校与跨校开放的合作机会", "发现项目", "travel_explore"),
        (quick_columns[2], "发布招募需求", "明确研究目标与合作需求", "发布项目", "add_circle"),
    )
    for column, title, description, page, icon in quick_actions:
        with column:
            with st.container(border=True, key=f"quick_{page}"):
                st.markdown(
                    f'<span class="zl-quick-icon material-symbols-rounded">{icon}</span>',
                    unsafe_allow_html=True,
                )
                st.subheader(title)
                st.caption(description)
                st.button(
                    "进入",
                    key=f"home_go_{page}",
                    on_click=navigate_to,
                    args=(page,),
                    use_container_width=True,
                    icon=":material/arrow_forward:",
                )

    st.markdown(
        "<div class='zl-section'><div class='zl-section-title'>优先推荐</div>"
        "<div class='zl-section-caption'>按当前画像的匹配评分排序，供合作选择参考。</div></div>",
        unsafe_allow_html=True,
    )
    if matches:
        for match in matches[:2]:
            render_match_card(match, source="home")
    else:
        render_empty_state(
            "暂时没有推荐项目",
            "请完善画像，或浏览当前开放的科研项目。",
            icon="manage_search",
        )

    st.button(
        "刷新概览",
        key="refresh_home",
        icon=":material/refresh:",
        on_click=lambda: st.session_state.pop(f"home_overview_{st.session_state['user_id']}", None),
    )


def show_discover_projects_page() -> None:
    if (
        st.session_state.get("selected_project_id")
        and st.session_state.get("project_return_page") == "发现项目"
    ):
        show_project_detail()
        return

    render_page_heading("发现项目", "浏览同校与跨校科研项目，寻找契合的合作机会。")
    keyword = st.text_input(
        "搜索项目",
        placeholder="搜索项目名称、描述、学校或技能",
    ).strip()
    school_column, type_column, skill_column = st.columns(3)
    with school_column:
        school = st.text_input("学校", placeholder="例如：华东师范大学").strip()
    with type_column:
        project_type = st.text_input("项目类型", placeholder="例如：大模型应用").strip()
    with skill_column:
        skill = st.text_input("所需技能", placeholder="例如：Python").strip()

    scope_column, status_column, sort_column = st.columns(3)
    with scope_column:
        scope_label = st.selectbox("开放范围", ["全部范围", "同校优先", "跨校开放"])
    with status_column:
        status_label = st.selectbox(
            "招募状态", ["招募中", "全部状态", "已满员", "已关闭", "已完成"]
        )
    with sort_column:
        sort_label = st.selectbox("排序", ["最新发布", "匹配度优先"])

    scope_map = {"全部范围": "", "同校优先": "same_school", "跨校开放": "cross_school"}
    status_map = {
        "全部状态": "all",
        "招募中": "recruiting",
        "已满员": "full",
        "已关闭": "closed",
        "已完成": "completed",
    }
    page = int(st.session_state.get("discover_page", 1))
    query = urlencode(
        {
            "keyword": keyword,
            "school": school,
            "project_type": project_type,
            "skill": skill,
            "scope": scope_map[scope_label],
            "status": status_map[status_label],
            "sort": "match" if sort_label == "匹配度优先" else "latest",
            "page": page,
            "page_size": 8,
            "user_id": st.session_state["user_id"],
        }
    )
    with st.spinner("正在搜索项目..."):
        result = get_api(f"/api/projects?{query}")
    if not result or not result.get("success"):
        return

    projects = result.get("projects", [])
    pagination = result.get("pagination", {})
    total = int(pagination.get("total", len(projects)))
    total_pages = max(int(pagination.get("total_pages", 1)), 1)
    if page > total_pages:
        st.session_state["discover_page"] = total_pages
        st.rerun()

    st.caption(f"找到 {total} 个符合条件的项目 · 第 {page}/{total_pages} 页")
    if not projects:
        render_empty_state(
            "没有符合当前条件的项目",
            "可以尝试清空关键词、放宽筛选条件或切换开放范围。",
            icon="filter_alt_off",
        )
        return
    for project in projects:
        render_project_card(project)

    previous_column, page_column, next_column = st.columns([1, 2, 1])
    with previous_column:
        if st.button("上一页", disabled=page <= 1, use_container_width=True):
            st.session_state["discover_page"] = page - 1
            st.rerun()
    with page_column:
        st.markdown(
            f"<div style='text-align:center;padding:.65rem;color:#667085'>"
            f"第 {page} 页，共 {total_pages} 页</div>",
            unsafe_allow_html=True,
        )
    with next_column:
        if st.button("下一页", disabled=page >= total_pages, use_container_width=True):
            st.session_state["discover_page"] = page + 1
            st.rerun()


def show_auth_page() -> None:
    brand_column, form_column = st.columns([1.18, 0.82], gap="large")
    with brand_column:
        with st.container(key="auth_copy"):
            render_brand_lockup(inverse=True, subtitle="高校科研协作匹配平台")
            st.markdown(
                textwrap.dedent(
                    """
                <div class="zl-auth-kicker">RESEARCH COLLABORATION NETWORK</div>
                <h1>知遇 LinkLab</h1>
                <p>找到你的科研搭档。以能力连接机遇，与同行共赴探索。</p>
                <div class="zl-auth-proof">
                    <span>结构化能力画像</span>
                    <span>可解释匹配</span>
                    <span>同校优先 · 跨校开放</span>
                </div>
                """,
                ),
                unsafe_allow_html=True,
            )

    with form_column:
        with st.container(key="auth_panel"):
            auth_mode = st.segmented_control(
                "账户入口",
                ["登录", "注册"],
                default="登录",
                selection_mode="single",
                label_visibility="collapsed",
                key="auth_mode",
            )

            if auth_mode == "注册":
                st.markdown(
                    '<div class="zl-auth-panel-head"><h2>创建账号</h2>'
                    '<p>加入高校科研协作网络</p></div>',
                    unsafe_allow_html=True,
                )
                st.caption("账号信息 → 邮箱验证 → 进入平台")
                st.info("创建账号后进入邮箱验证步骤，发送验证码并输入邮件中的 6 位数字。")
                with st.form("register_form"):
                    identity_left, identity_right = st.columns(2)
                    with identity_left:
                        username = st.text_input("用户名", key="register_username")
                    with identity_right:
                        email = st.text_input("邮箱", key="register_email")
                    password_left, password_right = st.columns(2)
                    with password_left:
                        password = st.text_input(
                            "密码", type="password", key="register_password"
                        )
                    with password_right:
                        confirm_password = st.text_input(
                            "确认密码",
                            type="password",
                            key="register_confirm_password",
                        )
                    school = st.text_input("学校", key="register_school")
                    detail_left, detail_right = st.columns(2)
                    with detail_left:
                        major = st.text_input("专业", key="register_major")
                    with detail_right:
                        grade = st.text_input("年级", key="register_grade")
                    submitted = st.form_submit_button(
                        "创建账号",
                        icon=":material/person_add:",
                        type="primary",
                        use_container_width=True,
                    )

                if submitted:
                    if (
                        not username.strip()
                        or not email.strip()
                        or not password
                        or not confirm_password
                    ):
                        st.warning("用户名、邮箱和密码不能为空")
                    elif password != confirm_password:
                        st.error("两次输入的密码不一致")
                    else:
                        with st.spinner("正在创建账号..."):
                            result = post_api(
                                "/api/auth/register",
                                {
                                    "username": username.strip(),
                                    "email": email.strip(),
                                    "password": password,
                                    "confirm_password": confirm_password,
                                    "school": school.strip(),
                                    "major": major.strip(),
                                    "grade": grade.strip(),
                                },
                            )
                        if result:
                            with st.spinner("账号已创建，正在进入邮箱验证..."):
                                login_result = post_api(
                                    "/api/auth/login",
                                    {"username": username.strip(), "password": password},
                                    error_messages={
                                        "user_not_found": "账号已创建，请使用用户名登录",
                                        "invalid_password": "账号已创建，请使用刚才设置的密码登录",
                                    },
                                )
                            if login_result and login_result.get("token"):
                                set_current_user(
                                    login_result["user_id"],
                                    login_result["username"],
                                    login_result.get("school"),
                                    login_result["token"],
                                    login_result.get("email"),
                                )
                                st.session_state["email_verification_onboarding"] = True
                                queue_success("注册成功，请验证邮箱")
                                st.rerun()
                            else:
                                show_success("注册成功，请登录后验证邮箱")
            else:
                st.markdown(
                    '<div class="zl-auth-panel-head"><h2>欢迎回来</h2>'
                    '<p>继续探索适合你的科研合作机会</p></div>',
                    unsafe_allow_html=True,
                )
                with st.form("login_form"):
                    username = st.text_input("用户名", key="login_username")
                    password = st.text_input(
                        "密码", type="password", key="login_password"
                    )
                    submitted = st.form_submit_button(
                        "登录",
                        icon=":material/login:",
                        type="primary",
                        use_container_width=True,
                    )

                if submitted:
                    if not username.strip() or not password:
                        st.warning("请输入用户名和密码")
                    else:
                        with st.spinner("正在验证账号..."):
                            result = post_api(
                                "/api/auth/login",
                                {"username": username.strip(), "password": password},
                                error_messages={
                                    "user_not_found": "用户不存在",
                                    "invalid_password": "密码错误",
                                },
                            )
                        if result:
                            token = result.get("token")
                            if not token:
                                st.error("未获取到登录凭证，请重新登录")
                            else:
                                set_current_user(
                                    result["user_id"],
                                    result["username"],
                                    result.get("school"),
                                    token,
                                    result.get("email"),
                                )
                                queue_success("登录成功")
                                st.rerun()

            st.markdown(
                '<div class="zl-auth-foot">登录即表示你同意遵守平台科研协作规范</div>',
                unsafe_allow_html=True,
            )
            st.caption("邮箱验证版 · 2026.10.08")


def render_email_verification_panel(user_id: int, *, context: str = "profile") -> bool:
    """Render the reusable email verification flow and return its current status."""
    token = st.session_state.get("token")
    email_status_key = f"email_status_{user_id}"
    if token and email_status_key not in st.session_state:
        with st.spinner("正在检查邮箱状态..."):
            status_result = get_api(
                "/api/email/status",
                token=token,
                show_error=False,
            )
        if status_result and status_result.get("success"):
            st.session_state[email_status_key] = status_result
            st.session_state["email_resend_available_at"] = (
                time.time() + int(status_result.get("resend_after") or 0)
            )

    email_status = st.session_state.get(email_status_key) or {}
    verified = bool(email_status.get("verified"))
    suffix = "onboarding" if context == "onboarding" else "profile"
    with st.container(border=True):
        email_column, action_column = st.columns([3, 1], vertical_alignment="center")
        with email_column:
            st.markdown("**账号邮箱验证**")
            st.caption(
                email_status.get("email")
                or st.session_state.get("email")
                or "当前邮箱"
            )
            if not email_status.get("enabled", True):
                st.info("邮箱验证服务暂未启用，你可以先进入平台，稍后再完成验证。")
            elif verified:
                st.success("邮箱已验证，可在双方互选成功后展示。")
            else:
                st.warning("邮箱尚未验证。发送验证码后，在下方输入邮件中的 6 位数字。")
        with action_column:
            resend_after = max(
                0,
                int(st.session_state.get("email_resend_available_at", 0) - time.time()),
            )
            send_disabled = bool(
                verified
                or not email_status.get("enabled", True)
                or resend_after > 0
                or not token
            )
            send_label = f"{resend_after} 秒后重发" if resend_after > 0 else "发送验证码"
            if st.button(
                send_label,
                key=f"send_email_code_{suffix}",
                icon=":material/outgoing_mail:",
                disabled=send_disabled,
                use_container_width=True,
            ):
                with st.spinner("正在发送验证码..."):
                    result = post_api(
                        "/api/email/send_code",
                        {},
                        token=token,
                        error_messages={
                            "email_verification_disabled": "邮箱验证功能暂未开放",
                            "email_verification_unavailable": "邮箱服务配置尚未完成",
                            "email_delivery_failed": "邮件发送失败，请稍后重试",
                            "send_too_frequent": "发送过于频繁，请稍后重试",
                            "daily_limit_reached": "今日发送次数已达上限",
                            "email_already_verified": "邮箱已经验证",
                        },
                    )
                if result:
                    st.session_state["email_code_sent"] = True
                    st.session_state["email_resend_available_at"] = (
                        time.time() + int(result.get("resend_after") or 60)
                    )
                    st.session_state.pop(email_status_key, None)
                    queue_success("验证码已发送，请检查收件箱和垃圾箱")
                    st.rerun()
            if resend_after > 0 and st.button(
                "刷新发送状态",
                key=f"refresh_email_resend_{suffix}",
                icon=":material/refresh:",
                use_container_width=True,
            ):
                st.session_state.pop(email_status_key, None)
                st.rerun()

        if st.session_state.get("email_code_sent") and not verified:
            code_column, verify_column = st.columns([3, 1], vertical_alignment="bottom")
            with code_column:
                verification_code = st.text_input(
                    "6 位邮箱验证码",
                    key=f"email_verification_code_{suffix}",
                    max_chars=6,
                    placeholder="请输入邮件中的验证码",
                )
            with verify_column:
                if st.button(
                    "完成验证",
                    key=f"verify_email_code_{suffix}",
                    type="primary",
                    icon=":material/verified:",
                    use_container_width=True,
                ):
                    if not re.fullmatch(r"\d{6}", verification_code.strip()):
                        st.error("请输入 6 位数字验证码")
                    else:
                        with st.spinner("正在验证邮箱..."):
                            result = post_api(
                                "/api/email/verify",
                                {"code": verification_code.strip()},
                                token=token,
                                error_messages={
                                    "invalid_code": "验证码错误或已失效",
                                    "code_expired": "验证码已过期，请重新发送",
                                    "too_many_attempts": "尝试次数过多，请重新发送验证码",
                                    "email_verification_unavailable": "邮箱验证服务暂不可用",
                                },
                            )
                        if result:
                            st.session_state.pop("email_code_sent", None)
                            st.session_state.pop(
                                f"email_verification_code_{suffix}", None
                            )
                            st.session_state.pop(email_status_key, None)
                            if context == "onboarding":
                                st.session_state.pop(
                                    "email_verification_onboarding", None
                                )
                                navigate_to("首页")
                            queue_success("邮箱验证成功")
                            st.rerun()
    return verified


def show_email_verification_onboarding() -> None:
    show_queued_success()
    render_page_heading(
        "验证注册邮箱",
        "完成邮箱验证后，双方达成互选时才能可靠地交换账号邮箱。",
    )
    user_id = st.session_state["user_id"]
    if render_email_verification_panel(user_id, context="onboarding"):
        st.session_state.pop("email_verification_onboarding", None)
        navigate_to("首页")
        st.rerun()

    st.caption("暂时跳过不会影响画像和项目功能，你可以稍后在“我的画像”中继续验证。")
    continue_column, logout_column = st.columns([3, 1])
    with continue_column:
        if st.button(
            "稍后验证，进入平台",
            key="skip_email_verification",
            use_container_width=True,
        ):
            st.session_state.pop("email_verification_onboarding", None)
            navigate_to("首页")
            st.rerun()
    with logout_column:
        if st.button(
            "退出登录",
            key="onboarding_logout",
            icon=":material/logout:",
            use_container_width=True,
        ):
            st.session_state.clear()
            st.rerun()


def show_profile_page() -> None:
    render_page_heading("我的画像", "记录技能、经历与研究兴趣，明确协作偏好和时间投入。")
    user_id = st.session_state["user_id"]
    loaded_key = f"profile_loaded_{user_id}"
    contact_loaded_key = f"contact_loaded_{user_id}"

    if not st.session_state.get(loaded_key) or not st.session_state.get(contact_loaded_key):
        with st.spinner("正在读取画像..."):
            existing = get_api(f"/api/profile/{user_id}", expected_empty="画像不存在")
        if existing is None:
            return
        if not existing.get("success") and existing.get("message") != "画像不存在":
            return
        if not st.session_state.get(loaded_key):
            if existing.get("success") and not st.session_state.get("profile_draft"):
                set_profile_draft(existing)
            st.session_state[loaded_key] = True
        if not st.session_state.get(contact_loaded_key):
            st.session_state["contact_method"] = existing.get("contact_method") or ""
            st.session_state["contact_value"] = existing.get("contact_value") or ""
            st.session_state["contact_visible"] = bool(existing.get("contact_visible", False))
            st.session_state[contact_loaded_key] = True

    raw_text = st.text_area(
        "自然语言描述",
        placeholder="请描述你的技能、经历、兴趣、协作偏好和每周可投入时间",
        height=160,
        key="profile_raw_text",
    )

    if st.button(
        "AI 解析",
        key="parse_profile_button",
        icon=":material/auto_awesome:",
    ):
        if not raw_text.strip():
            st.warning("请先输入个人描述")
        else:
            with st.spinner("AI正在解析中..."):
                loading_placeholder = st.empty()
                with loading_placeholder.container():
                    render_skeleton(rows=4)
                try:
                    result = post_api("/api/parse_profile", {"raw_text": raw_text})
                finally:
                    loading_placeholder.empty()
            if result:
                parsed_data = result.get("data", {})
                set_profile_draft(parsed_data, include_raw_text=False)
                queue_success("画像解析成功")
                st.rerun()

    if st.session_state.get("profile_draft"):
        st.subheader("画像内容")
        left, right = st.columns(2)
        with left:
            st.text_area("技能（一行一项）", key="profile_skills", height=130)
            st.text_area("项目经历（一行一项）", key="profile_experience", height=130)
            st.text_input("协作偏好", key="profile_preference")
        skills = list(dict.fromkeys(text_to_list(st.session_state["profile_skills"])))
        with right:
            skill_levels = render_skill_level_editor(skills)
            st.text_area("兴趣方向（一行一项）", key="profile_interests", height=130)
            st.text_input("时间投入", key="profile_time")

        if st.button(
            "保存画像",
            type="primary",
            icon=":material/save:",
            use_container_width=True,
        ):
            parsed_data = {
                "skills": skills,
                "skill_levels": skill_levels,
                "experience": text_to_list(st.session_state["profile_experience"]),
                "interests": text_to_list(st.session_state["profile_interests"]),
                "preference": st.session_state["profile_preference"].strip(),
                "time_commitment": st.session_state["profile_time"].strip(),
            }
            with st.spinner("正在保存画像..."):
                result = post_api(
                    "/api/save_profile",
                    {
                        "user_id": user_id,
                        "raw_text": st.session_state["profile_raw_text"],
                        "parsed_data": parsed_data,
                    },
                )
            if result:
                st.session_state.pop(f"home_overview_{user_id}", None)
                show_success("画像保存成功")

    st.divider()
    st.subheader("匹配后的联系方式")
    st.caption(
        "通过验证的账号邮箱只会在双方互选成功后向对方展示。你还可以选择开放一种额外联系方式。"
    )
    render_email_verification_panel(user_id)

    contact_labels = {
        "": "不填写",
        "wechat": "微信",
        "qq": "QQ",
        "phone": "手机号",
        "other": "其他",
    }
    with st.form("contact_settings_form"):
        st.selectbox(
            "联系方式类型",
            list(contact_labels),
            format_func=lambda value: contact_labels[value],
            key="contact_method",
        )
        st.text_input(
            "联系方式内容",
            placeholder="填写微信号、QQ号、手机号或其他联系方式",
            key="contact_value",
        )
        st.checkbox(
            "双方匹配后允许向对方展示这项联系方式",
            key="contact_visible",
        )
        save_contact = st.form_submit_button(
            "保存联系方式设置",
            type="primary",
            use_container_width=True,
        )
    if save_contact:
        method = st.session_state["contact_method"]
        value = st.session_state["contact_value"].strip()
        if value and not method:
            st.error("填写联系方式内容后，请选择对应类型")
        else:
            with st.spinner("正在保存联系方式设置..."):
                result = post_api(
                    "/api/profile/contact",
                    {
                        "user_id": user_id,
                        "contact_method": method,
                        "contact_value": value,
                        "contact_visible": st.session_state["contact_visible"],
                    },
                )
            if result:
                show_success("联系方式设置已保存")


def show_publish_project_page() -> None:
    render_page_heading("发布项目", "明确项目背景与合作需求，发布科研招募信息。")
    project_name = st.text_input("项目名称", key="new_project_name")
    raw_text = st.text_area(
        "需求描述",
        placeholder="请描述项目背景、所需技能、时间要求和优先条件",
        height=160,
        key="new_project_raw_text",
    )
    scope_label = st.radio(
        "开放范围",
        ["同校优先", "接受跨校"],
        horizontal=True,
        key="new_project_scope",
    )

    if st.button(
        "AI 解析",
        key="parse_project_button",
        icon=":material/auto_awesome:",
    ):
        if not raw_text.strip():
            st.warning("请先输入项目需求")
        else:
            with st.spinner("AI正在解析中..."):
                loading_placeholder = st.empty()
                with loading_placeholder.container():
                    render_skeleton(rows=4)
                try:
                    result = post_api("/api/parse_project", {"raw_text": raw_text})
                finally:
                    loading_placeholder.empty()
            if result:
                set_project_draft(result.get("data", {}))
                queue_success("项目需求解析成功")
                st.rerun()

    if st.session_state.get("project_draft"):
        st.subheader("项目需求")
        left, right = st.columns(2)
        with left:
            st.text_area(
                "所需技能（一行一项）",
                key="project_required_skills",
                height=130,
            )
            st.text_area("优先条件（一行一项）", key="project_priority", height=130)
            st.text_input("项目类型", key="project_type")
        with right:
            st.text_input("时间要求", key="project_time")
            st.text_area("项目背景", key="project_background", height=210)

        if st.button(
            "发布项目",
            type="primary",
            icon=":material/publish:",
            use_container_width=True,
        ):
            if not project_name.strip():
                st.warning("请填写项目名称")
            else:
                parsed_data = {
                    "required_skills": text_to_list(
                        st.session_state["project_required_skills"]
                    ),
                    "time_requirement": st.session_state["project_time"].strip(),
                    "priority": text_to_list(st.session_state["project_priority"]),
                    "project_type": st.session_state["project_type"].strip(),
                    "background": st.session_state["project_background"].strip(),
                }
                with st.spinner("正在发布项目..."):
                    result = post_api(
                        "/api/create_project",
                        {
                            "owner_id": st.session_state["user_id"],
                            "name": project_name.strip(),
                            "raw_text": raw_text,
                            "parsed_data": parsed_data,
                            "scope": (
                                "same_school"
                                if scope_label == "同校优先"
                                else "cross_school"
                            ),
                        },
                    )
                if result:
                    show_success(f"项目发布成功，项目编号：{result['project_id']}")


def show_match_recommendations_page() -> None:
    if (
        st.session_state.get("selected_project_id")
        and st.session_state.get("project_return_page") == "匹配推荐"
    ):
        show_project_detail()
        return

    render_page_heading(
        "为你推荐的匹配项目",
        "依据技能、时间投入与经历相关性推荐项目，评分仅供合作选择参考。",
    )
    success_message = st.session_state.pop("interest_success_message", None)
    if success_message:
        show_success(success_message)

    scope_label = st.radio(
        "推荐范围",
        ["同校优先", "跨校开放"],
        horizontal=True,
        key="match_scope",
    )
    scope = "same_school" if scope_label == "同校优先" else "cross_school"

    with st.spinner("正在计算匹配度..."):
        result = get_api(
            f"/api/match_list/{st.session_state['user_id']}?scope={scope}",
            timeout=120,
        )

    if result is None or not result.get("success"):
        return

    matches = result.get("matches", [])
    if not matches:
        render_empty_state(
            "暂无推荐项目",
            "请完善画像，或稍后查看新发布的项目。",
            icon="recommend",
        )
        return

    st.caption(f"共 {len(matches)} 个推荐项目")
    for match in matches:
        render_match_card(match, source="recommendation")


def show_my_matches_page() -> None:
    if (
        st.session_state.get("selected_project_id")
        and st.session_state.get("project_return_page") == "我的匹配"
    ):
        show_project_detail()
        return

    render_page_heading("我的匹配", "查看合作意向、发起人回应与互选进展。")
    with st.spinner("正在读取匹配进度..."):
        result = get_api(f"/api/my_matches/{st.session_state['user_id']}")
    if result is None or not result.get("success"):
        return
    matches = result.get("matches", [])
    if not matches:
        render_empty_state(
            "暂无合作意向记录",
            "浏览科研项目，向意向项目发起人表达合作意愿。",
            icon="handshake",
        )
        return

    counts = {
        "mutual": sum(item.get("relationship_status") == "mutual" for item in matches),
        "pending": sum(
            item.get("relationship_status") == "user_interested" for item in matches
        ),
        "declined": sum(
            item.get("relationship_status") == "owner_declined" for item in matches
        ),
    }
    metric_columns = st.columns(3)
    with metric_columns[0]:
        render_metric_tile("双方已匹配", counts["mutual"], accent="green", icon="handshake")
    with metric_columns[1]:
        render_metric_tile("等待处理", counts["pending"], accent="amber", icon="schedule")
    with metric_columns[2]:
        render_metric_tile("暂不考虑", counts["declined"], accent="slate", icon="pause_circle")
    for match in matches:
        render_my_match_card(match)


def show_notifications_page() -> None:
    if (
        st.session_state.get("selected_project_id")
        and st.session_state.get("project_return_page") == "通知"
    ):
        show_project_detail()
        return

    render_page_heading("通知中心", "集中查看申请进度、互选结果与项目状态变化。")
    user_id = st.session_state["user_id"]
    unread_only = st.segmented_control(
        "通知范围",
        options=["全部通知", "仅看未读"],
        default="全部通知",
        key="notification_filter",
    )
    query = "?unread_only=true" if unread_only == "仅看未读" else ""
    with st.spinner("正在读取通知..."):
        result = get_api(f"/api/notifications/{user_id}{query}")
    if result is None or not result.get("success"):
        return

    notifications = result.get("notifications", [])
    unread_count = int(result.get("unread_count", 0))
    heading, action = st.columns([4, 1])
    heading.metric("未读通知", unread_count)
    if action.button(
        "全部标记已读",
        use_container_width=True,
        disabled=unread_count == 0,
    ):
        with st.spinner("正在更新通知状态..."):
            update_result = post_api(
                "/api/notifications/read-all",
                {"user_id": user_id},
            )
        if update_result and update_result.get("success"):
            queue_success("全部通知已标记为已读")
            st.rerun()

    if not notifications:
        message = "目前没有未读通知" if unread_only == "仅看未读" else "目前还没有通知"
        render_empty_state(message, "项目与匹配状态发生变化时会在这里提醒你。", icon="notifications")
        return

    st.markdown(
        textwrap.dedent(
            """
        <style>
        .zl-notification-card {
            margin-bottom: 12px;
            min-height: 112px;
            box-sizing: border-box;
            padding: 14px 16px;
            border: 1px solid #E4E7EC;
            border-radius: 8px;
            background: #FFFFFF;
            text-align: left;
            transition: background 120ms ease, box-shadow 120ms ease;
        }
        .zl-notification-card:hover {
            background: #F5F8FF;
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.08);
        }
        .zl-notification-card-unread {
            border-left: 3px solid #2563EB;
        }
        .zl-notification-title-row {
            display: flex;
            align-items: center;
            min-height: 22px;
            line-height: 1.35;
        }
        .zl-notification-dot {
            width: 6px;
            height: 6px;
            margin-right: 8px;
            flex: 0 0 6px;
            border-radius: 50%;
            background: #2563EB;
        }
        .zl-notification-title {
            color: #1A1A1A;
            font-size: 16px;
            font-weight: 700;
        }
        .zl-notification-type {
            margin-left: 8px;
            color: #999999;
            font-size: 12px;
            font-weight: 400;
        }
        .zl-notification-content {
            margin-top: 6px;
            color: #666666;
            font-size: 14px;
            font-weight: 400;
            line-height: 1.45;
            display: -webkit-box;
            -webkit-box-orient: vertical;
            -webkit-line-clamp: 2;
            overflow: hidden;
        }
        .zl-notification-time {
            margin-top: 8px;
            color: #999999;
            font-size: 12px;
            font-weight: 400;
            line-height: 1.2;
        }
        .zl-notification-action {
            margin-top: -4px;
            margin-bottom: 12px;
        }
        </style>
        """,
        ),
        unsafe_allow_html=True,
    )

    notification_type_labels = {
        "candidate_interested": "候选人",
        "mutual_match": "匹配结果",
        "candidate_declined": "匹配结果",
        "project_moderated": "项目动态",
        "project_restored": "项目动态",
        "project_status_changed": "项目动态",
        "project_deleted": "项目动态",
        "feedback_reply": "系统通知",
    }
    for item in notifications:
        notification_id = item.get("notification_id")
        is_read = bool(item.get("is_read"))
        title = str(item.get("title") or "通知")
        preview = _notification_preview(item.get("content"))
        time_label = _notification_time_label(item.get("created_at"))
        type_label = notification_type_labels.get(item.get("type"), "通知")
        card_class = (
            "zl-notification-card zl-notification-card-unread"
            if not is_read
            else "zl-notification-card"
        )
        marker_html = (
            "<span class='zl-notification-dot' aria-hidden='true'></span>"
            if not is_read
            else ""
        )
        st.markdown(
            (
                f'<div class="{card_class}">'
                f'<div class="zl-notification-title-row">'
                f'{marker_html}'
                f'<span class="zl-notification-title">{escape(title)}</span>'
                f'<span class="zl-notification-type">{escape(type_label)}</span>'
                f'</div>'
                f'<div class="zl-notification-content">{escape(preview)}</div>'
                f'<div class="zl-notification-time">{escape(time_label)}</div>'
                f'</div>'
            ),
            unsafe_allow_html=True,
        )
        if st.button(
            "查看详情",
            key=f"notification_open_{notification_id}",
            use_container_width=True,
        ):
            _handle_notification_click(item, user_id)


def show_my_projects_page() -> None:
    render_page_heading("我的项目", "管理你发布的项目状态，并处理候选人的合作意向。")
    with st.spinner("正在读取项目列表..."):
        result = get_api(f"/api/my_projects/{st.session_state['user_id']}")
    if result is None or not result.get("success"):
        return

    projects = result.get("projects", [])
    if not projects:
        render_empty_state(
            "你还没有发布项目",
            "明确研究目标与技能需求后，即可发布项目。",
            icon="science",
        )
        return

    st.caption(f"共 {len(projects)} 个项目")
    status_labels = {
        "recruiting": "招募中",
        "full": "已满员",
        "closed": "已关闭",
        "completed": "已完成",
    }
    scope_labels = {
        "same_school": "同校优先",
        "cross_school": "接受跨校",
    }

    for project in projects:
        status = status_labels.get(project.get("status"), project.get("status", "未知"))
        created_at = project.get("created_at") or "未知日期"
        with st.expander(f"{project.get('name', '未命名项目')}  |  {status}  |  {created_at}"):
            if project.get("moderation_status") == "removed":
                st.error("该项目已被平台下架，暂不对其他用户展示。")
                if project.get("moderation_reason"):
                    st.warning(f"处理原因：{project['moderation_reason']}")
            st.caption(
                f"发布时间：{created_at} · "
                f"开放范围：{scope_labels.get(project.get('scope'), '未设置')}"
            )

            required_skills = project.get("required_skills") or []
            st.markdown("**所需技能**")
            st.write("、".join(str(skill) for skill in required_skills) or "未填写")

            left, right = st.columns(2)
            with left:
                st.markdown("**项目类型**")
                st.write(project.get("project_type") or "未填写")
                st.markdown("**时间要求**")
                st.write(project.get("time_requirement") or "未知")
            with right:
                st.markdown("**优先条件**")
                priority = project.get("priority") or []
                st.write("、".join(str(item) for item in priority) or "无")
                st.markdown("**当前状态**")
                st.write(status)

            st.markdown("**项目背景**")
            st.write(project.get("background") or "未填写")
            st.markdown("**原始需求描述**")
            st.write(project.get("raw_text") or "未填写")

            st.markdown("**候选人管理**")
            with st.spinner("正在读取候选人..."):
                candidates_result = get_api(
                    f"/api/project/{project.get('project_id')}/candidates"
                    f"?owner_id={st.session_state['user_id']}"
                )
            if candidates_result is None or not candidates_result.get("success"):
                continue
            candidates = candidates_result.get("candidates", [])
            if not candidates:
                st.caption("暂无用户表达合作意向")
            else:
                st.caption(f"共有 {len(candidates)} 位候选人表达了意向")
                for candidate in candidates:
                    render_candidate_card(candidate, project.get("project_id"))


def show_favorites_page() -> None:
    if (
        st.session_state.get("selected_project_id")
        and st.session_state.get("project_return_page") == "我的收藏"
    ):
        show_project_detail()
        return
    render_page_heading("我的收藏", "保存关注的科研项目，便于后续查看。")
    with st.spinner("正在读取收藏..."):
        result = get_api(f"/api/favorites/{st.session_state['user_id']}")
    if result is None or not result.get("success"):
        return
    favorites = result.get("favorites", [])
    if not favorites:
        render_empty_state(
            "还没有收藏项目",
            "浏览项目时可收藏意向项目，便于后续查看。",
            icon="bookmark",
        )
        return
    st.caption(f"已收藏 {len(favorites)} 个项目")
    for favorite in favorites:
        project_id = favorite.get("project_id")
        with st.container(border=True, key=f"favorite_card_{project_id}"):
            left, right = st.columns([4, 1])
            with left:
                st.subheader(favorite.get("name") or "未命名项目")
                st.caption(
                    f"{favorite.get('owner_school') or '学校未填写'} · "
                    f"{favorite.get('project_type') or '类型未填写'} · "
                    f"{favorite.get('status') or '未知状态'}"
                )
                render_skill_pills(favorite.get("required_skills"))
                st.write(
                    (favorite.get("raw_text") or "暂无项目描述")[:180]
                )
            with right:
                st.button(
                    "查看详情",
                    key=f"favorite_detail_{project_id}",
                    on_click=open_project_detail,
                    args=(project_id, "我的收藏"),
                    use_container_width=True,
                    icon=":material/arrow_forward:",
                )
                if st.button(
                    "取消收藏",
                    key=f"danger_favorite_remove_{project_id}",
                    use_container_width=True,
                    icon=":material/bookmark_remove:",
                ):
                    with st.spinner("正在取消收藏..."):
                        removed = delete_api(
                            f"/api/favorites/{project_id}",
                            {"user_id": st.session_state["user_id"]},
                        )
                    if removed and not removed.get("favorited"):
                        queue_success("已取消收藏")
                        st.rerun()


def show_feedback_page() -> None:
    render_page_heading("意见反馈", "你的反馈会帮助平台持续改进匹配体验。")
    categories = ["功能建议", "匹配不准确", "使用问题", "内容举报", "账号问题", "其他"]
    with st.form("feedback_form"):
        category = st.selectbox("反馈类型", categories)
        content = st.text_area(
            "反馈内容",
            placeholder="请描述遇到的问题或希望改进的地方",
            height=150,
        )
        contact_email = st.text_input("联系邮箱（可选）")
        submitted = st.form_submit_button(
            "提交反馈",
            type="primary",
            icon=":material/send:",
        )
    if submitted:
        with st.spinner("正在提交反馈..."):
            result = post_api(
                "/api/feedback",
                {
                    "user_id": st.session_state["user_id"],
                    "category": category,
                    "content": content,
                    "contact_email": contact_email,
                    "source_page": st.session_state.get("app_page", "意见反馈"),
                },
            )
        if result:
            show_success("反馈已提交，感谢你的建议")

    st.markdown("### 我的反馈记录")
    with st.spinner("正在读取反馈记录..."):
        result = get_api(f"/api/my_feedback/{st.session_state['user_id']}")
    if result is None or not result.get("success"):
        return
    status_labels = {
        "pending": "待处理",
        "reviewing": "处理中",
        "resolved": "已处理",
        "rejected": "已驳回",
    }
    feedbacks = result.get("feedback", [])
    if not feedbacks:
        st.caption("你还没有提交过反馈")
        return
    for item in feedbacks:
        with st.expander(
            f"{item.get('category', '其他')} · "
            f"{status_labels.get(item.get('status'), '未知')} · "
            f"{str(item.get('created_at') or '')[:10]}"
        ):
            st.write(item.get("content") or "")
            if item.get("admin_reply"):
                st.info(f"管理员回复：{item['admin_reply']}")


def show_authenticated_app() -> None:
    if st.session_state.get("email_verification_onboarding"):
        show_email_verification_onboarding()
        return

    show_queued_success()
    notification_summary = get_api(
        f"/api/notifications/{st.session_state['user_id']}?unread_only=true&page_size=1",
        show_error=False,
        timeout=5,
    )
    unread_count = (
        int(notification_summary.get("unread_count", 0))
        if notification_summary and notification_summary.get("success")
        else 0
    )
    with st.sidebar:
        render_brand_lockup(compact=True, subtitle="科研协作匹配平台")
        st.divider()
        username = st.session_state["username"]
        school = st.session_state.get("school")
        initial = (username.strip()[:1] or "知").upper()
        st.markdown(
            textwrap.dedent(
                f"""
            <div class="zl-sidebar-user">
                <div class="zl-avatar">{escape(initial)}</div>
                <div>
                    <div class="zl-sidebar-name">{escape(username)}</div>
                    <div class="zl-sidebar-school">{escape(school or '高校科研社区')}</div>
                </div>
            </div>
            """,
            ),
            unsafe_allow_html=True,
        )

        pages = [
            "首页",
            "发现项目",
            "匹配推荐",
            "我的匹配",
            "通知",
            "我的收藏",
            "意见反馈",
            "我的画像",
            "发布项目",
            "我的项目",
        ]
        current_page = st.session_state.get("app_page", "首页")
        if current_page not in pages:
            current_page = "首页"
        navigation_labels = {
            item: f"通知 ({unread_count})" if item == "通知" and unread_count else item
            for item in pages
        }
        page = st.radio(
            "页面导航",
            pages,
            index=pages.index(current_page),
            key="app_page",
            format_func=lambda item: navigation_labels[item],
        )

        st.divider()
        if st.button(
            "退出登录",
            key="logout_button",
            icon=":material/logout:",
            use_container_width=True,
        ):
            token = st.session_state.get("token")
            if token:
                try:
                    requests.post(
                        f"{BACKEND_URL}/api/auth/logout",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=5,
                    )
                except requests.RequestException:
                    pass
            st.session_state.clear()
            st.rerun()
        st.markdown(
            '<div class="zl-sidebar-version">v2.0 · 2026</div>',
            unsafe_allow_html=True,
        )

    pages = {
        "首页": show_home_page,
        "发现项目": show_discover_projects_page,
        "我的画像": show_profile_page,
        "发布项目": show_publish_project_page,
        "匹配推荐": show_match_recommendations_page,
        "我的匹配": show_my_matches_page,
        "通知": show_notifications_page,
        "我的收藏": show_favorites_page,
        "意见反馈": show_feedback_page,
        "我的项目": show_my_projects_page,
    }
    pages[page]()


def main() -> None:
    st.set_page_config(
        page_title="知遇LinkLab - 找到你的科研搭档",
        page_icon="🔗",
        layout="wide",
    )
    pending_page = st.session_state.pop("_pending_page", None)
    if pending_page:
        st.session_state["app_page"] = pending_page
    inject_theme("user" if st.session_state.get("user_id") else "auth")

    if st.session_state.get("user_id"):
        enforce_current_account_status()
        show_authenticated_app()
    else:
        show_auth_page()


if __name__ == "__main__":
    main()
