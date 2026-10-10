import json
import logging
import os

from openai import OpenAI


logger = logging.getLogger(__name__)


DEFAULT_PROFILE = {
    "skills": [],
    "skill_levels": {},
    "experience": [],
    "interests": [],
    "preference": "",
    "time_commitment": "未知",
}

DEFAULT_PROJECT = {
    "required_skills": [],
    "time_requirement": "未知",
    "priority": [],
    "project_type": "",
    "background": "",
}


def validate_and_complete_fields(
    result: dict,
    defaults: dict,
    data_name: str,
) -> dict:
    """Complete missing fields and normalize values to their expected types."""
    if not isinstance(result, dict):
        logger.warning("%s不是字典，已使用全部默认值", data_name)
        result = {}

    normalized = {}
    for field, default in defaults.items():
        if field not in result:
            logger.warning("%s缺少字段 %s，已使用默认值", data_name, field)
            value = default
        else:
            value = result[field]

        if value is None or (isinstance(value, str) and not value.strip()):
            logger.warning("%s字段 %s 为空，已使用默认值", data_name, field)
            value = default

        if isinstance(default, list):
            if not isinstance(value, list):
                logger.warning("%s字段 %s 类型错误，已自动转换为列表", data_name, field)
                value = [] if value in (None, "") else [value]
            normalized[field] = [
                str(item).strip()
                for item in value
                if item is not None and str(item).strip()
            ]
        elif isinstance(default, dict):
            if not isinstance(value, dict):
                logger.warning("%s字段 %s 类型错误，已使用空字典", data_name, field)
                value = {}
            normalized[field] = {
                str(key).strip(): str(item).strip()
                for key, item in value.items()
                if key is not None
                and str(key).strip()
                and item is not None
                and str(item).strip()
            }
        else:
            if not isinstance(value, str):
                logger.warning("%s字段 %s 类型错误，已自动转换为字符串", data_name, field)
                value = str(value)
            normalized[field] = value.strip() or default

    return normalized


def parse_user_profile(raw_text: str) -> dict:
    """Parse a user's natural-language profile into structured JSON."""
    api_key = os.getenv("LLM_API_KEY")
    base_url = os.getenv("LLM_BASE_URL")
    model = os.getenv("LLM_MODEL", "qwen-plus")  # 默认值给 qwen-plus

    if not api_key:
        raise RuntimeError("环境变量 LLM_API_KEY 未设置")
    if not base_url:
        raise RuntimeError("环境变量 LLM_BASE_URL 未设置")
    if not raw_text or not raw_text.strip():
        raise ValueError("raw_text 不能为空")

    client = OpenAI(api_key=api_key, base_url=base_url)

    system_prompt = """你是一个科研协作平台的用户画像解析引擎。你的任务是把用户的自然语言描述解析为结构化JSON。

必须严格返回以下字段，不得多、不得少：
{
  "skills": ["技能1", "技能2"],
  "skill_levels": {"技能1": "熟练/掌握/了解"},
  "experience": ["经历1", "经历2"],
  "interests": ["兴趣1", "兴趣2"],
  "preference": "协作偏好描述",
  "time_commitment": "每周X小时"
}

规则：
1. skills 必须是数组，每项是标准化技能名称
2. skill_levels 的键必须与 skills 中的项对应
3. 如果用户没有提到某个字段，返回空数组或空字符串
4. 只返回JSON，不要任何解释文字、不要markdown代码块标记"""
    user_prompt = f"请解析以下用户描述：{raw_text}"

    try:
        response = client.chat.completions.create(
            model=model,  # ✅ 用变量，不再写死 gpt-4o-mini
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content
        if not content:
            raise ValueError("模型返回为空")

        cleaned_content = content.strip()
        if cleaned_content.startswith("```") and cleaned_content.endswith("```"):
            cleaned_content = cleaned_content[3:-3].strip()
            if cleaned_content.lower().startswith("json"):
                cleaned_content = cleaned_content[4:].lstrip()

        result = json.loads(cleaned_content)
        if not isinstance(result, dict):
            raise ValueError("模型返回的 JSON 不是对象")
        return validate_and_complete_fields(result, DEFAULT_PROFILE, "用户画像")
    except Exception:
        logger.exception("解析用户画像失败")
        raise


def parse_project_requirement(raw_text: str) -> dict:
    """Parse a natural-language project requirement into structured JSON."""
    api_key = os.getenv("LLM_API_KEY")
    base_url = os.getenv("LLM_BASE_URL")
    model = os.getenv("LLM_MODEL", "qwen-plus")

    if not api_key:
        raise RuntimeError("环境变量 LLM_API_KEY 未设置")
    if not base_url:
        raise RuntimeError("环境变量 LLM_BASE_URL 未设置")
    if not raw_text or not raw_text.strip():
        raise ValueError("raw_text 不能为空")

    client = OpenAI(api_key=api_key, base_url=base_url)
    prompt = f"""
请把下面的项目需求自然语言描述解析为结构化 JSON。
只返回 JSON，不要返回 Markdown、代码块或任何解释文字。
JSON 必须包含以下字段：
- required_skills: list[str]，所需技能
- time_requirement: str，时间要求
- priority: list[str]，优先条件
- project_type: str，项目类型
- background: str，项目背景

项目需求：
{raw_text}
"""

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "你是一个严谨的信息抽取助手。你只能输出合法 JSON。"},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content
        if not content:
            raise ValueError("模型返回为空")
        result = json.loads(content)
        if not isinstance(result, dict):
            raise ValueError("模型返回的 JSON 不是对象")
        return validate_and_complete_fields(result, DEFAULT_PROJECT, "项目需求")
    except Exception:
        logger.exception("解析项目需求失败")
        raise


def judge_experience_relevance(
    user_experience: list[str],
    project_type: str,
    project_background: str,
) -> float:
    """Use the language model to score experience relevance from 0 to 1."""
    try:
        api_key = os.getenv("LLM_API_KEY")
        base_url = os.getenv("LLM_BASE_URL")
        model = os.getenv("LLM_MODEL", "qwen-plus")

        if not api_key:
            raise RuntimeError("环境变量 LLM_API_KEY 未设置")
        if not base_url:
            raise RuntimeError("环境变量 LLM_BASE_URL 未设置")

        client = OpenAI(api_key=api_key, base_url=base_url)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "你是一个科研项目匹配助手。请判断用户的过往经历是否与目标项目相关。"
                        "只返回0到1之间的一个数字，不要任何解释。"
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"用户经历：{user_experience}。"
                        f"项目类型：{project_type}。"
                        f"项目背景：{project_background}。"
                        "请给出0-1的相关性评分。"
                    ),
                },
            ],
        )

        content = response.choices[0].message.content
        score = float((content or "").strip())
        return min(max(score, 0.0), 1.0)
    except Exception:
        logger.exception("AI 经历相关性判断失败，使用默认分数 0.5")
        return 0.5


def normalize_skills(skills: list[str]) -> list[str]:
    """Normalize skill aliases into standard labels with the language model."""
    if not isinstance(skills, list):
        logger.warning("技能数据不是列表，无法调用归一化")
        return skills

    original_skills = [
        str(skill).strip()
        for skill in skills
        if skill is not None and str(skill).strip()
    ]
    if not original_skills:
        return []

    try:
        api_key = os.getenv("LLM_API_KEY")
        base_url = os.getenv("LLM_BASE_URL")
        model = os.getenv("LLM_MODEL", "qwen-plus")

        if not api_key:
            raise RuntimeError("环境变量 LLM_API_KEY 未设置")
        if not base_url:
            raise RuntimeError("环境变量 LLM_BASE_URL 未设置")

        client = OpenAI(api_key=api_key, base_url=base_url)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "你是一个技能标签归一化助手。\n"
                        "规则：\n"
                        "1. 同一技能的不同写法（缩写、全称、中英文、别名）合并为一个标准名称。\n"
                        "   例如：ML / Machine Learning / 机器学习 → 只保留\"机器学习\"\n"
                        "   例如：Web开发 / 前端 / Frontend → 只保留\"前端开发\"\n"
                        "   例如：大模型 / LLM / 大语言模型 → 只保留\"大语言模型\"\n"
                        "2. 标准名称优先用中文全称。\n"
                        "3. 去重后返回 JSON 数组，不要任何解释，不要 Markdown 代码块。\n"
                        "4. 如果输入为空，返回空数组 []。"
                    ),
                },
                {
                    "role": "user",
                    "content": f"请归一化以下技能列表：{original_skills}",
                },
            ],
        )

        content = (response.choices[0].message.content or "").strip()
        if content.startswith("```") and content.endswith("```"):
            content = content[3:-3].strip()
            if content.lower().startswith("json"):
                content = content[4:].lstrip()

        result = json.loads(content)
        if not isinstance(result, list):
            raise ValueError("模型返回结果不是 JSON 数组")

        normalized_skills = [
            str(skill).strip()
            for skill in result
            if skill is not None and str(skill).strip()
        ]
        return normalized_skills or original_skills
    except Exception:
        logger.warning("技能标签归一化失败，返回原技能列表", exc_info=True)
        return original_skills


def judge_skill_similarity(
    user_skills: list[str],
    required_skills: list[str],
) -> list[tuple]:
    """Match each user skill to a required skill and return similarity scores."""
    clean_user_skills = [
        str(skill).strip()
        for skill in user_skills
        if skill is not None and str(skill).strip()
    ]
    clean_required_skills = [
        str(skill).strip()
        for skill in required_skills
        if skill is not None and str(skill).strip()
    ]

    def literal_fallback() -> list[tuple]:
        required_by_lower = {
            skill.lower(): skill for skill in clean_required_skills
        }
        return [
            (
                user_skill,
                required_by_lower.get(user_skill.lower(), ""),
                1.0 if user_skill.lower() in required_by_lower else 0.0,
            )
            for user_skill in clean_user_skills
        ]

    if not clean_user_skills or not clean_required_skills:
        return literal_fallback()

    try:
        api_key = os.getenv("LLM_API_KEY")
        base_url = os.getenv("LLM_BASE_URL")
        model = os.getenv("LLM_MODEL", "qwen-plus")

        if not api_key:
            raise RuntimeError("环境变量 LLM_API_KEY 未设置")
        if not base_url:
            raise RuntimeError("环境变量 LLM_BASE_URL 未设置")

        client = OpenAI(api_key=api_key, base_url=base_url)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "你是一个技能匹配助手。请判断用户技能与项目需求技能之间的语义相关性。"
                        "返回JSON数组，每项包含user_skill、matched_skill、similarity三个字段。"
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"用户技能：{clean_user_skills}。"
                        f"项目所需技能：{clean_required_skills}。"
                        "请逐项判断并返回。"
                    ),
                },
            ],
        )

        content = (response.choices[0].message.content or "").strip()
        if content.startswith("```") and content.endswith("```"):
            content = content[3:-3].strip()
            if content.lower().startswith("json"):
                content = content[4:].lstrip()

        result = json.loads(content)
        if not isinstance(result, list):
            raise ValueError("模型返回结果不是 JSON 数组")

        matches = []
        for item in result:
            if not isinstance(item, dict):
                logger.warning("忽略格式错误的技能匹配项：%r", item)
                continue

            user_skill = str(item.get("user_skill", "")).strip()
            matched_skill = str(item.get("matched_skill", "")).strip()
            similarity = float(item.get("similarity", 0))
            if not user_skill:
                logger.warning("忽略缺少 user_skill 的技能匹配项：%r", item)
                continue

            matches.append(
                (user_skill, matched_skill, min(max(similarity, 0.0), 1.0))
            )

        if not matches:
            raise ValueError("模型未返回有效的技能匹配项")
        return matches
    except Exception:
        logger.exception("AI 技能语义匹配失败，降级为字面匹配")
        return literal_fallback()
