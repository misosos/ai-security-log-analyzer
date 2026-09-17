from dataclasses import asdict, is_dataclass
from datetime import datetime
import json
import os

from dotenv import load_dotenv
from google import genai

from app.analyzer.prompt import SYSTEM_PROMPT


load_dotenv()


def serialize_value(value):
    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, tuple):
        return [serialize_value(item) for item in value]

    if isinstance(value, list):
        return [serialize_value(item) for item in value]

    if isinstance(value, dict):
        return {
            key: serialize_value(item)
            for key, item in value.items()
        }

    if is_dataclass(value):
        return {
            key: serialize_value(item)
            for key, item in asdict(value).items()
        }

    return value


def build_llm_input(ip, analysis):
    return serialize_value({
        "ip": ip,
        "detections": analysis["detections"],
        "risk_level": analysis["risk_level"],
        "risk_factors": analysis["risk_factors"],
        "correlation": analysis["correlation"],
    })


def build_llm_messages(ip, analysis):
    llm_input = build_llm_input(ip, analysis)

    return [
        {
            "role": "system",
            "content": SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": json.dumps(
                llm_input,
                ensure_ascii=False,
                indent=2,
            ),
        },
    ]


def generate_security_summary(ip, analysis):
    client = genai.Client(
        api_key=os.getenv("GEMINI_API_KEY")
    )

    llm_input = build_llm_input(ip, analysis)

    prompt = f"""
{SYSTEM_PROMPT}

다음은 보안 로그 분석 시스템이 생성한 분석 결과입니다.

{json.dumps(
    llm_input,
    ensure_ascii=False,
    indent=2,
)}

위 분석 결과를 바탕으로 보안 상황을 요약해주세요.
"""

    interaction = client.interactions.create(
        model="gemini-3.6-flash",
        input=prompt,
    )

    return interaction.output_text


def generate_overall_summary(results):
    client = genai.Client(
        api_key=os.getenv("GEMINI_API_KEY")
    )

    llm_input = serialize_value(results)

    prompt = f"""
{SYSTEM_PROMPT}

다음은 전체 보안 로그에 대한 분석 결과입니다.

{json.dumps(
    llm_input,
    ensure_ascii=False,
    indent=2,
)}

전체 분석 결과를 바탕으로 보안 상황을 요약해주세요.

다음 내용을 중심으로 설명합니다.

1. 전체적으로 탐지된 보안 이벤트
2. IP별 주요 탐지 결과
3. 확인된 Correlation 및 공격 흐름
4. 각 분석 결과의 Risk Level과 Confidence
5. 공격 성공 여부와 같이 로그만으로 확인할 수 없는 내용
6. 여러 IP의 결과를 임의로 연결하거나 새로운 공격 흐름을 만들어내지 않음

분석 결과에 존재하지 않는 사실은 추가하지 않습니다.
"""

    interaction = client.interactions.create(
        model="gemini-3.6-flash",
        input=prompt,
    )

    return interaction.output_text