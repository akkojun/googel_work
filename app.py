# app.py
import os
import streamlit as st
import google.generativeai as genai
import json

# --- 설정 ---
# 실행 전에 환경 변수에 API 키를 넣으세요:
# 예) export GOOGLE_API_KEY="YOUR_KEY"
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

MODEL_NAME = "models/gemini-2.5-pro"

# --- UI ---
st.set_page_config(page_title="간단 CVE 요약기", layout="centered")
st.title("📝 Gemini 기반 CVE 정보 요약기")
st.caption("CVE ID를 입력하면 Gemini가 해당 취약점에 대한 정보를 검색하고 요약해줍니다.")

cve_id = st.text_input("분석할 CVE ID를 입력하세요 (예: CVE-2023-4863)", "")

temperature = 0.0  # 창의성을 0으로 고정하여 사실 기반 응답 유도
max_tokens = st.slider("응답 최대 토큰", 200, 4096, 1500, 50)

if st.button("CVE 정보 분석하기"):
    if not cve_id.strip():
        st.warning("CVE ID를 먼저 입력해주세요.")
    else:
        # GOOGLE_API_KEY 환경 변수가 설정되었는지 확인
        if not os.getenv("GOOGLE_API_KEY"):
            st.error("GOOGLE_API_KEY 환경 변수가 설정되지 않았습니다. 앱을 실행하기 전에 API 키를 설정해주세요.")
        else:
            with st.spinner(f"{cve_id}에 대한 정보를 Gemini로 분석 중입니다..."):
                # --- 프롬프트 템플릿 ---
                prompt = f'''
너는 최신 정보를 검색할 수 있는 사이버 보안 전문가야. **반드시 웹 검색을 실행해서** 주어진 CVE ID에 대한 최신 정보를 찾아야 해. **검색된 사실만을 기반으로** 답변하고, **불확실하거나 추측에 기반한 정보는 절대 생성하지 마**.

검색 결과를 바탕으로, 아래 JSON 형식에 맞춰 자세히 설명해줘.

CVE ID: {cve_id}

반드시 다음 키를 포함하는 valid JSON 형식으로만 응답해야 해:
{{
  "cve_id": "{cve_id}",
  "summary": "취약점에 대한 한 줄 요약",
  "vuln_type": "CWE-ID를 포함한 구체적인 취약점 유형 (예: CWE-416: Use After Free)",
  "description": "취약점에 대한 상세한 설명 (어떻게 발생하고, 어떤 영향을 미치는지)",
  "how_exploited": "공격자가 이 취약점을 어떻게 악용할 수 있는지 시나리오 설명",
  "severity": "CVSS 점수를 포함한 위험도 (예: 높음, CVSS 3.1: 9.8)",
  "impact": "이 취약점으로 인해 발생할 수 있는 주요 영향",
  "recommendation": "개발자 또는 시스템 관리자를 위한 구체적인 대응 및 완화 방안",
  "references": [
      {{
          "title": "언급된 주요 공식 발표, 블로그, 또는 기술 문서 제목",
          "url": "해당 자료의 URL"
      }}
  ]
}}

각 항목의 설명은 2-3 문장으로 간결하게 요약해줘. 만약 특정 항목에 대한 정보를 찾을 수 없다면, 빈 문자열("")로 남겨둬.
'''
                try:
                    model = genai.GenerativeModel(MODEL_NAME)
                    resp = model.generate_content(
                        prompt,
                        generation_config={
                            "temperature": temperature,
                            "candidate_count": 1,
                            "max_output_tokens": max_tokens
                        }
                    )

                    st.subheader("✅ Gemini 분석 결과")
                    
                    # 텍스트를 추출하고 정리
                    raw_text = ""
                    try:
                        # 응답이 안전상의 이유로 차단되었는지 확인
                        if resp.candidates and resp.candidates[0].finish_reason.name != "STOP":
                            finish_reason = resp.candidates[0].finish_reason.name
                            if finish_reason == "RECITATION":
                                st.error("오류: 모델의 응답이 저작권(표절) 문제로 인해 차단되었습니다. 다른 CVE를 시도해 보세요.")
                            else:
                                st.error(f"오류: 모델의 응답이 안전상의 이유({finish_reason})로 차단되었습니다.")
                        else:
                            raw_text = resp.text
                    except (AttributeError, IndexError, ValueError) as e:
                        st.error(f"모델 응답을 처리하는 중 오류가 발생했습니다. 응답이 비어있을 수 있습니다. (오류: {e})")
                    
                    # 모델이 JSON을 ```json ... ```으로 감쌀 수 있으므로 추출
                    clean_json_str = raw_text.strip().removeprefix("```json").removesuffix("```").strip()

                    st.subheader("모델 응답 (JSON 원문)")
                    st.code(clean_json_str, language="json")

                    # JSON을 파싱하고 화면에 표시
                    try:
                        parsed = json.loads(clean_json_str)
                        st.subheader("구조화된 분석 내용")
                        st.markdown(f"**취약점 요약:** {parsed.get('summary', 'N/A')}")
                        st.markdown(f"**취약점 유형:** {parsed.get('vuln_type', 'N/A')}")
                        st.markdown(f"**상세 설명:** {parsed.get('description', 'N/A')}")
                        st.markdown(f"**악용 시나리오:** {parsed.get('how_exploited', 'N/A')}")
                        st.markdown(f"**위험도:** {parsed.get('severity', 'N/A')}")
                        st.markdown(f"**주요 영향:** {parsed.get('impact', 'N/A')}")
                        st.markdown(f"**대응 방안:** {parsed.get('recommendation', 'N/A')}")

                        st.subheader("주요 참고 자료")
                        references = parsed.get("references", [])
                        if references:
                            for ref in references:
                                st.markdown(f"- [{ref.get('title', 'Link')}]({ref.get('url', '#')})")
                        else:
                            st.markdown("N/A")

                    except json.JSONDecodeError:
                        st.error("모델이 유효한 JSON을 반환하지 않았습니다. 원문을 확인해주세요.")
                    except Exception as e:
                        st.error(f"결과 파싱 중 오류 발생: {e}")

                except Exception as e:
                    st.error(f"API 호출 중 오류가 발생했습니다: {e}")
                    st.exception(e)