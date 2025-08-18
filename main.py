# -*- coding: utf-8 -*-
# 실행: streamlit run main.py
import streamlit as st
from streamlit.components.v1 import html as st_html  # 권장 방식
import base64, json, re, io, csv, math
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any
import pandas as pd

st.set_page_config(page_title="범용 로그 분석기 + Puter.js(무제한/무키) AI 보고서", layout="wide")

# ---------------------------
# 공통 상수·정규식
# ---------------------------
AM_PM_MAP = {"오전": "AM", "오후": "PM"}

ISO_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")
KR_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2})\s*(오전|오후)\s*(\d{1,2}:\d{2}:\d{2})")
YMD_HMS_RE = re.compile(r"\b(\d{4}[-/]\d{1,2}[-/]\d{1,2})[ T](\d{1,2}:\d{2}:\d{2})\b")  # naive

JSON_TIME_KEYS = [
    "timestamp", "time", "eventTime", "event_time", "logged_at", "created_at",
    "@timestamp", "ts", "datetime"
]

@dataclass
class LogLine:
    file: str
    line: int
    ts: Optional[pd.Timestamp]
    text: str

# ---------------------------
# 유틸
# ---------------------------
def _korean_ampm_to_en(s: str) -> str:
    return s.replace("오전", "AM").replace("오후", "PM")

def _ensure_utc(ts: Optional[pd.Timestamp], local_tz: str = "Asia/Seoul") -> Optional[pd.Timestamp]:
    """tz-naive는 local_tz로 가정→UTC 변환, aware는 UTC 변환"""
    if ts is None or pd.isna(ts):
        return None
    try:
        if ts.tzinfo is None:
            return ts.tz_localize(local_tz).tz_convert("UTC")
        return ts.tz_convert("UTC")
    except Exception:
        # 파싱 실패 시 None
        return None

def parse_timestamp_any(s: str, local_tz: str = "Asia/Seoul") -> Optional[pd.Timestamp]:
    """여러 형태의 타임스탬프를 찾아 UTC-aware Timestamp로 반환. 없으면 None."""
    # ISO/RFC3339
    m = ISO_TS_RE.search(s)
    if m:
        try:
            ts = pd.to_datetime(m.group(0), utc=True, errors="coerce")
            if isinstance(ts, pd.Timestamp) and pd.notna(ts):
                return ts  # 이미 UTC-aware
        except Exception:
            pass

    # 한국어 오전/오후 → AM/PM
    m = KR_TS_RE.search(s)
    if m:
        try:
            ymd, ampm, hms = m.groups()
            s2 = f"{ymd} {AM_PM_MAP.get(ampm, ampm)} {hms}"
            ts_naive = pd.to_datetime(s2, errors="coerce")
            if isinstance(ts_naive, pd.Timestamp) and pd.notna(ts_naive):
                return _ensure_utc(ts_naive, local_tz)
        except Exception:
            pass

    # 단순 YMD HMS (tz 정보 없음 → local_tz 가정)
    m = YMD_HMS_RE.search(s)
    if m:
        try:
            ts_naive = pd.to_datetime(m.group(0), errors="coerce")
            if isinstance(ts_naive, pd.Timestamp) and pd.notna(ts_naive):
                return _ensure_utc(ts_naive, local_tz)
        except Exception:
            pass
    return None

def to_iso_z(ts: Optional[pd.Timestamp]) -> str:
    if ts is None or pd.isna(ts):
        return ""
    try:
        ts_utc = ts.tz_convert("UTC") if ts.tzinfo else ts.tz_localize("UTC")
        return ts_utc.isoformat().replace("+00:00", "Z")
    except Exception:
        return ""

# ---------------------------
# 로딩/파싱
# ---------------------------
def _decode_bytes(file_bytes: bytes) -> str:
    for enc in ("utf-8", "cp949", "euc-kr", "latin-1"):
        try:
            return file_bytes.decode(enc)
        except Exception:
            continue
    return file_bytes.decode("utf-8", errors="ignore")

def _csv_reader_with_fallback(sio: io.StringIO):
    """CSV Sniffer 강화: 구분자 후보 지정 + 다단계 Fallback"""
    sample = sio.read(4096)  # 넉넉한 샘플
    sio.seek(0)
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        return csv.reader(sio, dialect)
    except Exception:
        # 후보별 수동 시도
        for delim in [",", "\t", ";", "|"]:
            sio.seek(0)
            try:
                return csv.reader(sio, delimiter=delim)
            except Exception:
                continue
        sio.seek(0)
        return csv.reader(sio)  # 최후의 수단

def _iter_json_lines(text: str, name: str):
    """JSON/NDJSON을 라인 문자열 리스트로 변경(탭 결합)"""
    out = []
    if name.lower().endswith(".ndjson"):
        for i, line in enumerate(text.splitlines(), start=1):
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
                # 대표 타임스탬프 키를 찾아 가장 먼저 오는 값을 헤더처럼 앞에 둠
                ts_val = ""
                for k in JSON_TIME_KEYS:
                    if k in obj:
                        ts_val = str(obj[k])
                        break
                # 간단히 탭으로 key=value 나열
                kv = "\t".join(f"{k}={obj.get(k)}" for k in list(obj)[:20])
                out.append(f"{ts_val}\t{kv}")
            except Exception:
                # JSON 파싱 실패 시 원문 라인
                out.append(s)
        return out
    else:
        # .json (객체 또는 리스트)
        try:
            data = json.loads(text)
            rows = data if isinstance(data, list) else [data]
            for obj in rows:
                if not isinstance(obj, dict):
                    out.append(str(obj))
                    continue
                ts_val = ""
                for k in JSON_TIME_KEYS:
                    if k in obj:
                        ts_val = str(obj[k])
                        break
                kv = "\t".join(f"{k}={obj.get(k)}" for k in list(obj)[:30])
                out.append(f"{ts_val}\t{kv}")
            return out
        except Exception:
            # 구조 예측 실패 → 일반 텍스트로
            return text.splitlines()

def read_text_like(file_bytes: bytes, name: str) -> List[str]:
    """CSV/텍스트/JSON/NDJSON를 라인 리스트로 반환."""
    text = _decode_bytes(file_bytes)
    lower = name.lower()

    # JSON/NDJSON 우선 처리
    if lower.endswith(".json") or lower.endswith(".ndjson"):
        return _iter_json_lines(text, name)

    # CSV 감지(확장자 또는 쉼표 수 + 줄 수)
    head = text[:2000]
    is_csv = (lower.endswith(".csv") or (head.count(",") >= 2 and "\n" in head))
    if is_csv:
        sio = io.StringIO(text)
        reader = _csv_reader_with_fallback(sio)
        lines = []
        for row in reader:
            if not row:
                continue
            lines.append("\t".join("" if c is None else str(c) for c in row))
        return lines

    # 일반 텍스트
    return text.splitlines()

@st.cache_data(show_spinner=False)
def extract_records(all_files: List[Tuple[str, bytes]], local_tz: str) -> List[LogLine]:
    records: List[LogLine] = []
    for fname, data in all_files:
        lines = read_text_like(data, fname)
        for i, raw in enumerate(lines, start=1):
            s = (raw or "").strip()
            if not s:
                continue
            s_norm = _korean_ampm_to_en(s)
            ts = parse_timestamp_any(s_norm, local_tz=local_tz)
            records.append(LogLine(file=fname, line=i, ts=ts, text=s))

    # 정렬: ts(없으면 +∞) → 파일 → 라인
    def _key(r: LogLine):
        if r.ts is None or pd.isna(r.ts):
            return (pd.Timestamp.max.tz_localize("UTC"), r.file, r.line)
        try:
            t = r.ts.tz_convert("UTC") if r.ts.tzinfo else r.ts.tz_localize("UTC")
        except Exception:
            t = pd.Timestamp.max.tz_localize("UTC")
        return (t, r.file, r.line)

    records.sort(key=_key)
    return records

def _sanitize_msg(msg: str, max_len: int = 600) -> str:
    msg = msg.replace("\t", " ").replace("  ", " ")
    msg = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", msg)  # 제어문자 제거
    if len(msg) > max_len:
        msg = msg[:max_len] + " …"
    return msg

def build_evidence_lines(records: List[LogLine], max_lines: int = 5000) -> List[str]:
    out = []
    for r in records[:max_lines]:
        ts = to_iso_z(r.ts) or "NA"
        msg = _sanitize_msg(r.text)
        out.append(f"[{r.file}:{r.line}@{ts}] {msg}")
    return out

# ---------------------------
# 고정 프롬프트(사용자 사양)
# ---------------------------
FIXED_PROMPT = """당신은 로그 분석 전문가입니다.
첨부된 로그와 부가 자료를 근거 기반으로 문제의 근본 원인을 식별하고, 실행 가능한 해결책과 재발 방지 대책을 제시한 뒤
분석 결과를 바탕으로 고객사 전달용 이메일 초안까지 작성하세요.

절대 준수 사항
추측 금지: 로그에 없는 사실은 적지 말고 로그 근거 없음/추가 필요로 표기
증거 인용 필수: 모든 주장에 증거 인용을 붙일 것
- 포맷: [파일명:라인번호@ISO8601타임스탬프(타임존)] 메시지 요약…
충돌되는 정보가 있을 경우 로그 증거를 최우선으로 하되, 불일치 사항은 “로그 근거 없음/추가 필요”로 명시
보안: 토큰/계정/내부호스트/PII는 ****로 마스킹
숫자 규칙: 비율은 소수점 1자리 반올림, 표/합계/기여도는 교차검증
타임존: 가능한 경우 원시 로그의 타임존을 보존, 혼재 시 하나의 타임존(예: UTC)으로 정규화 후 명시
언어/톤: 문서는 한국어, 기술적으로 명확·간결 / 이메일은 비전문가용 쉬운 표현

방법론(요약)
1. 전처리: 중복 제거(오류 시그니처), 타임존 정규화, PII 마스킹
2. 시그니처화 & 집계: 오류 그룹화, 최초/최다/최신, 오류 발생 비율(%)
3. 원인 기여도 산정(총합 100%): 빈도0.4, 심각도0.4, 상관0.1, 스택패턴0.1
4. 해결/완화/예방: 즉시 적용 가능한 조치, 우선순위/대체안
5. 검증 체크: 수치/인용/마스킹/타임존 점검

출력물(필수)
🔍 1. 로그 개요
⚠️ 2. 주요 오류 식별
🧠 3. 오류 분석(기여도 표 포함, 총합 100%)
🛠️ 4. 문제 해결 방안(우선순위)
🧩 5. 예방 및 모니터링 전략
🔬 6. 추가 분석 권고
📌 요청 사항 요약
📧 고객사 전달용 이메일 초안 (비전문가용)
"""

# ---------------------------
# UI
# ---------------------------
st.title("📄 범용 로그 분석기 + 🌐 Puter.js(무제한/무키) AI 보고서")

tab1, tab2 = st.tabs(["로그 업로드·전처리", "AI 분석 (키 없이 Puter.js)"])

with tab1:
    st.caption("여러 개의 텍스트/CSV/JSON/NDJSON/로그 파일을 업로드하면 자동으로 시간 순으로 정렬·정규화합니다.")
    files = st.file_uploader(
        "파일 선택(다중)", 
        type=["log", "txt", "csv", "json", "ndjson"], 
        accept_multiple_files=True
    )
    # 로컬 타임존 선택(기본 Asia/Seoul)
    local_tz = st.selectbox(
        "입력 로그의 기본(naive) 시간대", 
        ["Asia/Seoul", "UTC", "Asia/Tokyo", "America/Los_Angeles", "Europe/London"], 
        index=0, 
        help="타임존 정보가 없는 타임스탬프에 적용됩니다. 이후 UTC로 정규화됩니다."
    )

    max_preview = st.slider("미리보기 라인 수", 50, 2000, 200, step=50)

    if files:
        payload = [(f.name, f.read()) for f in files]
        records = extract_records(payload, local_tz)
        st.session_state["records"] = records
        st.session_state["local_tz"] = local_tz

        df = pd.DataFrame([{
            "파일": r.file,
            "라인": r.line,
            "타임스탬프(UTC)": to_iso_z(r.ts),
            "메시지": r.text
        } for r in records[:max_preview]])
        st.dataframe(df, use_container_width=True, height=400)

        df_all = pd.DataFrame([{
            "file": r.file,
            "line": r.line,
            "ts_utc": to_iso_z(r.ts),
            "text": r.text
        } for r in records])
        csv_bytes = df_all.to_csv(index=False).encode("utf-8")
        st.download_button("정규화 로그 CSV 다운로드", data=csv_bytes, file_name="normalized_logs.csv", mime="text/csv")
    else:
        st.info("파일을 업로드하세요.")

with tab2:
    st.subheader("🧠 Puter.js로 AI 분석 실행 (No API Key)")
    st.caption("아래 버튼을 누르면 브라우저(iframe)에서 Puter.js가 실행되어 보고서를 생성합니다. "
               "기업망에서 차단될 경우 IT팀에 js.puter.com 허용(CSP/프록시) 요청이 필요할 수 있습니다.")

    # 고급 옵션
    cols = st.columns(3)
    with cols[0]:
        model = st.selectbox("모델(권장 기본값 사용)", ["gpt-4.1-nano", "gpt-4o-mini", "gpt-5", "o3", "claude-3-5-sonnet"], index=0)
    with cols[1]:
        temperature = st.number_input("temperature", min_value=0.0, max_value=2.0, value=0.2, step=0.1)
    with cols[2]:
        max_tokens = st.number_input("max_tokens(0=모델 기본)", min_value=0, max_value=200000, value=0, step=1000)

    auto_chunk_limit = st.number_input("브라우저로 전송할 최대 바이트(청크 단위, 권장 120000~240000)", 
                                       min_value=50000, max_value=500000, value=160000, step=10000)
    test_mode = st.toggle("테스트 모드 사용(요청 크레딧 소모 위험 최소화)", value=False, help="Puter testMode (일부 환경에서만 적용)")

    run = st.button("🚀 분석 시작")
    output_height = 560

    if run:
        recs: List[LogLine] = st.session_state.get("records", [])
        if not recs:
            st.error("업로드된 정규화 레코드가 없습니다. 먼저 파일을 업로드하세요.")
        else:
            evid = build_evidence_lines(recs, max_lines=20000)
            text_blob = "\n".join(evid)
            fixed = FIXED_PROMPT.strip()

            # 자동 청크 튜닝: 너무 작은 limit이면 증가, 너무 크면 감소(경험적)
            limit = int(auto_chunk_limit)
            if limit < 80000:
                limit = 80000
            elif limit > 300000:
                limit = 300000

            def chunkify(s: str, limit: int) -> List[str]:
                bs = s.encode("utf-8", errors="ignore")
                if len(bs) <= limit:
                    return [s]
                parts = []
                start = 0
                N = len(bs)
                while start < N:
                    end = min(start + limit, N)
                    if end < N:
                        back = bs[start:end].rfind(b"\n")
                        if back > 0:
                            end = start + back + 1
                    chunk = bs[start:end].decode("utf-8", errors="ignore")
                    parts.append(chunk)
                    start = end
                return parts

            chunks = chunkify(text_blob, limit)
            payload = {
                "fixed_prompt": fixed,
                "chunk_count": len(chunks),
                "chunks": chunks,
                "options": {
                    "model": model,
                    "stream": True,
                    "temperature": temperature,
                    **({"max_tokens": max_tokens} if max_tokens > 0 else {})
                },
                "testMode": bool(test_mode)
            }
            b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

            # HTML/JS: escape + 줄바꿈 처리, 진행률/오류 표시 강화
            html_code = f"""
<div style="font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace;">
  <p><strong>브라우저 내 Puter.js 실행 중…</strong></p>
  <div id="status" style="margin:6px 0;color:#666;">초기화 중…</div>
  <pre id="out" style="white-space:pre-wrap;background:#070c1a;color:#e8eefc;border-radius:8px;padding:14px;min-height:360px;"></pre>
  <pre id="err" style="white-space:pre-wrap;color:#ff9aa2;"></pre>
  <div style="font-size:12px;color:#888;margin-top:6px;">
    네트워크/CSP 문제로 Puter.js가 로드되지 않으면 IT팀에 <code>https://js.puter.com/v2/</code> 허용을 요청하세요.
  </div>
</div>

<script src="https://js.puter.com/v2/"></script>
<script>
(function() {{
  const out = document.getElementById('out');
  const err = document.getElementById('err');
  const status = document.getElementById('status');
  function esc(s) {{
    return (s||'').replace(/[&<>]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c]));
  }}

  try {{
    const raw = atob("{b64}");
    const data = JSON.parse(raw);
    const fixed = data.fixed_prompt;
    const chunks = data.chunks || [];
    const total = data.chunk_count || chunks.length;
    const options = data.options || {{}};
    const testMode = !!data.testMode;

    if (!window.puter || !puter.ai || !puter.ai.chat) {{
      err.textContent = "Puter.js가 로드되지 않았습니다. 네트워크 또는 브라우저 보안 정책(CSP)을 확인하세요.";
      return;
    }}

    status.textContent = `총 ${'{'}total{'}'}개 청크 분석을 시작합니다… (모델: ${'{'}options.model||'기본'{'}'})`;

    (async () => {{
      let messages = [{{ role: "system", content: fixed }}];

      for (let i = 0; i < total; i++) {{
        let user_content;
        if (i === 0) {{
          user_content = `아래는 정규화된 증거 라인입니다. [파일:라인@ISO8601Z] 메시지 형식을 따릅니다. 총 ${'{'}total{'}'}개 청크 중 1개를 보냅니다. 이를 기반으로 전체 보고서의 뼈대를 작성하고, 인용 포맷을 유지하세요.\\n\\n` + (chunks[i] || '');
        }} else {{
          user_content = [
            "이어서 청크 " + (i + 1) + " / " + total + " 를 반영하여 이전 답변을 보완/정교화하여 완전한 단일 보고서를 다시 작성하세요.",
            "중복 내용은 요약하고, 증거 인용은 필수로 유지하세요.",
            "이전 답변의 모든 내용을 포함해야 합니다. 이것은 추가가 아니라 업데이트입니다.",
            "",
            chunks[i] || ""
          ].join("\\n");
        }}
        messages.push({{ role: "user", content: user_content }});

        status.textContent = `청크 ${{i + 1}} / ${{total}} 분석 중… 이전 내용을 바탕으로 보고서를 다시 생성합니다.`;
        out.innerHTML = ''; // 이전 출력을 지우고 새로 생성
        err.textContent = '';

        let fullResponseContent = "";
        try {{
          let resp = await puter.ai.chat(messages, testMode, {{ ...options, stream: true }});
          for await (const part of resp) {{
            const t = (typeof part === 'string') ? part
              : (part && part.text) ? part.text
              : (part && part.message && typeof part.message.content === 'string') ? part.message.content
              : (part && part.message && Array.isArray(part.message.content)) ? part.message.content.map(c => (typeof c === 'string' ? c : (c && c.text) || '')).join('')
              : '';
            if (t) {{
              fullResponseContent += t;
              out.innerHTML += esc(t).replaceAll("\\n", "<br>");
            }}
          }}
          messages.push({{ role: "assistant", content: fullResponseContent }});
        }} catch (e) {{
          console.error(e);
          err.textContent = `스트리밍 오류 (청크 ${{i + 1}}): ` + (e?.message || e?.toString?.() || "알 수 없는 오류");
          break; // Exit loop on error
        }}
      }}
      status.textContent = "분석 완료";
    }})();
  }} catch (e) {{
    console.error(e);
    err.textContent = "오류: " + (e?.message || e?.toString?.() || "알 수 없는 오류");
  }}
})();
</script>
"""
            st_html(html_code, height=output_height + 140, scrolling=True)
    else:
        st.info("전처리된 로그를 바탕으로 브라우저에서 Puter.js가 실행됩니다. 먼저 파일을 업로드한 뒤 [분석 시작]을 눌러주세요.")
