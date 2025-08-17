# -*- coding: utf-8 -*-
# streamlit run main.py
import streamlit as st
import base64, json, re, io, csv
from dataclasses import dataclass
from typing import List, Optional, Tuple
import pandas as pd

st.set_page_config(page_title="범용 로그 분석기 + Puter.js(무제한/무키) AI 보고서", layout="wide")

# ---------------------------
# 공통 유틸
# ---------------------------
AM_PM_MAP = {"오전": "AM", "오후": "PM"}

ISO_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
)
KR_TS_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2})\s*(오전|오후)\s*(\d{1,2}:\d{2}:\d{2})"
)
YMD_HMS_RE = re.compile(
    r"\b(\d{4}[-/]\d{1,2}[-/]\d{1,2})[ T](\d{1,2}:\d{2}:\d{2})\b"  # naive
)

def _korean_ampm_to_en(s: str) -> str:
    return s.replace("오전", "AM").replace("오후", "PM")

def parse_timestamp_any(s: str) -> Optional[pd.Timestamp]:
    """여러 형태의 타임스탬프를 찾아 UTC-aware Timestamp로 반환. 없으면 None."""
    # ISO/RFC3339 우선
    m = ISO_TS_RE.search(s)
    if m:
        try:
            ts = pd.to_datetime(m.group(0), utc=True, errors="coerce")
            if isinstance(ts, pd.Timestamp) and pd.notna(ts):
                return ts
        except Exception:
            pass

    # 한국어 오전/오후
    m = KR_TS_RE.search(s)
    if m:
        try:
            ymd, ampm, hms = m.groups()
            s2 = f"{ymd} {AM_PM_MAP.get(ampm, ampm)} {hms}"
            ts = pd.to_datetime(s2, utc=True, errors="coerce")
            if isinstance(ts, pd.Timestamp) and pd.notna(ts):
                return ts
        except Exception:
            pass

    # 단순 YMD HMS (tz 정보 없음 → UTC 가정)
    m = YMD_HMS_RE.search(s)
    if m:
        try:
            ts = pd.to_datetime(m.group(0), utc=True, errors="coerce")  # naive→UTC
            if isinstance(ts, pd.Timestamp) and pd.notna(ts):
                return ts
        except Exception:
            pass
    return None

def to_iso_z(ts: Optional[pd.Timestamp]) -> str:
    if ts is None or pd.isna(ts):
        return ""
    ts_utc = ts.tz_convert("UTC") if ts.tzinfo else ts.tz_localize("UTC")
    return ts_utc.isoformat().replace("+00:00", "Z")

@dataclass
class LogLine:
    file: str
    line: int
    ts: Optional[pd.Timestamp]
    text: str

# ---------------------------
# 로딩/파싱
# ---------------------------
def read_text_like(file_bytes: bytes, name: str) -> List[str]:
    """CSV/텍스트를 모두 라인 리스트로 반환."""
    # 1) 바이너리→텍스트
    for enc in ("utf-8", "cp949", "euc-kr", "latin-1"):
        try:
            text = file_bytes.decode(enc)
            break
        except Exception:
            continue
    else:
        text = file_bytes.decode("utf-8", errors="ignore")

    # 2) CSV 감지 (쉼표 다수 & 줄 수 > 1 이면 CSV로 가정)
    head = text[:2000]
    is_csv = (name.lower().endswith(".csv") or head.count(",") >= 2)
    if is_csv:
        lines = []
        sio = io.StringIO(text)
        try:
            # 다양한 구분자 시도
            sniffer = csv.Sniffer()
            dialect = sniffer.sniff(sio.read(2048))
            sio.seek(0)
            reader = csv.reader(sio, dialect)
        except Exception:
            sio.seek(0)
            reader = csv.reader(sio)

        for row in reader:
            if not row:
                continue
            # 컬럼들을 탭으로 합쳐 1라인으로
            lines.append("\t".join([c if c is not None else "" for c in row]))
        return lines

    # 일반 텍스트
    return text.splitlines()

def extract_records(all_files: List[Tuple[str, bytes]]) -> List[LogLine]:
    records: List[LogLine] = []
    for fname, data in all_files:
        lines = read_text_like(data, fname)
        for i, raw in enumerate(lines, start=1):
            s = raw.strip()
            if not s:
                continue
            s_norm = _korean_ampm_to_en(s)
            ts = parse_timestamp_any(s_norm)
            rec = LogLine(file=fname, line=i, ts=ts, text=s)
            records.append(rec)

    # 정렬: ts(없으면 +∞) → 파일 → 라인
    def _key(r: LogLine):
        # tz-aware 보장: None→max, 나머지는 UTC
        if r.ts is None or pd.isna(r.ts):
            return (pd.Timestamp.max.tz_localize("UTC"), r.file, r.line)
        t = r.ts
        t = t.tz_localize("UTC") if t.tzinfo is None else t.tz_convert("UTC")
        return (t, r.file, r.line)

    records.sort(key=_key)
    return records

def build_evidence_lines(records: List[LogLine], max_lines:int=5000) -> List[str]:
    out = []
    for r in records[:max_lines]:
        ts = to_iso_z(r.ts) or "NA"
        # 너무 긴 메시지는 600자 내로 요약
        msg = r.text.replace("\t", " ").replace("  ", " ")
        if len(msg) > 600:
            msg = msg[:600] + " …"
        out.append(f"[{r.file}:{r.line}@{ts}] {msg}")
    return out

# ---------------------------
# 고정 프롬프트(사용자 제공 사양)
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
    st.caption("여러 개의 텍스트/CSV/로그 파일을 업로드하면 자동으로 시간 순으로 정렬·정규화합니다.")
    files = st.file_uploader("파일 선택(다중)", type=["log", "txt", "csv", "json", "ndjson"], accept_multiple_files=True)

    max_preview = st.slider("미리보기 라인 수", 50, 2000, 200, step=50)

    if files:
        payload = [(f.name, f.read()) for f in files]
        records = extract_records(payload)
        st.session_state["records"] = records

        # 미리보기 테이블
        df = pd.DataFrame([{
            "파일": r.file,
            "라인": r.line,
            "타임스탬프(UTC)": to_iso_z(r.ts),
            "메시지": r.text
        } for r in records[:max_preview]])
        st.dataframe(df, use_container_width=True, height=400)

        # 다운로드(정규화 CSV)
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
    st.caption("아래 버튼을 누르면 브라우저(iframe)에서 Puter.js가 실행되어 보고서를 생성합니다.")
    auto_chunk_limit = st.number_input("브라우저로 전송할 최대 바이트(청크 단위, 권장 120000~240000)", min_value=50000, max_value=500000, value=160000, step=10000)

    run = st.button("🚀 분석 시작")
    output_height = 520

    if run:
        recs: List[LogLine] = st.session_state.get("records", [])
        if not recs:
            st.error("업로드된 정규화 레코드가 없습니다. 먼저 파일을 업로드하세요.")
        else:
            evid = build_evidence_lines(recs, max_lines=20000)
            # 대용량 안전 전송: JSON → base64
            # 너무 크면 청크로 나눔
            text_blob = "\n".join(evid)
            fixed = FIXED_PROMPT.strip()

            def chunkify(s: str, limit: int) -> List[str]:
                bs = s.encode("utf-8")
                if len(bs) <= limit:
                    return [s]
                # 문장 단위로 잘라 최대한 경계 유지
                parts = []
                start = 0
                while start < len(bs):
                    end = min(start + limit, len(bs))
                    # 경계 보정(줄바꿈 기준)
                    if end < len(bs):
                        # 뒤로 가며 \n 찾기
                        back = bs[start:end].rfind(b"\n")
                        if back > 0:
                            end = start + back + 1
                    chunk = bs[start:end].decode("utf-8", errors="ignore")
                    parts.append(chunk)
                    start = end
                return parts

            chunks = chunkify(text_blob, int(auto_chunk_limit))
            # Puter로 넘길 페이로드
            payload = {
                "fixed_prompt": fixed,
                "chunk_count": len(chunks),
                "chunks": chunks
            }
            b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

            html = f"""
<div style="font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace;">
  <p><strong>브라우저 내 Puter.js 실행 중…</strong> (스트리밍 표시, 오류 발생 시 아래에 적색으로 표시됩니다)</p>
  <div id="status" style="margin:6px 0;color:#666;"></div>
  <pre id="out" style="white-space:pre-wrap;background:#070c1a;color:#e8eefc;border-radius:8px;padding:14px;min-height:360px;"></pre>
  <pre id="err" style="white-space:pre-wrap;color:#ff9aa2;"></pre>
</div>

<script src="https://js.puter.com/v2/"></script>
<script>
(async () => {{
  const out = document.getElementById('out');
  const err = document.getElementById('err');
  const status = document.getElementById('status');

  function append(txt) {{
    out.textContent += txt;
  }}
  function appendLn(txt) {{
    out.textContent += txt + "\\n";
  }}

  try {{
    const raw = atob("{b64}");
    const data = JSON.parse(raw);
    const fixed = data.fixed_prompt;
    const chunks = data.chunks || [];
    const total = data.chunk_count || chunks.length;

    if (!window.puter || !puter.ai || !puter.ai.chat) {{
      err.textContent = "Puter.js가 로드되지 않았습니다. 네트워크 또는 브라우저 보안 정책(CSP)을 확인하세요.";
      return;
    }}

    // 진행 상태
    status.textContent = `총 {{total}} 청크 분석을 시작합니다…`;

    // 1) 첫 청크: 시스템+유저 메시지로 시작
    let messages = [
      {{ role: "system", content: fixed }},
      {{ role: "user", content: `아래는 정규화된 증거 라인입니다. [파일:라인@ISO8601Z] 메시지 형식을 따릅니다. 총 {{total}}개 청크 중 1개를 보냅니다. 이를 기반으로 전체 보고서의 뼈대를 작성하고, 인용 포맷을 유지하세요.\\n\\n` + chunks[0] }}
    ];

    // 스트리밍으로 출력
    let resp = await puter.ai.chat(messages, {{ stream: true }});
    for await (const part of resp) {{
      if (typeof part === 'string') append(part);
      else if (part && typeof part.text === 'string') append(part.text);
      else if (part && part.message && typeof part.message.content === 'string') append(part.message.content);
      else if (part && part.message && Array.isArray(part.message.content)) {{
        for (const c of part.message.content) {{
          if (typeof c === 'string') append(c);
          else if (c && c.text) append(c.text);
        }}
      }}
    }}
    append("\\n");

    // 2) 나머지 청크는 '연속 작업'으로 전달
    for (let i = 1; i < total; i++) {{
      status.textContent = `청크 {{i+1}} / {{total}} 분석 중…`;
      const followUser = [
        "이어서 청크 " + (i+1) + " / " + total + " 를 반영하여 동일한 구조로 보완/정교화하세요.",
        "중복 내용은 요약하고, 증거 인용은 필수로 유지하세요.",
        "마지막 청크에서는 전체를 일관된 하나의 보고서로 재정리하세요.",
        "",
        chunks[i]
      ].join("\\n");
      // 이전 컨텍스트 요약을 막기 위해 최근 사용자 메시지만 전달(모델 컨텍스트는 벤더별 최적화됨)
      let r2 = await puter.ai.chat([{{
        role: "system", content: fixed
      }}, {{
        role: "user", content: followUser
      }}], {{ stream: true }});

      for await (const part of r2) {{
        if (typeof part === 'string') append(part);
        else if (part && typeof part.text === 'string') append(part.text);
        else if (part && part.message && typeof part.message.content === 'string') append(part.message.content);
        else if (part && part.message && Array.isArray(part.message.content)) {{
          for (const c of part.message.content) {{
            if (typeof c === 'string') append(c);
            else if (c && c.text) append(c.text);
          }}
        }}
      }}
      append("\\n");
    }}

    status.textContent = "분석 완료";
  }} catch (e) {{
    console.error(e);
    err.textContent = "오류: " + (e?.message || e?.toString?.() || "알 수 없는 오류");
  }}
}})();
</script>
"""
            st.components.v1.html(html, height=output_height + 100, scrolling=True)
    else:
        st.info("전처리된 로그를 바탕으로 브라우저에서 Puter.js가 실행됩니다. 먼저 파일을 업로드한 뒤 [분석 시작]을 눌러주세요.")
