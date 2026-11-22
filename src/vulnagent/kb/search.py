"""CWE 검색: BM25(키워드) · 임베딩(의미) · 하이브리드(RRF).

- BM25: 직접 구현한 Okapi BM25 (역색인). 조문 번호 같은 정확한 단어("SQL", "deserialization")에 강하다.
- 임베딩: sentence-transformers 모델로 문서를 벡터화해 pgvector에 저장하고 코사인 거리로 찾는다.
  표현이 달라도 뜻이 같으면 찾는다 ("crafted input crashes the parser" -> 메모리 손상 계열).
- 하이브리드: 두 순위를 Reciprocal Rank Fusion으로 합친다. 점수 척도가 달라도 순위만 쓰므로 합치기 쉽다.

모델은 서버에 이미 받아 둔 것을 오프라인으로 쓴다 (HF_HUB_OFFLINE). 공용 서버라 CPU 스레드 수를 제한한다.
"""

import math
import os
import re
from collections import Counter, defaultdict

import psycopg

DEFAULT_MODEL = "sentence-transformers/all-mpnet-base-v2"
MODELS = {
    "minilm": "sentence-transformers/all-MiniLM-L6-v2",
    "mpnet": "sentence-transformers/all-mpnet-base-v2",
}

_TOKEN = re.compile(r"[a-z0-9]+")
STOPWORDS = frozenset(
    "a an and are as at be been by can could does do for from has have if in into is it its may might more "
    "not of on or other such than that the their them then there these this those to via was were when where "
    "which while who with within without would".split()
)


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if len(t) > 1 and t not in STOPWORDS]


class BM25:
    """Okapi BM25 (k1=1.5, b=0.75). 질의 쪽 단어는 중복을 세지 않는다."""

    def __init__(self, docs: list[list[str]], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.n = len(docs)
        self.lengths = [len(d) for d in docs]
        self.avg = sum(self.lengths) / max(self.n, 1)
        self.postings: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for i, doc in enumerate(docs):
            for term, f in Counter(doc).items():
                self.postings[term].append((i, f))
        self.idf = {t: math.log(1 + (self.n - len(p) + 0.5) / (len(p) + 0.5)) for t, p in self.postings.items()}

    def scores(self, query_tokens: list[str]) -> dict[int, float]:
        out: dict[int, float] = defaultdict(float)
        for term in set(query_tokens):
            idf = self.idf.get(term)
            if idf is None:
                continue
            for i, f in self.postings[term]:
                norm = self.k1 * (1 - self.b + self.b * self.lengths[i] / self.avg)
                out[i] += idf * f * (self.k1 + 1) / (f + norm)
        return out


def rrf(rankings: list[list[str]], k: int = 60) -> list[tuple[str, float]]:
    """Reciprocal Rank Fusion: 각 순위 목록에서 1/(k + 순위)를 더한다."""
    fused: dict[str, float] = defaultdict(float)
    for ranking in rankings:
        for rank, doc_id in enumerate(ranking, 1):
            fused[doc_id] += 1.0 / (k + rank)
    return sorted(fused.items(), key=lambda kv: -kv[1])


_ENCODERS: dict[str, object] = {}


def encoder(model: str):
    if model not in _ENCODERS:
        os.environ.setdefault("HF_HUB_OFFLINE", "1")  # 이미 받아 둔 모델만 사용 (네트워크로 받지 않음)
        import torch
        from sentence_transformers import SentenceTransformer

        torch.set_num_threads(int(os.environ.get("VULNAGENT_TORCH_THREADS", "8")))  # 공용 서버 배려
        _ENCODERS[model] = SentenceTransformer(model, device="cpu")
    return _ENCODERS[model]


def _vec(values) -> str:
    return "[" + ",".join(f"{float(v):.6f}" for v in values) + "]"


class CweIndex:
    def __init__(self, conn: psycopg.Connection, include_observed: bool = False):
        """include_observed=True는 누수 비교 실험 전용 (관찰 사례 설명까지 색인)."""
        self.conn = conn
        rows = conn.execute(
            "SELECT cwe_id, kind, name, abstraction, description, doc, observed_text FROM cwe_entry ORDER BY cwe_id"
        ).fetchall()
        self.rows = {r["cwe_id"]: r for r in rows}
        self.ids = [r["cwe_id"] for r in rows]
        texts = [r["doc"] + ("\n" + (r["observed_text"] or "") if include_observed else "") for r in rows]
        self.bm25 = BM25([tokenize(t) for t in texts])

    def __contains__(self, cwe_id: str) -> bool:
        return cwe_id in self.rows

    # -------------------------------------------------------------- 키워드
    def bm25_search(self, query: str, k: int = 10) -> list[tuple[str, float]]:
        scores = self.bm25.scores(tokenize(query))
        top = sorted(scores.items(), key=lambda kv: -kv[1])[:k]
        return [(self.ids[i], s) for i, s in top]

    # -------------------------------------------------------------- 임베딩 (pgvector)
    def ensure_embeddings(self, model: str) -> int:
        have = {r["cwe_id"] for r in self.conn.execute("SELECT cwe_id FROM cwe_embedding WHERE model = %s", (model,))}
        todo = [cid for cid in self.ids if cid not in have]
        if not todo:
            return 0
        vectors = encoder(model).encode([self.rows[c]["doc"] for c in todo], batch_size=32,
                                        normalize_embeddings=True, show_progress_bar=False)
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO cwe_embedding (cwe_id, model, embedding) VALUES (%s, %s, %s::vector) "
                "ON CONFLICT (cwe_id, model) DO UPDATE SET embedding = EXCLUDED.embedding",
                [(c, model, _vec(v)) for c, v in zip(todo, vectors)],
            )
        return len(todo)

    def dense_search(self, query: str, k: int = 10, model: str = DEFAULT_MODEL) -> list[tuple[str, float]]:
        q = _vec(encoder(model).encode([query], normalize_embeddings=True, show_progress_bar=False)[0])
        rows = self.conn.execute(
            """
            SELECT cwe_id, 1 - (embedding <=> %(q)s::vector) AS score FROM cwe_embedding
            WHERE model = %(m)s ORDER BY embedding <=> %(q)s::vector LIMIT %(k)s
            """,
            {"q": q, "m": model, "k": k},
        )
        return [(r["cwe_id"], float(r["score"])) for r in rows]

    # -------------------------------------------------------------- 하이브리드
    def hybrid_search(self, query: str, k: int = 10, model: str = DEFAULT_MODEL, depth: int = 100) -> list[tuple[str, float]]:
        keyword = [cid for cid, _ in self.bm25_search(query, depth)]
        semantic = [cid for cid, _ in self.dense_search(query, depth, model)]
        return rrf([keyword, semantic])[:k]

    def search(self, query: str, k: int = 5, method: str = "hybrid", model: str = DEFAULT_MODEL) -> list[tuple[str, float]]:
        if method == "bm25":
            return self.bm25_search(query, k)
        if method == "dense":
            return self.dense_search(query, k, model)
        return self.hybrid_search(query, k, model)
