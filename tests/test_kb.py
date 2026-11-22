"""security-kb 테스트. BM25·RRF·파서는 torch 없이 돈다."""

from vulnagent.kb.cwe import parse
from vulnagent.kb.search import BM25, rrf, tokenize

XML = b"""<?xml version="1.0"?>
<Weakness_Catalog Name="CWE" Version="9.9" xmlns="http://cwe.mitre.org/cwe-8">
 <Weaknesses>
  <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')" Abstraction="Base" Status="Stable">
   <Description>The product does not neutralize user-controllable input before it is placed in output used as a web page.</Description>
   <Common_Consequences><Consequence><Scope>Integrity</Scope><Impact>Execute Unauthorized Code</Impact></Consequence></Common_Consequences>
   <Potential_Mitigations><Mitigation><Description>Use output encoding.</Description></Mitigation></Potential_Mitigations>
   <Observed_Examples><Observed_Example><Reference>CVE-2021-0001</Reference><Description>XSS in the search box of FooCMS</Description></Observed_Example></Observed_Examples>
  </Weakness>
  <Weakness ID="1" Name="Old" Abstraction="Base" Status="Deprecated"><Description>gone</Description></Weakness>
 </Weaknesses>
 <Groupings><Grouping ID="1000" Name="Injection Grouping" Status="Draft"><Summary>Weaknesses about injection.</Summary></Grouping></Groupings>
</Weakness_Catalog>"""


def test_parse_keeps_observed_examples_out_of_the_search_text():
    version, entries = parse(XML)
    assert version == "9.9"
    by_id = {e["cwe_id"]: e for e in entries}
    assert set(by_id) == {"CWE-79", "CWE-1000"}  # Deprecated 제외
    xss = by_id["CWE-79"]
    assert xss["observed_cves"] == ["CVE-2021-0001"]
    assert "FooCMS" not in xss["doc"] and "FooCMS" in xss["observed_text"]  # 누수 방지
    assert "output encoding" in xss["doc"] and "Integrity" in xss["doc"]
    assert by_id["CWE-1000"]["kind"] == "grouping" and "injection" in by_id["CWE-1000"]["doc"]


def test_tokenize_drops_stopwords_and_single_chars():
    assert tokenize("The SQL injection in a login-form (CVE-2020-1)") == ["sql", "injection", "login", "form", "cve", "2020"]


def test_bm25_prefers_documents_with_rare_query_terms():
    docs = [tokenize(t) for t in (
        "sql injection in database query construction",
        "cross site scripting in web page output",
        "buffer overflow memory corruption in parser",
    )]
    scores = BM25(docs).scores(tokenize("attacker injects SQL into the login query"))
    assert max(scores, key=scores.get) == 0


def test_rrf_rewards_items_ranked_high_by_both_lists():
    fused = rrf([["a", "b", "c"], ["b", "a", "d"]])
    assert [doc for doc, _ in fused[:2]] in (["a", "b"], ["b", "a"])
    assert dict(fused)["d"] < dict(fused)["c"] or dict(fused)["d"] == dict(fused)["c"]
