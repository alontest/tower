#!/usr/bin/env python3
"""Measure policy-group emoji recognition against public configs on GitHub.

The vocabulary in Tower/Models/PolicyGroupEmoji.swift was built from the
group names of 8,362 public configs (2026-10-19). This script rebuilds that
corpus and reports how much of it the recogniser reads, so new spellings can
be found and regressions caught. Nothing it downloads is bundled or committed:
everything stays in the work directory given with --work.

  python3 Scripts/policy_group_corpus.py search   --work DIR   # GitHub code search (needs gh, ~1 query/min)
  python3 Scripts/policy_group_corpus.py download --work DIR   # fetch each unique file
  python3 Scripts/policy_group_corpus.py parse    --work DIR   # groups.jsonl + eval_names.txt
  # then run the recogniser over DIR/eval_names.txt:
  #   TEST_RUNNER_TOWER_CORPUS=DIR/eval_names.txt xcodebuild test ... \
  #     -only-testing:TowerTests/PolicyGroupEmojiCorpusEvaluation
  python3 Scripts/policy_group_corpus.py report   --work DIR   # coverage and the most common misses

Downloaded files are untrusted data: they are only read as text here.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request
from urllib.parse import unquote, urlparse

QUERIES = [
    "custom_proxy_group --extension ini", "custom_proxy_group select --extension ini",
    "custom_proxy_group url-test --extension ini", "custom_proxy_group 节点选择 --extension ini",
    "custom_proxy_group 漏网之鱼", "custom_proxy_group 奈飞", "custom_proxy_group 自动选择",
    "proxy-groups 节点选择 --extension yaml", "proxy-groups 漏网之鱼 --extension yaml",
    "proxy-groups 自动选择 --extension yaml", "proxy-groups 奈飞 --extension yaml",
    "proxy-groups 国外媒体 --extension yaml", "proxy-groups 电报 --extension yaml",
    "proxy-groups 手动切换 --extension yaml", "proxy-groups Netflix select --extension yaml",
    "proxy-groups YouTube select --extension yaml", "proxy-groups OpenAI select --extension yaml",
    "proxy-groups 香港节点 --extension yaml", '"[Proxy Group]" select 节点选择',
    '"[Proxy Group]" select Netflix', '"[Proxy Group]" url-test 漏网之鱼', '"[policy]" static= img-url',
    '"[policy]" static= 节点选择', '"[Proxy Group]" select 香港 --extension conf',
    '"[Proxy Group]" select --extension lcf', "proxy-groups 视频 --extension yaml",
    "proxy-groups 影视 --extension yaml", "custom_proxy_group 影视", "proxy-groups 亚马逊 --extension yaml",
    "proxy-groups 学术 --extension yaml", "proxy-groups 游戏 --extension yaml", "proxy-groups 微软 --extension yaml",
    "proxy-groups 苹果 --extension yaml", "proxy-groups 谷歌 --extension yaml", "proxy-groups 哔哩哔哩 --extension yaml",
    "proxy-groups 巴哈姆特 --extension yaml", "proxy-groups 动漫 --extension yaml", "proxy-groups 社交 --extension yaml",
    "proxy-groups 新闻 --extension yaml", "proxy-groups 支付 --extension yaml",
]
LEADING_EMOJI = re.compile(
    "^((?:[\U0001F1E6-\U0001F1FF]{2})|(?:[\u2190-\u2BFF\u3030\u303D\u3297\u3299\u24C2\U0001F000-\U0001FAFF]"
    "(?:\uFE0F|\u200D[\u2190-\u2BFF\U0001F000-\U0001FAFF]\uFE0F?)*))\\s*(.*)$"
)


def search(work: str) -> None:
    hits = os.path.join(work, "hits")
    os.makedirs(hits, exist_ok=True)
    for index, query in enumerate(QUERIES, 1):
        out = os.path.join(hits, f"q{index}.json")
        if os.path.exists(out) and os.path.getsize(out) > 2:
            continue
        args = ["gh", "search", "code", *split_query(query), "--limit", "1000", "--json", "repository,path,sha,url"]
        result = subprocess.run(args, capture_output=True, text=True)
        open(out, "w").write(result.stdout or "[]")
        print(f"q{index} {len(json.loads(result.stdout or '[]'))}: {query}", flush=True)
        time.sleep(65)  # code search allows 10 requests a minute


def split_query(query: str) -> list[str]:
    return [part.strip('"') if part.startswith('"[') else part for part in re.findall(r'"[^"]*"\S*|\S+', query)]


def download(work: str) -> None:
    files = os.path.join(work, "files")
    os.makedirs(files, exist_ok=True)
    seen: dict[str, str] = {}
    for name in sorted(os.listdir(os.path.join(work, "hits"))):
        if name.endswith(".json"):
            for hit in json.load(open(os.path.join(work, "hits", name))):
                raw = hit["url"].replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/", 1)
                seen.setdefault(hit["sha"], raw)

    def fetch(item: tuple[str, str]) -> int:
        sha, url = item
        target = os.path.join(files, sha)
        if os.path.exists(target):
            return 1
        parts = urllib.parse.urlsplit(url)
        url = urllib.parse.urlunsplit(parts._replace(path=urllib.parse.quote(urllib.parse.unquote(parts.path))))
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Tower corpus"}), timeout=30) as response:
                data = response.read(5_000_001)
        except Exception:
            return 0
        if len(data) > 5_000_000:
            return 0
        open(target, "wb").write(data)
        return 1

    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        ok = sum(pool.map(fetch, seen.items()))
    print(f"{ok}/{len(seen)} files")


def stem(ref):
    ref = ref.strip().strip('"\'')
    path = unquote(urlparse(ref).path if "://" in ref else ref)
    base = os.path.basename(path.rstrip("/"))
    base = re.sub(r"\.(list|yaml|yml|txt|mrs|srs|json|conf|snippet|rules?)$", "", base, flags=re.I)
    return base

def emit(f, name, rules, members):
    name = name.strip().strip('"\'')
    if not name or len(name) > 60: return
    out.write(json.dumps({"file": f, "name": name, "rules": rules.get(name, []), "members": members}, ensure_ascii=False) + "\n")

def parse_ini(f, t):
    rules = {}
    for m in re.finditer(r"^ruleset=([^,\n]+),(.+)$", t, re.M):
        rules.setdefault(m.group(1).strip(), []).append(stem(m.group(2).split(",")[0]) if not m.group(2).startswith("[]") else m.group(2)[2:].split(",")[0])
    for m in re.finditer(r"^custom_proxy_group=(.+)$", t, re.M):
        parts = m.group(1).split("`")
        if len(parts) >= 2: emit(f, parts[0], rules, parts[2:])

def parse_yaml(f, t):
    providers = {}
    pm = re.search(r"^rule-providers:\s*\n((?:[ \t]+.*\n|\s*\n)+)", t, re.M)
    if pm:
        cur = None
        for line in pm.group(1).splitlines():
            k = re.match(r"^\s{2}([^\s:#][^:]*):\s*$", line) or re.match(r"^\s{2}([^\s:#][^:]*):\s*\{", line)
            if k: cur = k.group(1).strip().strip('"\''); providers[cur] = cur
            u = re.search(r"(?:url|path):\s*['\"]?([^'\"\s,}]+)", line)
            if cur and u: providers[cur] = stem(u.group(1))
    rules = {}
    for m in re.finditer(r"^\s*-\s*['\"]?RULE-SET,([^,]+),([^,'\"\n]+)", t, re.M):
        rules.setdefault(m.group(2).strip(), []).append(providers.get(m.group(1).strip(), m.group(1).strip()))
    for m in re.finditer(r"^\s*-\s*['\"]?(GEOSITE|GEOIP),([^,]+),([^,'\"\n]+)", t, re.M):
        rules.setdefault(m.group(3).strip(), []).append(f"{m.group(1)}:{m.group(2)}")
    gm = re.search(r"^proxy-groups:\s*\n((?:[ \t-].*\n|\s*\n)+)", t, re.M)
    if not gm: return
    block = gm.group(1)
    for m in re.finditer(r"^\s*-\s*\{\s*name:\s*([^,}]+)(.*)$", block, re.M):
        emit(f, m.group(1), rules, re.findall(r"proxies:\s*\[([^\]]*)\]", m.group(2)))
    for m in re.finditer(r"^\s*-\s*name:\s*(.+)$", block, re.M):
        emit(f, m.group(1).split(" #")[0], rules, [])

def parse_conf(f, t):
    rules = {}
    for m in re.finditer(r"^(?:RULE-SET|DOMAIN-SET),([^,\n]+),([^,\n]+)", t, re.M):
        rules.setdefault(m.group(2).strip(), []).append(stem(m.group(1)))
    for m in re.finditer(r"^\s*(?:https?://[^,\n]+),\s*tag=[^,\n]*,\s*force-policy=([^,\n]+)", t, re.M):
        pass
    for m in re.finditer(r"^\s*(https?://[^,\s]+)[^\n]*?force-policy=([^,\n]+)", t, re.M):
        rules.setdefault(m.group(2).strip(), []).append(stem(m.group(1)))
    sec = re.search(r"^\[Proxy Group\]\s*\n(.*?)(?=^\[)", t, re.M | re.S | re.I)
    if sec:
        for line in sec.group(1).splitlines():
            m = re.match(r"^([^#;=\n][^=\n]*?)\s*=\s*(select|url-test|fallback|load-balance|smart|subnet|ssid)\b(.*)$", line.strip())
            if m: emit(f, m.group(1), rules, [x.strip() for x in m.group(3).split(",")])
    pol = re.search(r"^\[policy\]\s*\n(.*?)(?=^\[)", t, re.M | re.S | re.I)
    if pol:
        for line in pol.group(1).splitlines():
            m = re.match(r"^(static|available|round-robin|url-latency-benchmark|dest-hash|ssid)\s*=\s*([^,\n]+),?(.*)$", line.strip())
            if m: emit(f, m.group(2), rules, [x.strip() for x in m.group(3).split(",")])



def split_emoji(name: str) -> tuple[str | None, str]:
    match = LEADING_EMOJI.match(name.strip())
    return (match.group(1).replace("\uFE0F", ""), match.group(2).strip()) if match else (None, name.strip())


def parse(work: str) -> None:
    global out
    files_dir = os.path.join(work, "files")
    out = open(os.path.join(work, "groups.jsonl"), "w")
    for f in os.listdir(files_dir):
        t = open(os.path.join(files_dir, f), encoding="utf-8", errors="replace").read().replace("\r\n", "\n") + "\n["
        if "custom_proxy_group=" in t:
            parse_ini(f, t)
        if "proxy-groups:" in t:
            parse_yaml(f, t)
        if re.search(r"^\[(Proxy Group|policy)\]", t, re.M | re.I):
            parse_conf(f, t)
    out.close()
    files = collections.defaultdict(set)
    emoji = collections.defaultdict(collections.Counter)
    for line in open(os.path.join(work, "groups.jsonl")):
        record = json.loads(line)
        own, name = split_emoji(record["name"])
        if name and "\t" not in name and "\n" not in name:
            files[name].add(record["file"])
            emoji[name][own] += 1
    names = [name for name in files if len(files[name]) >= 2]
    open(os.path.join(work, "eval_names.txt"), "w").write("\n".join(names))
    json.dump({name: [len(files[name]), emoji[name].most_common(3)] for name in names},
              open(os.path.join(work, "eval_meta.json"), "w"), ensure_ascii=False)
    print(f"{len(names)} names in at least two configs, {sum(len(files[n]) for n in names)} groups")


def report(work: str) -> None:
    meta = json.load(open(os.path.join(work, "eval_meta.json")))
    results = {}
    for line in open(os.path.join(work, "eval_names.txt.out")):
        if "\t" in line:
            name, emoji = line.rstrip("\n").rsplit("\t", 1)
            results[name] = emoji
    total = sum(meta[n][0] for n in results)
    read = sum(meta[n][0] for n in results if results[n] != "-")
    distinct = sum(1 for n in results if results[n] != "-")
    print(f"groups read: {read / total:.1%}; distinct names: {distinct}/{len(results)} = {distinct / len(results):.1%}")
    misses = sorted((n for n in results if results[n] == "-"), key=lambda n: -meta[n][0])
    print("most common misses:", "  ".join(f"{n}({meta[n][0]})" for n in misses[:80]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("step", choices=["search", "download", "parse", "report"])
    parser.add_argument("--work", required=True, help="work directory outside the repository")
    arguments = parser.parse_args()
    os.makedirs(arguments.work, exist_ok=True)
    {"search": search, "download": download, "parse": parse, "report": report}[arguments.step](arguments.work)


if __name__ == "__main__":
    main()
