"""Executable semantic reference. Not the Rust product or a security boundary.

All binding happens before execution, including on empty inputs. This deliberately
simple row interpreter is for independent expected results, not performance claims.
"""
from __future__ import annotations

import copy
import functools
import json
import re
from dataclasses import dataclass
from typing import Any

MIN_I64, MAX_I64 = -(2**63), 2**63 - 1
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
TYPES = {"i64", "bool", "text"}


class QueryError(Exception):
    def __init__(self, code: str, phase: str, message: str):
        super().__init__(message)
        self.code, self.phase, self.message = code, phase, message


def fail(code: str, phase: str, message: str) -> Any:
    raise QueryError(code, phase, message)


def fields(value: Any, expected: set[str], phase: str = "decode") -> None:
    if not isinstance(value, dict) or set(value) != expected:
        fail("E_INPUT", phase, "object has missing or unsupported fields")


def identifier(value: Any) -> str:
    if not isinstance(value, str) or not IDENT.fullmatch(value):
        fail("E_INPUT", "decode", "invalid identifier")
    return value


def integer(value: Any, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        fail("E_INPUT", "decode", "integer outside allowed range")
    return value


def value_type(value: Any) -> str:
    if type(value) is bool:
        return "bool"
    if type(value) is int and MIN_I64 <= value <= MAX_I64:
        return "i64"
    if isinstance(value, str):
        try:
            size = len(value.encode("utf-8"))
        except UnicodeError:
            fail("E_INPUT", "decode", "invalid Unicode value")
        if size <= 4096:
            return "text"
    fail("E_TYPE", "bind", "unsupported value type or size")


def checked(value: int) -> int:
    if not MIN_I64 <= value <= MAX_I64:
        fail("E_OVERFLOW", "execute", "integer overflow")
    return value


def strict_loads(text: str, limit: int = 65536) -> Any:
    try:
        if len(text.encode("utf-8")) > limit:
            fail("E_LIMIT", "decode", "input byte limit exceeded")
    except UnicodeError:
        fail("E_INPUT", "decode", "invalid Unicode input")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out = {}
        for key, value in items:
            if key in out:
                fail("E_INPUT", "decode", "duplicate object key")
            out[key] = value
        return out

    def nonfinite(_: str) -> Any:
        fail("E_INPUT", "decode", "non-finite numeric literal")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)
    except (ValueError, RecursionError):
        fail("E_INPUT", "decode", "invalid JSON")


@dataclass(frozen=True)
class Col:
    name: str
    dtype: str
    nullable: bool


@dataclass
class Relation:
    schema: tuple[Col, ...]
    rows: list[tuple[Any, ...]]


@dataclass
class Limits:
    work: int = 10_000_000
    output_rows: int = 10_000
    output_bytes: int = 1_048_576
    intermediate_rows: int = 100_000


class Reference:
    def __init__(self, catalog: dict[str, Any], context: dict[str, Any],
                 limits: Limits | None = None):
        self.catalog, self.context = copy.deepcopy(catalog), copy.deepcopy(context)
        self.limits = limits or Limits()
        self.work = 0
        self.scans = 0
        self.schemas: dict[int, tuple[Col, ...]] = {}
        self.hidden: set[str] = set()
        self.aliases: set[str] = set()
        self._validate_catalog()

    def _validate_catalog(self) -> None:
        fields(self.catalog, {"version", "snapshot", "tables"}, "catalog")
        fields(self.context, {"version", "policy_revision", "tenant", "tables"}, "context")
        for obj in (self.catalog, self.context):
            if type(obj["version"]) is not int or obj["version"] != 1:
                fail("E_INPUT", "catalog", "unsupported schema version")
            if not isinstance(obj["tables"], dict):
                fail("E_CATALOG", "catalog", "tables must be an object")
        if not isinstance(self.catalog["snapshot"], str) or not self.catalog["snapshot"]:
            fail("E_CATALOG", "catalog", "snapshot identity required")
        if not isinstance(self.context["policy_revision"], str) or not self.context["policy_revision"]:
            fail("E_CONTEXT", "context", "policy revision required")
        if value_type(self.context["tenant"]) != "text":
            fail("E_CONTEXT", "context", "tenant must be text")
        for name, table in self.catalog["tables"].items():
            identifier(name)
            fields(table, {"columns", "rows"}, "catalog")
            if not isinstance(table["columns"], list) or not 1 <= len(table["columns"]) <= 64:
                fail("E_CATALOG", "catalog", "invalid catalog schema")
            names = []
            for col in table["columns"]:
                fields(col, {"name", "type", "nullable"}, "catalog")
                names.append(identifier(col["name"]))
                if not isinstance(col["type"], str) or col["type"] not in TYPES or type(col["nullable"]) is not bool:
                    fail("E_CATALOG", "catalog", "invalid column type")
            if len(set(names)) != len(names):
                fail("E_CATALOG", "catalog", "duplicate catalog column")
            if not isinstance(table["rows"], list) or len(table["rows"]) > 1_000_000:
                fail("E_CATALOG", "catalog", "invalid catalog rows")
            for row in table["rows"]:
                if not isinstance(row, list) or len(row) != len(names):
                    fail("E_CATALOG", "catalog", "row width mismatch")
                for col, val in zip(table["columns"], row):
                    if val is None:
                        if not col["nullable"]:
                            fail("E_CATALOG", "catalog", "null in nonnullable column")
                    elif value_type(val) != col["type"]:
                        fail("E_CATALOG", "catalog", "catalog value type mismatch")
        for name, grant in self.context["tables"].items():
            if name not in self.catalog["tables"]:
                fail("E_CONTEXT", "context", "unknown granted table")
            fields(grant, {"tenant_column", "columns"}, "context")
            cols = {c["name"]: c for c in self.catalog["tables"][name]["columns"]}
            tc = cols.get(identifier(grant["tenant_column"]))
            if tc is None or tc["type"] != "text" or tc["nullable"]:
                fail("E_CONTEXT", "context", "tenant column must be nonnullable text")
            allowed = grant["columns"]
            if not isinstance(allowed, list) or not all(isinstance(x, str) for x in allowed):
                fail("E_CONTEXT", "context", "invalid allowed columns")
            if len(set(allowed)) != len(allowed) or any(x not in cols for x in allowed):
                fail("E_CONTEXT", "context", "invalid granted column")

    def charge(self, amount: int = 1) -> None:
        self.work += amount
        if self.work > self.limits.work:
            fail("E_BUDGET", "execute", "work budget exceeded")

    def bounded_append(self, rows: list, row: tuple) -> None:
        self.charge(len(row) + 1)
        if len(rows) >= self.limits.intermediate_rows:
            fail("E_BUDGET", "execute", "reference intermediate row bound exceeded")
        rows.append(row)

    def resolve(self, name: Any, schema: tuple[Col, ...]) -> int:
        if not isinstance(name, str) or len(name.split(".")) > 2:
            fail("E_BIND", "bind", "invalid column reference")
        for part in name.split("."):
            identifier(part)
        matches = [i for i, c in enumerate(schema) if c.name == name or (
            "." not in name and c.name.rsplit(".", 1)[-1] == name)]
        if len(matches) > 1:
            fail("E_BIND", "bind", "ambiguous column reference")
        if not matches:
            code = "E_FORBIDDEN" if name in self.hidden else "E_BIND"
            fail(code, "bind", "column is not available in this scope")
        return matches[0]

    def infer(self, expr: Any, schema: tuple[Col, ...]) -> tuple[str, bool]:
        if not isinstance(expr, dict):
            fail("E_INPUT", "decode", "expression must be an object")
        if "col" in expr:
            fields(expr, {"col"})
            c = schema[self.resolve(expr["col"], schema)]
            return c.dtype, c.nullable
        if "lit" in expr:
            if expr["lit"] is None:
                fields(expr, {"lit", "type"})
                if not isinstance(expr["type"], str) or expr["type"] not in TYPES:
                    fail("E_TYPE", "bind", "null requires explicit type")
                return expr["type"], True
            fields(expr, {"lit"})
            return value_type(expr["lit"]), False
        op = expr.get("op")
        if op in ("not", "is_null"):
            fields(expr, {"op", "expr"})
            dtype, nullable = self.infer(expr["expr"], schema)
            if op == "not" and dtype != "bool":
                fail("E_TYPE", "bind", "boolean operand required")
            return "bool", nullable if op == "not" else False
        if op not in ("eq", "ne", "lt", "le", "gt", "ge", "and", "or", "add", "sub"):
            fail("E_UNSUPPORTED", "decode", "unsupported expression")
        fields(expr, {"op", "left", "right"})
        lt, ln = self.infer(expr["left"], schema)
        rt, rn = self.infer(expr["right"], schema)
        if lt != rt or (op in ("and", "or") and lt != "bool") or (
                op in ("add", "sub") and lt != "i64"):
            fail("E_TYPE", "bind", "incompatible expression types")
        return ("i64" if op in ("add", "sub") else "bool"), ln or rn

    def bind(self, node: Any) -> tuple[Col, ...]:
        if not isinstance(node, dict):
            fail("E_INPUT", "decode", "plan node must be an object")
        op = node.get("op")
        if op == "scan":
            fields(node, {"op", "table", "alias"})
            name, alias = identifier(node["table"]), identifier(node["alias"])
            if alias in self.aliases:
                fail("E_BIND", "bind", "duplicate scan alias")
            self.aliases.add(alias)
            self.scans += 1
            if self.scans > 4:
                fail("E_LIMIT", "bind", "too many scans")
            if name not in self.context["tables"]:
                fail("E_FORBIDDEN", "bind", "table is not available")
            grant = self.context["tables"][name]
            cols = self.catalog["tables"][name]["columns"]
            schema = tuple(Col(alias + "." + c["name"], c["type"], c["nullable"])
                           for c in cols if c["name"] in grant["columns"])
            for c in cols:
                if c["name"] not in grant["columns"]:
                    self.hidden.update({c["name"], alias + "." + c["name"]})
        elif op == "join":
            fields(node, {"op", "left", "right", "on"})
            left, right = self.bind(node["left"]), self.bind(node["right"])
            if not isinstance(node["on"], list) or not node["on"]:
                fail("E_INPUT", "bind", "join keys required")
            for pair in node["on"]:
                fields(pair, {"left", "right"})
                fields(pair["left"], {"col"}); fields(pair["right"], {"col"})
                if self.infer(pair["left"], left)[0] != self.infer(pair["right"], right)[0]:
                    fail("E_TYPE", "bind", "join key types differ")
            schema = left + right
        elif op in ("filter", "project", "aggregate", "sort", "limit"):
            expected = {"filter": {"op", "input", "predicate"},
                        "project": {"op", "input", "columns"},
                        "aggregate": {"op", "input", "keys", "aggregates"},
                        "sort": {"op", "input", "keys"},
                        "limit": {"op", "input", "count"}}[op]
            fields(node, expected)
            source = self.bind(node["input"])
            schema = source
            if op == "filter":
                if self.infer(node["predicate"], source)[0] != "bool":
                    fail("E_TYPE", "bind", "filter must be boolean")
            elif op == "limit":
                integer(node["count"], 0, 10000)
            elif op == "sort":
                if not isinstance(node["keys"], list) or not node["keys"]:
                    fail("E_INPUT", "bind", "sort keys required")
                for key in node["keys"]:
                    fields(key, {"expr", "direction", "nulls"})
                    self.infer(key["expr"], source)
                    if key["direction"] not in ("asc", "desc") or key["nulls"] not in ("first", "last"):
                        fail("E_INPUT", "bind", "invalid sort direction or null ordering")
            else:
                items = node["columns"] if op == "project" else node["keys"]
                if not isinstance(items, list) or (op == "project" and not items):
                    fail("E_INPUT", "bind", "projection/key list invalid")
                if op == "aggregate" and len(items) > 16:
                    fail("E_LIMIT", "bind", "too many grouping keys")
                output = []
                for item in items:
                    fields(item, {"name", "expr"})
                    dt, nu = self.infer(item["expr"], source)
                    output.append(Col(identifier(item["name"]), dt, nu))
                if op == "aggregate":
                    if not isinstance(node["aggregates"], list) or not node["aggregates"]:
                        fail("E_INPUT", "bind", "aggregate list required")
                    for agg in node["aggregates"]:
                        kind = agg.get("kind") if isinstance(agg, dict) else None
                        if kind not in ("count_all", "count", "sum"):
                            fail("E_UNSUPPORTED", "bind", "unsupported aggregate")
                        fields(agg, {"name", "kind"} if kind == "count_all" else {"name", "kind", "expr"})
                        if kind != "count_all":
                            dt, _ = self.infer(agg["expr"], source)
                            if kind == "sum" and dt != "i64":
                                fail("E_TYPE", "bind", "sum requires i64")
                        output.append(Col(identifier(agg["name"]), "i64", kind == "sum"))
                if len({c.name for c in output}) != len(output):
                    fail("E_BIND", "bind", "duplicate output name")
                schema = tuple(output)
        else:
            fail("E_UNSUPPORTED", "decode", "unsupported relational operator")
        if len(schema) > 64:
            fail("E_LIMIT", "bind", "too many output columns")
        self.schemas[id(node)] = schema
        return schema

    def expr(self, e: dict, schema: tuple[Col, ...], row: tuple) -> Any:
        self.charge()
        if "col" in e:
            return row[self.resolve(e["col"], schema)]
        if "lit" in e:
            return e["lit"]
        op = e["op"]
        if op in ("not", "is_null"):
            value = self.expr(e["expr"], schema, row)
            return value is None if op == "is_null" else (None if value is None else not value)
        a, b = self.expr(e["left"], schema, row), self.expr(e["right"], schema, row)
        if op == "and":
            return False if a is False or b is False else (None if a is None or b is None else True)
        if op == "or":
            return True if a is True or b is True else (None if a is None or b is None else False)
        if a is None or b is None:
            return None
        if op == "add": return checked(a + b)
        if op == "sub": return checked(a - b)
        if op == "eq": return a == b
        if op == "ne": return a != b
        if op == "lt": return a < b
        if op == "le": return a <= b
        if op == "gt": return a > b
        return a >= b

    def execute(self, node: dict) -> Relation:
        op, schema = node["op"], self.schemas[id(node)]
        rows: list[tuple] = []
        if op == "scan":
            table, grant = self.catalog["tables"][node["table"]], self.context["tables"][node["table"]]
            names = [c["name"] for c in table["columns"]]
            tenant_idx = names.index(grant["tenant_column"])
            visible = [i for i, n in enumerate(names) if n in grant["columns"]]
            for raw in table["rows"]:
                self.charge()
                if raw[tenant_idx] == self.context["tenant"]:
                    self.bounded_append(rows, tuple(raw[i] for i in visible))
        elif op == "join":
            left, right = self.execute(node["left"]), self.execute(node["right"])
            for a in left.rows:
                for b in right.rows:
                    self.charge()
                    matches = True
                    for pair in node["on"]:
                        x, y = self.expr(pair["left"], left.schema, a), self.expr(pair["right"], right.schema, b)
                        if x is None or y is None or x != y:
                            matches = False
                    if matches:
                        self.bounded_append(rows, a + b)
        else:
            source = self.execute(node["input"])
            if op == "filter":
                for row in source.rows:
                    if self.expr(node["predicate"], source.schema, row) is True:
                        self.bounded_append(rows, row)
            elif op == "project":
                for row in source.rows:
                    self.bounded_append(rows, tuple(self.expr(c["expr"], source.schema, row) for c in node["columns"]))
            elif op == "limit":
                rows = source.rows[:node["count"]]
            elif op == "sort":
                # Precompute expressions once: comparisons do not change error ordering.
                decorated = [(tuple(self.expr(k["expr"], source.schema, r) for k in node["keys"]), r) for r in source.rows]
                def compare(a: tuple, b: tuple) -> int:
                    self.charge()
                    for x, y, key in zip(a[0], b[0], node["keys"]):
                        if x is None or y is None:
                            comp = 0 if x is y else (-1 if x is None else 1) * (1 if key["nulls"] == "first" else -1)
                        else:
                            comp = (x > y) - (x < y)
                            if key["direction"] == "desc": comp = -comp
                        if comp: return comp
                    return 0
                rows = [r for _, r in sorted(decorated, key=functools.cmp_to_key(compare))]
            elif op == "aggregate":
                groups: dict[tuple, list[tuple]] = {}
                if not node["keys"]: groups[()] = []
                for row in source.rows:
                    key = tuple(self.expr(k["expr"], source.schema, row) for k in node["keys"])
                    self.charge()
                    groups.setdefault(key, []).append(row)
                for key, members in groups.items():
                    vals = []
                    for agg in node["aggregates"]:
                        if agg["kind"] == "count_all": vals.append(checked(len(members)))
                        else:
                            nonnull = [self.expr(agg["expr"], source.schema, r) for r in members]
                            nonnull = [v for v in nonnull if v is not None]
                            if agg["kind"] == "count": vals.append(checked(len(nonnull)))
                            else:
                                total = None
                                for val in nonnull: total = checked((total or 0) + val)
                                vals.append(total)
                    self.bounded_append(rows, key + tuple(vals))
        return Relation(schema, rows)

    def run(self, query: dict) -> dict:
        self.work, self.scans = 0, 0
        self.schemas.clear(); self.aliases.clear(); self.hidden.clear()
        fields(query, {"version", "plan"})
        if type(query["version"]) is not int or query["version"] != 1:
            fail("E_UNSUPPORTED", "decode", "unsupported query version")
        count = 0
        def walk(x: Any, depth: int) -> None:
            nonlocal count
            count += 1
            if count > 256 or depth > 32:
                fail("E_LIMIT", "decode", "query structural limit exceeded")
            if isinstance(x, dict):
                for val in x.values(): walk(val, depth + 1)
            elif isinstance(x, list):
                for val in x: walk(val, depth + 1)
        walk(query, 0)
        self.bind(query["plan"])
        result = self.execute(query["plan"])
        if len(result.rows) > self.limits.output_rows:
            fail("E_OUTPUT_LIMIT", "collect", "result row limit exceeded")
        out = {"version": 1, "status": "ok", "implementation": "python-reference",
               "schema": [{"name": c.name, "type": c.dtype, "nullable": c.nullable} for c in result.schema],
               "rows": [list(r) for r in result.rows], "metrics": {"work_units": self.work}}
        if len(json.dumps(out, ensure_ascii=False).encode("utf-8")) > self.limits.output_bytes:
            fail("E_OUTPUT_LIMIT", "collect", "result byte limit exceeded")
        return out


def evaluate(catalog: dict, context: dict, query: dict, limits: Limits | None = None) -> dict:
    try:
        return Reference(catalog, context, limits).run(query)
    except QueryError as error:
        return {"version": 1, "status": "error", "implementation": "python-reference",
                "error": {"code": error.code, "phase": error.phase, "message": error.message}}
