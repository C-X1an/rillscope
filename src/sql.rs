//! Bounded original parser for the documented SELECT dialect; unmatched syntax rejects.
use crate::error::{ErrorCode as E, Result};
use crate::query::{Agg, Expr, Named, NamedAgg, Plan, Query, SortKey, SqlGroupChecks};
use crate::types::{BinaryOp, UnaryOp, Value, identifier};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Number(String),
    Text(String),
    Symbol(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Scalar {
    Plain(Expr),
    Unary(UnaryOp, Box<Scalar>),
    Binary(BinaryOp, Box<Scalar>, Box<Scalar>),
    CountAll,
    Count(Box<Scalar>),
    Sum(Box<Scalar>),
}
struct Item {
    expr: Scalar,
    name: String,
}
fn tokenize(bytes: &[u8]) -> Result<Vec<Token>> {
    if bytes.len() > 65536 {
        return Err(E::Limit.into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| E::Input)?;
    let chars: Vec<_> = text.char_indices().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        let (start, c) = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '-' && chars.get(i + 1).is_some_and(|(_, c)| *c == '-') {
            while i < chars.len() && chars[i].1 != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && chars.get(i + 1).is_some_and(|(_, c)| *c == '*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i].1 == '*' && chars[i + 1].1 == '/') {
                i += 1;
            }
            if i + 1 >= chars.len() {
                return Err(E::Input.into());
            }
            i += 2;
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            i += 1;
            while i < chars.len() && (chars[i].1.is_ascii_alphanumeric() || chars[i].1 == '_') {
                i += 1;
            }
            let end = chars.get(i).map_or(text.len(), |(p, _)| *p);
            let word = text.get(start..end).ok_or(E::Input)?.to_ascii_lowercase();
            if !identifier(&word) {
                return Err(E::Input.into());
            }
            out.push(Token::Word(word));
        } else if c.is_ascii_digit() {
            i += 1;
            while i < chars.len() && chars[i].1.is_ascii_digit() {
                i += 1;
            }
            let end = chars.get(i).map_or(text.len(), |(p, _)| *p);
            out.push(Token::Number(
                text.get(start..end).ok_or(E::Input)?.to_owned(),
            ));
        } else if c == '\'' {
            i += 1;
            let mut value = String::new();
            let mut closed = false;
            while i < chars.len() {
                let c = chars[i].1;
                i += 1;
                if c == '\'' {
                    if chars.get(i).is_some_and(|(_, c)| *c == '\'') {
                        value.push('\'');
                        i += 1;
                    } else {
                        closed = true;
                        break;
                    }
                } else {
                    value.push(c);
                }
                if value.len() > 4096 {
                    return Err(E::Limit.into());
                }
            }
            if !closed {
                return Err(E::Input.into());
            }
            out.push(Token::Text(value));
        } else if "(),.*;+-=<>!".contains(c) {
            let mut symbol = c.to_string();
            i += 1;
            if matches!(c, '<' | '>' | '!')
                && chars
                    .get(i)
                    .is_some_and(|(_, next)| *next == '=' || c == '<' && *next == '>')
            {
                symbol.push(chars[i].1);
                i += 1;
            }
            out.push(Token::Symbol(symbol));
        } else {
            return Err(E::Unsupported.into());
        }
        if out.len() > 8192 {
            return Err(E::Limit.into());
        }
    }
    Ok(out)
}
struct Parser {
    tokens: Vec<Token>,
    cursor: usize,
    nodes: usize,
}
impl Parser {
    fn word(&mut self, text: &str) -> bool {
        if self.tokens.get(self.cursor) == Some(&Token::Word(text.into())) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }
    fn symbol(&mut self, text: &str) -> bool {
        if self.tokens.get(self.cursor) == Some(&Token::Symbol(text.into())) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }
    fn expect_word(&mut self, text: &str) -> Result<()> {
        if self.word(text) {
            Ok(())
        } else {
            Err(E::Unsupported.into())
        }
    }
    fn expect_symbol(&mut self, text: &str) -> Result<()> {
        if self.symbol(text) {
            Ok(())
        } else {
            Err(E::Unsupported.into())
        }
    }
    fn name(&mut self) -> Result<String> {
        if let Some(Token::Word(name)) = self.tokens.get(self.cursor) {
            let name = name.clone();
            self.cursor += 1;
            Ok(name)
        } else {
            Err(E::Unsupported.into())
        }
    }
    fn expression(&mut self, min: u8, depth: usize) -> Result<Scalar> {
        if depth > 32 {
            return Err(E::Limit.into());
        }
        let mut added = 1;
        let mut left = if self.word("not") {
            Scalar::Unary(UnaryOp::Not, Box::new(self.expression(3, depth + 1)?))
        } else if self.symbol("(") {
            added = 0;
            let expr = self.expression(0, depth + 1)?;
            self.expect_symbol(")")?;
            expr
        } else if self.symbol("-") {
            if let Some(Token::Number(n)) = self.tokens.get(self.cursor) {
                let n = format!("-{n}").parse::<i64>().map_err(|_| E::Input)?;
                self.cursor += 1;
                Scalar::Plain(Expr::Lit(Value::I64(n)))
            } else {
                added = 2;
                Scalar::Binary(
                    BinaryOp::Sub,
                    Box::new(Scalar::Plain(Expr::Lit(Value::I64(0)))),
                    Box::new(self.expression(6, depth + 1)?),
                )
            }
        } else {
            let token = self.tokens.get(self.cursor).cloned().ok_or(E::Input)?;
            self.cursor += 1;
            match token {
                Token::Number(n) => {
                    Scalar::Plain(Expr::Lit(Value::I64(n.parse().map_err(|_| E::Input)?)))
                }
                Token::Text(s) => Scalar::Plain(Expr::Lit(Value::Text(s))),
                Token::Word(name) => match name.as_str() {
                    "true" => Scalar::Plain(Expr::Lit(Value::Bool(true))),
                    "false" => Scalar::Plain(Expr::Lit(Value::Bool(false))),
                    "null" => Scalar::Plain(Expr::Null),
                    _ => {
                        if matches!(
                            name.as_str(),
                            "select"
                                | "from"
                                | "where"
                                | "group"
                                | "order"
                                | "by"
                                | "limit"
                                | "as"
                                | "distinct"
                                | "having"
                                | "union"
                                | "all"
                                | "over"
                                | "partition"
                                | "with"
                                | "into"
                                | "window"
                                | "offset"
                                | "fetch"
                                | "top"
                                | "case"
                                | "when"
                                | "then"
                                | "else"
                                | "end"
                                | "cast"
                                | "collate"
                                | "like"
                                | "in"
                                | "exists"
                                | "between"
                                | "outer"
                                | "left"
                                | "right"
                                | "full"
                                | "cross"
                                | "natural"
                                | "lateral"
                                | "values"
                                | "set"
                                | "update"
                                | "returning"
                        ) {
                            return Err(E::Unsupported.into());
                        }
                        if self.symbol("(") {
                            let value = if name == "count" && self.symbol("*") {
                                Scalar::CountAll
                            } else {
                                let arg = self.expression(0, depth + 1)?;
                                match name.as_str() {
                                    "count" => Scalar::Count(Box::new(arg)),
                                    "sum" => Scalar::Sum(Box::new(arg)),
                                    _ => return Err(E::Unsupported.into()),
                                }
                            };
                            self.expect_symbol(")")?;
                            value
                        } else {
                            let name = if self.symbol(".") {
                                format!("{name}.{}", self.name()?)
                            } else {
                                name
                            };
                            Scalar::Plain(Expr::Col(name))
                        }
                    }
                },
                _ => return Err(E::Unsupported.into()),
            }
        };
        left = self.admit_scalar(left, added)?;
        loop {
            if min <= 3 && self.word("is") {
                let not = self.word("not");
                self.expect_word("null")?;
                left = self.admit_scalar(Scalar::Unary(UnaryOp::IsNull, Box::new(left)), 1)?;
                if not {
                    left = self.admit_scalar(Scalar::Unary(UnaryOp::Not, Box::new(left)), 1)?;
                }
                continue;
            }
            let next = match self.tokens.get(self.cursor) {
                Some(Token::Word(s)) => match s.as_str() {
                    "or" => Some((1, BinaryOp::Or)),
                    "and" => Some((2, BinaryOp::And)),
                    _ => None,
                },
                Some(Token::Symbol(s)) => match s.as_str() {
                    "=" => Some((3, BinaryOp::Eq)),
                    "!=" | "<>" => Some((3, BinaryOp::Ne)),
                    "<" => Some((3, BinaryOp::Lt)),
                    "<=" => Some((3, BinaryOp::Le)),
                    ">" => Some((3, BinaryOp::Gt)),
                    ">=" => Some((3, BinaryOp::Ge)),
                    "+" => Some((5, BinaryOp::Add)),
                    "-" => Some((5, BinaryOp::Sub)),
                    _ => None,
                },
                _ => None,
            };
            let Some((precedence, op)) = next else {
                break;
            };
            if precedence < min {
                break;
            }
            self.cursor += 1;
            let right = self.expression(precedence + 1, depth + 1)?;
            left = self.admit_scalar(Scalar::Binary(op, Box::new(left), Box::new(right)), 1)?;
        }
        Ok(left)
    }
    fn admit_scalar(&mut self, expr: Scalar, added: usize) -> Result<Scalar> {
        self.nodes = self.nodes.checked_add(added).ok_or(E::Limit)?;
        if self.nodes > 256 {
            return Err(E::Limit.into());
        }
        fn check(expr: &Scalar, depth: usize) -> Result<()> {
            if depth > 32 {
                return Err(E::Limit.into());
            }
            match expr {
                Scalar::Unary(_, a) | Scalar::Count(a) | Scalar::Sum(a) => check(a, depth + 1),
                Scalar::Binary(_, a, b) => {
                    check(a, depth + 1)?;
                    check(b, depth + 1)
                }
                _ => Ok(()),
            }
        }
        check(&expr, 1)?;
        Ok(expr)
    }
    fn alias(&mut self, default: String) -> Result<String> {
        if self.word("as") {
            return self.name();
        }
        if let Some(Token::Word(word)) = self.tokens.get(self.cursor)
            && !matches!(
                word.as_str(),
                "from"
                    | "inner"
                    | "join"
                    | "on"
                    | "where"
                    | "group"
                    | "order"
                    | "limit"
                    | "asc"
                    | "desc"
                    | "nulls"
                    | "having"
                    | "union"
                    | "left"
                    | "right"
                    | "full"
                    | "cross"
            )
        {
            return self.name();
        }
        Ok(default)
    }
    fn table(&mut self) -> Result<(Plan, String)> {
        let table = self.name()?;
        let alias = self.alias(table.clone())?;
        Ok((
            Plan::Scan {
                table,
                alias: alias.clone(),
            },
            alias,
        ))
    }
    fn list(&mut self) -> Result<Vec<Scalar>> {
        let mut out = vec![self.expression(0, 1)?];
        while self.symbol(",") {
            if out.len() >= 64 {
                return Err(E::Limit.into());
            }
            out.push(self.expression(0, 1)?);
        }
        Ok(out)
    }
    fn select(&mut self) -> Result<Query> {
        self.expect_word("select")?;
        let mut items = Vec::new();
        let mut names = BTreeSet::new();
        loop {
            if items.len() >= 64 {
                return Err(E::Limit.into());
            }
            let expr = self.expression(0, 1)?;
            let default = match &expr {
                Scalar::Plain(Expr::Col(name)) => {
                    name.rsplit('.').next().ok_or(E::Input)?.to_owned()
                }
                _ => format!("_expr{}", items.len()),
            };
            let name = self.alias(default)?;
            if !names.insert(name.clone()) {
                return Err(E::Input.into());
            }
            items.push(Item { expr, name });
            if !self.symbol(",") {
                break;
            }
        }
        self.expect_word("from")?;
        let (mut input, left_alias) = self.table()?;
        if self.word("inner") {
            self.expect_word("join")?;
            let (right, right_alias) = self.table()?;
            self.expect_word("on")?;
            let on = join_keys(&self.expression(0, 1)?, &left_alias, &right_alias)?;
            input = Plan::SqlJoin {
                left: Box::new(input),
                right: Box::new(right),
                on,
            };
        } else if self.word("join") {
            let (right, right_alias) = self.table()?;
            self.expect_word("on")?;
            let on = join_keys(&self.expression(0, 1)?, &left_alias, &right_alias)?;
            input = Plan::SqlJoin {
                left: Box::new(input),
                right: Box::new(right),
                on,
            };
        }
        if self.word("where") {
            input = Plan::Filter {
                input: Box::new(input),
                predicate: plain(&self.expression(0, 1)?)?,
            };
        }
        let groups = if self.word("group") {
            self.expect_word("by")?;
            let groups = self.list()?;
            if groups.len() > 16 {
                return Err(E::Limit.into());
            }
            groups
        } else {
            vec![]
        };
        let aggregated = !groups.is_empty() || items.iter().any(|i| has_aggregate(&i.expr));
        let mut group_checks = SqlGroupChecks {
            input: input.clone(),
            columns: Vec::new(),
            matches: Vec::new(),
            invalid_group: false,
        };
        if aggregated {
            for expr in items.iter().map(|i| &i.expr).chain(groups.iter()) {
                scalar_columns(expr, &mut group_checks.columns);
            }
        }
        let mut aggregates = Vec::new();
        let mut columns = Vec::new();
        for item in items {
            let expr = if aggregated {
                match lower(
                    &item.expr,
                    &groups,
                    &mut aggregates,
                    &mut group_checks.matches,
                ) {
                    Ok(expr) => expr,
                    Err(error) if error.code == E::Bind => {
                        group_checks.invalid_group = true;
                        Expr::Null
                    }
                    Err(error) => return Err(error),
                }
            } else {
                plain(&item.expr)?
            };
            columns.push(Named {
                name: item.name,
                expr,
            });
        }
        if aggregated {
            let keys = groups
                .iter()
                .enumerate()
                .map(|(i, g)| {
                    Ok(Named {
                        name: format!("_key{i}"),
                        expr: plain(g)?,
                    })
                })
                .collect::<Result<_>>()?;
            input = Plan::Aggregate {
                input: Box::new(input),
                keys,
                aggregates,
            };
        }
        input = Plan::Project {
            input: Box::new(input),
            columns,
        };
        if self.word("order") {
            self.expect_word("by")?;
            let mut keys = Vec::new();
            loop {
                if keys.len() >= 64 {
                    return Err(E::Limit.into());
                }
                let expr = plain(&self.expression(0, 1)?)?;
                if !matches!(&expr, Expr::Col(name) if !name.contains('.')) {
                    return Err(E::Unsupported.into());
                }
                let descending = self.word("desc");
                if !descending {
                    self.word("asc");
                }
                let nulls_first = if self.word("nulls") {
                    if self.word("first") {
                        true
                    } else {
                        self.expect_word("last")?;
                        false
                    }
                } else {
                    false
                };
                keys.push(SortKey {
                    expr,
                    descending,
                    nulls_first,
                });
                if !self.symbol(",") {
                    break;
                }
            }
            input = Plan::Sort {
                input: Box::new(input),
                keys,
            };
        }
        if self.word("limit") {
            let Some(Token::Number(value)) = self.tokens.get(self.cursor) else {
                return Err(E::Unsupported.into());
            };
            let count = value.parse::<usize>().map_err(|_| E::Input)?;
            if count > 10000 {
                return Err(E::Limit.into());
            }
            self.cursor += 1;
            input = Plan::Limit {
                input: Box::new(input),
                count,
            };
        }
        self.symbol(";");
        if self.cursor != self.tokens.len() {
            return Err(E::Unsupported.into());
        }
        let mut query = Query::from_plan(input)?;
        if aggregated {
            query.sql_group_checks = Some(group_checks);
        }
        Ok(query)
    }
}
fn plain(expr: &Scalar) -> Result<Expr> {
    match expr {
        Scalar::Plain(e) => Ok(e.clone()),
        Scalar::Unary(op, a) => Ok(Expr::Unary(*op, Box::new(plain(a)?))),
        Scalar::Binary(op, a, b) => Ok(Expr::Binary(*op, Box::new(plain(a)?), Box::new(plain(b)?))),
        _ => Err(E::Unsupported.into()),
    }
}
fn has_aggregate(expr: &Scalar) -> bool {
    match expr {
        Scalar::CountAll | Scalar::Count(_) | Scalar::Sum(_) => true,
        Scalar::Unary(_, a) => has_aggregate(a),
        Scalar::Binary(_, a, b) => has_aggregate(a) || has_aggregate(b),
        _ => false,
    }
}
fn has_column(expr: &Expr) -> bool {
    match expr {
        Expr::Col(_) => true,
        Expr::Unary(_, a) => has_column(a),
        Expr::Binary(_, a, b) => has_column(a) || has_column(b),
        _ => false,
    }
}
fn scalar_columns(expr: &Scalar, out: &mut Vec<Expr>) {
    match expr {
        Scalar::Plain(Expr::Col(name)) => out.push(Expr::Col(name.clone())),
        Scalar::Unary(_, a) | Scalar::Count(a) | Scalar::Sum(a) => scalar_columns(a, out),
        Scalar::Binary(_, a, b) => {
            scalar_columns(a, out);
            scalar_columns(b, out);
        }
        _ => {}
    }
}
fn same_group_shape(a: &Scalar, b: &Scalar) -> bool {
    match (a, b) {
        (Scalar::Plain(Expr::Col(a)), Scalar::Plain(Expr::Col(b))) => {
            a == b
                || ((!a.contains('.') || !b.contains('.'))
                    && a.rsplit('.').next() == b.rsplit('.').next())
        }
        (Scalar::Unary(aop, a), Scalar::Unary(bop, b)) => aop == bop && same_group_shape(a, b),
        (Scalar::Binary(aop, a, aa), Scalar::Binary(bop, b, bb)) => {
            aop == bop && same_group_shape(a, b) && same_group_shape(aa, bb)
        }
        _ => a == b,
    }
}
fn lower(
    expr: &Scalar,
    groups: &[Scalar],
    aggregates: &mut Vec<NamedAgg>,
    matches: &mut Vec<(Expr, Expr)>,
) -> Result<Expr> {
    if let Some(i) = groups.iter().position(|g| same_group_shape(g, expr)) {
        if groups[i] != *expr {
            matches.push((plain(expr)?, plain(&groups[i])?));
        }
        return Ok(Expr::Col(format!("_key{i}")));
    }
    match expr {
        Scalar::CountAll | Scalar::Count(_) | Scalar::Sum(_) => {
            let name = format!("_agg{}", aggregates.len());
            let agg = match expr {
                Scalar::CountAll => Agg::CountAll,
                Scalar::Count(a) => Agg::Count(plain(a)?),
                Scalar::Sum(a) => Agg::Sum(plain(a)?),
                _ => return Err(E::Internal.into()),
            };
            if aggregates.len() >= 64 {
                return Err(E::Limit.into());
            }
            aggregates.push(NamedAgg {
                name: name.clone(),
                agg,
            });
            Ok(Expr::Col(name))
        }
        Scalar::Unary(op, a) => Ok(Expr::Unary(
            *op,
            Box::new(lower(a, groups, aggregates, matches)?),
        )),
        Scalar::Binary(op, a, b) => Ok(Expr::Binary(
            *op,
            Box::new(lower(a, groups, aggregates, matches)?),
            Box::new(lower(b, groups, aggregates, matches)?),
        )),
        Scalar::Plain(e) => {
            if has_column(e) {
                Err(E::Bind.into())
            } else {
                Ok(e.clone())
            }
        }
    }
}
fn join_keys(expr: &Scalar, left: &str, right: &str) -> Result<Vec<(Expr, Expr)>> {
    fn add(expr: &Scalar, left: &str, right: &str, out: &mut Vec<(Expr, Expr)>) -> Result<()> {
        match expr {
            Scalar::Binary(BinaryOp::And, a, b) => {
                add(a, left, right, out)?;
                add(b, left, right, out)?;
            }
            Scalar::Binary(BinaryOp::Eq, a, b) => {
                let (a, b) = (plain(a)?, plain(b)?);
                let (Expr::Col(an), Expr::Col(bn)) = (&a, &b) else {
                    return Err(E::Unsupported.into());
                };
                let _ = (an, bn, left, right);
                out.push((a, b));
            }
            _ => return Err(E::Unsupported.into()),
        }
        Ok(())
    }
    let mut out = Vec::new();
    add(expr, left, right, &mut out)?;
    if out.is_empty() || out.len() > 64 {
        return Err(E::Unsupported.into());
    }
    Ok(out)
}
impl Query {
    pub fn from_sql(bytes: &[u8]) -> Result<Self> {
        Parser {
            tokens: tokenize(bytes)?,
            cursor: 0,
            nodes: 0,
        }
        .select()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_sql_effects_and_multiple_statements_reject() {
        for input in [
            "COPY sales TO 'x'",
            "ATTACH 'x'",
            "CREATE TABLE t (id int)",
            "UPDATE sales SET id=1",
            "SELECT read_csv('x') FROM sales",
            "SELECT id FROM sales; SELECT id FROM sales",
            "SELECT * FROM sales",
            "SELECT id FROM sales LEFT JOIN sales b ON sales.id=b.id",
            "SELECT DISTINCT id FROM sales",
        ] {
            assert!(Query::from_sql(input.as_bytes()).is_err(), "{input}");
        }
    }
    #[test]
    fn supported_query_lowers_exactly() -> Result<()> {
        let sql = Query::from_sql(
            b"SELECT id, amount FROM sales WHERE amount > 10 ORDER BY id LIMIT 10",
        )?;
        let json=Query::from_json(br#"{"version":1,"plan":{"op":"limit","count":10,"input":{"op":"sort","keys":[{"expr":{"col":"id"},"direction":"asc","nulls":"last"}],"input":{"op":"project","columns":[{"name":"id","expr":{"col":"id"}},{"name":"amount","expr":{"col":"amount"}}],"input":{"op":"filter","predicate":{"op":"gt","left":{"col":"amount"},"right":{"lit":10}},"input":{"op":"scan","table":"sales","alias":"sales"}}}}}}"#)?;
        assert_eq!(sql.plan, json.plan);
        Ok(())
    }
}
