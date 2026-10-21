//! Literal catalog outcomes independent of either ingestion implementation.
use super::*;
use crate::types::Value;

const TABLE: &str =
    r#"{"columns":[{"name":"x","type":"i64","nullable":true}],"rows":[[7],[null],[7]]}"#;

fn wrapped(table: &str) -> String {
    format!(r#"{{"version":1,"snapshot":"catalog-test","tables":{{"t":{table}}}}}"#)
}

fn denied(input: &[u8]) {
    assert_eq!(
        Catalog::from_bytes(input).err().map(|error| error.code),
        Some(E::Catalog)
    );
}

#[test]
fn reordered_metadata_preserves_exact_typed_duplicate_bag() -> Result<()> {
    let bytes = r#"{
      "snapshot":"reordered",
      "tables":{
        "z":{"rows":[[-9223372036854775808,true,"é\u0000\uD83D\uDE42"],
                     [null,null,null],[9223372036854775807,false,""],
                     [-9223372036854775808,true,"é\u0000\uD83D\uDE42"]],
             "columns":[{"nullable":true,"type":"i64","name":"n"},
                        {"type":"bool","name":"b","nullable":true},
                        {"name":"s","nullable":true,"type":"text"}]},
        "A":{"rows":[],"columns":[{"name":"empty","type":"text","nullable":false}]}
      },
      "\u0076ersion":1
    }"#;
    let catalog = Catalog::from_bytes(bytes.as_bytes())?;
    assert_eq!(catalog.snapshot(), "reordered");
    assert_eq!(
        catalog
            .tables
            .iter()
            .map(|table| table.name.as_str())
            .collect::<Vec<_>>(),
        vec!["A", "z"]
    );
    assert_eq!(catalog.tables[0].data.len(), 0);
    let data = &catalog.tables[1].data;
    let expected = [
        vec![
            Value::I64(i64::MIN),
            Value::Bool(true),
            Value::Text("é\0🙂".into()),
        ],
        vec![
            Value::Null(DataType::I64),
            Value::Null(DataType::Bool),
            Value::Null(DataType::Text),
        ],
        vec![
            Value::I64(i64::MAX),
            Value::Bool(false),
            Value::Text(String::new()),
        ],
        vec![
            Value::I64(i64::MIN),
            Value::Bool(true),
            Value::Text("é\0🙂".into()),
        ],
    ];
    assert_eq!(data.len(), expected.len());
    for (index, row) in expected.iter().enumerate() {
        assert_eq!(&data.row(index)?, row);
    }
    assert_eq!(data.fields(), catalog.tables[1].columns.as_slice());
    Ok(())
}

#[test]
fn decoded_duplicate_keys_and_unknown_fields_always_reject() {
    let base = wrapped(TABLE);
    let mut invalid = vec![
        base.replace(r#""version":1"#, r#""version":1,"\u0076ersion":1"#),
        base.replace(
            r#""snapshot":"catalog-test""#,
            r#""snapshot":"catalog-test","\u0073napshot":"catalog-test""#,
        ),
        base.replace(r#""tables":"#, r#""extra":0,"tables":"#),
        base.replace(r#""columns":"#, r#""extra":0,"columns":"#),
        base.replace(r#""columns":"#, r#""columns":[],"\u0063olumns":"#),
        base.replace(r#""rows":"#, r#""rows":[],"\u0072ows":"#),
        base.replace(r#""name":"x""#, r#""name":"x","\u006eame":"x""#),
        base.replace(r#""type":"i64""#, r#""type":"i64","\u0074ype":"i64""#),
        base.replace(
            r#""nullable":true"#,
            r#""nullable":true,"\u006eullable":true"#,
        ),
        base.replace(r#""name":"x""#, r#""extra":false,"name":"x""#),
    ];
    invalid.push(format!(
        r#"{{"version":1,"snapshot":"s","tables":{{"t":{TABLE},"\u0074":{TABLE}}}}}"#
    ));
    invalid.push(format!(
        r#"{{"version":1,"snapshot":"s","tables":{{"t":{TABLE}}},"\u0074ables":{{}}}}"#
    ));
    for input in invalid {
        assert!(serde_json::from_str::<serde_json::Value>(&input).is_ok());
        denied(input.as_bytes());
    }
}

#[test]
fn scalar_types_nullability_and_row_width_are_closed() {
    for scalar in [
        "true",
        "false",
        "1.0",
        "1e0",
        "-0",
        "9223372036854775808",
        "-9223372036854775809",
        "18446744073709551615",
        "1e400",
        r#""7""#,
        "[]",
        "{}",
        r#"{"x":1,"x":2}"#,
    ] {
        denied(wrapped(&TABLE.replace("[7]", &format!("[{scalar}]"))).as_bytes());
    }
    for rows in [
        "[[]]",
        "[[1,2]]",
        "[null]",
        "[{}]",
        "null",
        "{}",
        "[[1],]",
        "[[1]] false",
    ] {
        let table =
            format!(r#"{{"columns":[{{"name":"x","type":"i64","nullable":true}}],"rows":{rows}}}"#);
        denied(wrapped(&table).as_bytes());
    }
    denied(wrapped(&TABLE.replace(r#""nullable":true"#, r#""nullable":false"#)).as_bytes());
    for version in ["true", "1.0", "1e0", "-0", "null", "4294967297"] {
        denied(
            wrapped(TABLE)
                .replace(r#""version":1"#, &format!(r#""version":{version}"#))
                .as_bytes(),
        );
    }
    for (kind, scalar) in [
        ("bool", "1"),
        ("text", "true"),
        ("text", "7"),
        ("i64", r#""x""#),
    ] {
        let table = format!(
            r#"{{"rows":[[{scalar}]],"columns":[{{"name":"x","type":"{kind}","nullable":true}}]}}"#
        );
        denied(wrapped(&table).as_bytes());
    }
}

#[test]
fn text_cap_counts_decoded_utf8_bytes() -> Result<()> {
    for text in ["é".repeat(2048), "a".repeat(4096)] {
        let table = serde_json::json!({
            "rows":[[text]], "columns":[{"name":"x","type":"text","nullable":false}]
        });
        let catalog = Catalog::from_bytes(wrapped(&table.to_string()).as_bytes())?;
        assert_eq!(catalog.tables[0].data.cell(0, 0)?, Value::Text(text));
    }
    for text in ["é".repeat(2049), "a".repeat(4097)] {
        let table = serde_json::json!({
            "columns":[{"name":"x","type":"text","nullable":false}], "rows":[[text]]
        });
        denied(wrapped(&table.to_string()).as_bytes());
    }
    for bad in [r#""\uD800""#, r#""\uDC00""#, r#""\uD800x""#] {
        let table = format!(
            r#"{{"columns":[{{"name":"x","type":"text","nullable":false}}],"rows":[[{bad}]]}}"#
        );
        denied(wrapped(&table).as_bytes());
    }
    Ok(())
}

#[test]
fn validity_crosses_multiple_words_without_losing_nulls_or_duplicates() -> Result<()> {
    let mut input = Vec::new();
    let mut expected = Vec::new();
    for index in 0..130 {
        match index % 3 {
            0 => {
                input.push(serde_json::json!([null, null, null]));
                expected.push(vec![
                    Value::Null(DataType::I64),
                    Value::Null(DataType::Bool),
                    Value::Null(DataType::Text),
                ]);
            }
            1 => {
                input.push(serde_json::json!([-7, false, "é\0🙂"]));
                expected.push(vec![
                    Value::I64(-7),
                    Value::Bool(false),
                    Value::Text("é\0🙂".into()),
                ]);
            }
            _ => {
                input.push(serde_json::json!([7, true, ""]));
                expected.push(vec![
                    Value::I64(7),
                    Value::Bool(true),
                    Value::Text(String::new()),
                ]);
            }
        }
    }
    let table = serde_json::json!({"rows":input,"columns":[
        {"name":"n","type":"i64","nullable":true},
        {"name":"b","type":"bool","nullable":true},
        {"name":"s","type":"text","nullable":true}
    ]});
    let catalog = Catalog::from_bytes(wrapped(&table.to_string()).as_bytes())?;
    assert_eq!(catalog.tables[0].data.len(), 130);
    for (index, row) in expected.iter().enumerate() {
        assert_eq!(&catalog.tables[0].data.row(index)?, row);
    }
    Ok(())
}

#[test]
fn table_column_identifier_and_snapshot_caps_are_preserved() -> Result<()> {
    let fields = (0..64)
        .map(|index| {
            serde_json::json!({
                "name":format!("c{index}"),"type":"i64","nullable":false
            })
        })
        .collect::<Vec<_>>();
    let table = serde_json::json!({"rows":[vec![7;64]],"columns":fields});
    let catalog = Catalog::from_bytes(wrapped(&table.to_string()).as_bytes())?;
    assert_eq!(catalog.tables[0].data.fields().len(), 64);
    assert_eq!(catalog.tables[0].data.cell(0, 63)?, Value::I64(7));
    let mut extra = table.clone();
    extra["columns"]
        .as_array_mut()
        .ok_or(E::Internal)?
        .push(serde_json::json!({
            "name":"c64","type":"i64","nullable":false
        }));
    extra["rows"][0]
        .as_array_mut()
        .ok_or(E::Internal)?
        .push(7.into());
    denied(wrapped(&extra.to_string()).as_bytes());
    denied(wrapped(r#"{"rows":[],"columns":[]}"#).as_bytes());
    denied(wrapped(&TABLE.replace(r#""name":"x""#, r#""name":"not-valid""#)).as_bytes());
    for label in ["".to_owned(), "a".repeat(129), "é".repeat(65)] {
        let input = wrapped(TABLE).replace(
            r#""catalog-test""#,
            &serde_json::to_string(&label).map_err(|_| E::Internal)?,
        );
        denied(input.as_bytes());
    }
    let exact = wrapped(TABLE).replace("catalog-test", &"a".repeat(128));
    assert_eq!(Catalog::from_bytes(exact.as_bytes())?.snapshot().len(), 128);
    let tables = (0..256)
        .map(|index| format!(r#""t{index}":{TABLE}"#))
        .collect::<Vec<_>>()
        .join(",");
    let input = format!(r#"{{"version":1,"snapshot":"s","tables":{{{tables}}}}}"#);
    assert_eq!(Catalog::from_bytes(input.as_bytes())?.tables.len(), 256);
    let extra = format!(r#"{{"version":1,"snapshot":"s","tables":{{{tables},"extra":{TABLE}}}}}"#);
    denied(extra.as_bytes());
    Ok(())
}

#[test]
fn million_row_cap_is_exact_and_does_not_publish_a_partial_catalog() -> Result<()> {
    let mut rows = String::with_capacity(4_000_010);
    for _ in 0..1_000_000 {
        rows.push_str("[7],");
    }
    rows.pop();
    let table =
        format!(r#"{{"rows":[{rows}],"columns":[{{"name":"x","type":"i64","nullable":false}}]}}"#);
    let catalog = Catalog::from_bytes(wrapped(&table).as_bytes())?;
    assert_eq!(catalog.tables[0].data.len(), 1_000_000);
    assert_eq!(catalog.tables[0].data.cell(0, 0)?, Value::I64(7));
    assert_eq!(catalog.tables[0].data.cell(999_999, 0)?, Value::I64(7));
    rows.push_str(",[7]");
    let excessive =
        format!(r#"{{"columns":[{{"name":"x","type":"i64","nullable":false}}],"rows":[{rows}]}}"#);
    denied(wrapped(&excessive).as_bytes());
    Ok(())
}

#[test]
fn framing_utf8_and_all_metadata_member_orders_are_checked() -> Result<()> {
    for parts in [
        ["\"version\":1", "\"snapshot\":\"s\"", "\"tables\":{}"],
        ["\"snapshot\":\"s\"", "\"version\":1", "\"tables\":{}"],
        ["\"tables\":{}", "\"snapshot\":\"s\"", "\"version\":1"],
        ["\"tables\":{}", "\"version\":1", "\"snapshot\":\"s\""],
        ["\"version\":1", "\"tables\":{}", "\"snapshot\":\"s\""],
        ["\"snapshot\":\"s\"", "\"tables\":{}", "\"version\":1"],
    ] {
        let catalog = Catalog::from_bytes(format!("{{{}}}", parts.join(",")).as_bytes())?;
        assert!(catalog.tables.is_empty());
        assert_eq!(catalog.snapshot(), "s");
    }
    denied(format!("{} {{}}", wrapped(TABLE)).as_bytes());
    denied(wrapped(TABLE).trim_end_matches('}').as_bytes());
    denied(&[b'{', b'"', 0xff, b'"', b':', b'0', b'}']);
    Ok(())
}
