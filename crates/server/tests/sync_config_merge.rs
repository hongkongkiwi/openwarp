use openwarp_server::integrations::{path_selected, validate_sync_config};
use serde_json::{json, Value};

fn reject_all(kind: &str, configs: Vec<Value>) {
    let accepted: Vec<_> = configs.into_iter().filter(|config| validate_sync_config(kind, config).is_ok()).collect();
    assert!(accepted.is_empty(), "{} accepted invalid sync configurations: {:?}", kind, accepted);
}

#[test]
fn absent_rejects_explicit_nonstring_values() {
    reject_all("azure_key_vault", vec![json!(true), json!(false), json!(null), json!(1), json!([]), json!({})]
        .into_iter().map(|value| json!({"absent": value})).collect());
}

#[test]
fn absent_preserves_defaults_keep_and_capability_boundaries() {
    for kind in ["azure_key_vault", "aws_secrets_manager", "gcp_secret_manager", "webhook"] {
        for config in [json!({}), json!({"absent": ""}), json!({"absent": "keep"})] {
            assert!(validate_sync_config(kind, &config).is_ok(), "{} should accept {}", kind, config);
        }
    }
    assert!(validate_sync_config("azure_key_vault", &json!({"absent": "disable"})).is_ok());
    for kind in ["aws_secrets_manager", "gcp_secret_manager", "webhook"] {
        reject_all(kind, vec![json!({"absent": "disable"})]);
    }
    reject_all("azure_key_vault", vec![json!({"absent": "delete"}), json!({"absent": "disable", "mode": "mirror"})]);
}

#[test]
fn static_tags_reject_empty_and_whitespace_keys() {
    for kind in ["aws_secrets_manager", "azure_key_vault", "gcp_secret_manager"] {
        reject_all(kind, ["", " ", "\t\n"].into_iter().map(|key| {
            let mut tags = serde_json::Map::new(); tags.insert(key.into(), json!("value"));
            json!({"tags": tags})
        }).collect());
    }
}

#[test]
fn static_tags_preserve_empty_values_and_provider_capabilities() {
    for kind in ["aws_secrets_manager", "azure_key_vault", "gcp_secret_manager"] {
        for config in [json!({"tags": {}}), json!({"tags": {"owner": "platform", "bare": ""}})] {
            assert!(validate_sync_config(kind, &config).is_ok(), "{} should accept {}", kind, config);
        }
        reject_all(kind, vec![json!({"tags": {"owner": 1}}), json!({"tags": []})]);
    }
    reject_all("webhook", vec![json!({"tags": {"owner": "platform"}})]);
}

#[test]
fn vercel_target_rejects_unknown_contexts_and_invalid_types() {
    reject_all("vercel", vec![json!("staging"), json!("Production"), json!(["production", "staging"]), json!(["all"]), json!([""]),
        json!([]), json!(["preview", 1]), json!(true), json!(null), json!(1), json!({})]
        .into_iter().map(|value| json!({"target": value})).collect());
}

#[test]
fn vercel_type_rejects_unknown_and_nonstring_values() {
    reject_all("vercel", vec![json!("secret"), json!(true), json!(false), json!(null), json!(1), json!([]), json!({})]
        .into_iter().map(|value| json!({"type": value})).collect());
}

#[test]
fn vercel_preserves_supported_targets_types_and_defaults() {
    let targets = [json!({}), json!({"target": ""}), json!({"target": "all"}), json!({"target": "production"}),
        json!({"target": "preview"}), json!({"target": "development"}), json!({"target": ["preview"]}),
        json!({"target": ["production", "preview", "development"]})];
    for target in targets {
        assert!(validate_sync_config("vercel", &target).is_ok(), "default type should accept {}", target);
        for secret_type in ["", "plain", "encrypted", "sensitive"] {
            let mut config = target.clone(); config["type"] = json!(secret_type);
            assert!(validate_sync_config("vercel", &config).is_ok(), "Vercel should accept {}", config);
        }
    }
}

#[test]
fn azure_key_vault_rejects_unsupported_initial_import() {
    reject_all("azure_key_vault", ["import_local", "import_remote"].into_iter()
        .map(|initial| json!({"initial_sync": initial})).collect());
}

#[test]
fn initial_import_rejects_paths_that_exclude_root() {
    let mut configs = Vec::new();
    for initial in ["import_local", "import_remote"] {
        for paths in [json!(["/app/"]), json!(["app", "/db/"])] {
            for include in [false, true] {
                let config = json!({"initial_sync": initial, "paths": paths, "include_subfolders": include});
                assert!(!path_selected(&config, "/"), "fixture must exclude the import destination: {}", config);
                configs.push(config);
            }
        }
    }
    reject_all("aws_secrets_manager", configs);
}

#[test]
fn initial_import_accepts_root_using_existing_path_normalization() {
    for initial in ["import_local", "import_remote"] {
        for selection in [json!({}), json!({"paths": []}), json!({"paths": ["/"]}), json!({"paths": [""]}),
            json!({"paths": ["///"]}), json!({"paths": ["/app/", "//"]})] {
            for include in [false, true] {
                let mut config = selection.clone(); config["initial_sync"] = json!(initial); config["include_subfolders"] = json!(include);
                assert!(path_selected(&config, "/"), "fixture must select the import destination: {}", config);
                assert!(validate_sync_config("aws_secrets_manager", &config).is_ok(), "root-compatible import should accept {}", config);
            }
        }
    }
}

#[test]
fn initial_sync_rejects_unknown_and_nonstring_values() {
    reject_all("aws_secrets_manager", vec![json!("pull"), json!(""), json!(true), json!(false), json!(null), json!(1), json!([]), json!({})]
        .into_iter().map(|value| json!({"initial_sync": value})).collect());
}

#[test]
fn initial_sync_preserves_overwrite_and_default_with_nonroot_paths() {
    for kind in ["aws_secrets_manager", "azure_key_vault"] {
        for config in [json!({}), json!({"initial_sync": "overwrite"}), json!({"paths": ["/app/"]}),
            json!({"initial_sync": "overwrite", "paths": ["/app/"], "include_subfolders": true})] {
            assert!(validate_sync_config(kind, &config).is_ok(), "non-import sync should accept {} for {}", config, kind);
        }
    }
}
