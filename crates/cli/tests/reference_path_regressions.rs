include!("developer_workflows.rs");

#[test]
fn regression_root_reference_ignores_unrelated_valid_path_without_trailing_slash() {
    let s = Sandbox::new(); let api = Api::new();
    let input = template(&s, "root={{ow://env-a/ROOT}}\n");
    api.secrets("env-a", json!([secret("/", "ROOT", "root-control")]));
    let control = s.remote(&api, &["inject", "--input", text(&input)]);
    success(&control, "root reference control"); assert_eq!(control.stdout, b"root=root-control\n");
    api.secrets("env-a", json!([secret("/", "ROOT", "root-control"), secret("/service", "ROOT", "different-path")]));
    let out = s.remote(&api, &["inject", "--input", text(&input)]);
    success(&out, "root reference beside unrelated valid /service path");
    assert_eq!(out.stdout, b"root=root-control\n", "unrelated path must not prevent or change root resolution");
}

#[test]
fn regression_root_reference_ignores_unrelated_sealed_root_secret() {
    let s = Sandbox::new(); let api = Api::new();
    let mut sealed = secret("/", "UNRELATED_SEALED", ""); sealed["type"] = json!("sealed");
    api.secrets("env-a", json!([sealed, secret("/", "ROOT", "root-control")]));
    let input = template(&s, "{{ow://env-a/ROOT}}");
    let out = s.remote(&api, &["inject", "--input", text(&input)]);
    success(&out, "root reference beside unrelated sealed root secret");
    assert_eq!(out.stdout, b"root-control");
}
