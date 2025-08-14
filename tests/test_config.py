from auditor.config import load_config

def test_load_config_defaults(tmp_path):
    cfgfile = tmp_path / "c.yaml"
    cfgfile.write_text("assume_role_name: TestRole\n")
    conf = load_config(str(cfgfile))
    assert conf.assume_role_name == "TestRole"
    assert conf.stale_days.lambda_no_invocations == 30
