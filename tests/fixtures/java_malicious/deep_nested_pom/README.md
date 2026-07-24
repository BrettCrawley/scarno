# deep_nested_pom/

A `pom.xml` with 2000 levels of XML nesting is generated **programmatically**
in `tests/security/test_adversarial.py::test_deeply_nested_xml_does_not_stack_overflow`
via `tmp_path`. We deliberately do not commit a 2000-level file to the repo.
