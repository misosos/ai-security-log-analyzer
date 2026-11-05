import json
from pathlib import Path
import subprocess


def test_python_canonical_vectors_and_javascript_contract():
    vectors = json.loads(Path('tests/fixtures/evaluation_canonical_er2d_c.json').read_text(encoding='utf-8'))
    assert all(json.dumps(item['value'], ensure_ascii=True, sort_keys=True, separators=(',', ':')) == item['canonical'] for item in vectors)
    result = subprocess.run(['node', 'tests/evaluation_validator_contract_er2d_c.mjs'], capture_output=True, text=True, check=True)
    assert 'ER2DC_VALIDATOR PASS' in result.stdout
    assert 'ER2DC_RESPONSE PASS' in result.stdout
    assert 'ER2DC_OUTCOME PASS' in result.stdout
