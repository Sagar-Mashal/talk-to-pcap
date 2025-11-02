import pytest
from src.agents.message_type_mapper import preprocess_query_for_message_types

@pytest.mark.parametrize("inp, expected_fragment", [
    ("value in handover required msg", "message_type = 'HandoverPreparation'"),
    ("show handoverrequired", "message_type = 'HandoverPreparation'"),
    ("handoverRequired KPIs", "message_type = 'HandoverPreparation'"),
])
def test_handover_required_mapping(inp, expected_fragment):
    processed = preprocess_query_for_message_types(inp)
    assert expected_fragment in processed, processed
