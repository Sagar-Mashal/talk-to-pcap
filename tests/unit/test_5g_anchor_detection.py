import pytest
from src.query.query_helpers import detect_ue_id_in_sql


def test_detect_ran_ue_ngap_id_like_pattern():
    sql = "SELECT * FROM packets WHERE protocol_fields_json LIKE '%\"ngap.RAN_UE_NGAP_ID\": \"42\"%'"
    result = detect_ue_id_in_sql(sql)
    assert result is not None, "Expected to detect NGAP RAN UE ID in LIKE pattern"
    field, value = result
    assert field == "ngap.RAN_UE_NGAP_ID"
    assert value == "42"


def test_detect_ran_ue_ngap_id_direct_compare():
    sql = "SELECT * FROM packets WHERE ngap.RAN_UE_NGAP_ID = '99'"
    result = detect_ue_id_in_sql(sql)
    assert result is not None, "Expected to detect NGAP RAN UE ID in direct compare pattern"
    field, value = result
    assert field == "ngap.RAN_UE_NGAP_ID"
    assert value == "99"