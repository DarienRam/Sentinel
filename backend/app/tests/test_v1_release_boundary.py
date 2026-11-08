"""V1-only architecture, contract and network-isolation regression checks."""
import importlib.util
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from app.api import scans
from app.schemas.scan import ScanCreate, ScanResult
from app.services import scan_engine


def test_api_calls_original_rules_directly():
    assert scans.analyze_scan is scan_engine.analyze_scan


def test_only_v1_services_and_no_scientific_runtime():
    folder=Path(scan_engine.__file__).parent
    assert {p.name for p in folder.glob('*.py')} == {'__init__.py','scan_engine.py','retention.py'}
    assert not (folder.parents[2]/'ml').exists()
    for name in ('sklearn','numpy','scipy','joblib','pyarrow','openpyxl'):
        assert importlib.util.find_spec(name) is None
        assert name not in sys.modules


def test_original_public_response_contract():
    assert set(ScanResult.model_fields) == {
        'id','input_type','raw_content','risk_score','confidence_score','risk_level','summary',
        'recommendation','detected_categories','findings','finding_details','feedback','feedback_note',
        'is_saved','expires_at','created_at'}


def test_authenticated_and_anonymous_validation_remains_before_analysis(api_client,monkeypatch):
    calls=[]
    original=scans.analyze_scan
    def analyze(*args,**kwargs):
        calls.append(True)
        return original(*args,**kwargs)
    monkeypatch.setattr(scans,'analyze_scan',analyze)
    assert api_client.post('/scans',json={'input_type':'url','raw_content':'javascript:fixture'}).status_code==422
    assert api_client.post('/scans',json={'input_type':'message','raw_content':'Synthetic fixture.','save_scan':True}).status_code==403
    assert not calls


def test_v1_scan_neither_fetches_links_nor_spawns_workers(api_client,monkeypatch):
    import socket
    import urllib.request
    def denied(*args,**kwargs):
        raise AssertionError('Unexpected external operation')
    monkeypatch.setattr(socket,'getaddrinfo',denied)
    monkeypatch.setattr(urllib.request,'urlopen',denied)
    monkeypatch.setattr(subprocess,'Popen',denied)
    for kind,text in [('url','https://example.com/account/login'),
                      ('email','Review the meeting notes at https://example.com/docs'),
                      ('message','Please send the OTP code immediately.')]:
        response=api_client.post('/scans',json={'input_type':kind,'raw_content':text})
        assert response.status_code==200
        expected=scan_engine.analyze_scan(ScanCreate(input_type=kind,raw_content=text))
        for field in ('risk_score','risk_level','confidence_score','findings','recommendation','summary'):
            assert response.json()[field]==getattr(expected,field)
