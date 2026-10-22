from main import analyze, redact, incident_plan, agent_reply, Conversation, SCENARIOS

def test_scenarios():
    assert len(SCENARIOS)>=5
    assert analyze(SCENARIOS['bank']['message'])['risk']=='High'

def test_redaction():
    assert '123456' not in redact('OTP: 123456')
    assert '1234567812345678' not in redact('card 1234567812345678')

def test_exposure():
    assert incident_plan('paid')['severity']=='Urgent'
    assert any('1930' in s for s in incident_plan('paid')['steps'])

def test_context():
    req=Conversation(message='Please share your OTP',question='I sent money',history=[{'role':'user','content':'Why?'}])
    d=agent_reply(req)
    assert d['exposure']=='paid' and 'bank' in d['answer'].lower()

def test_safe():
    assert analyze(SCENARIOS['safe']['message'])['risk']=='Low'

def test_remote():
    d=agent_reply(Conversation(message='Install AnyDesk',question='I installed AnyDesk'))
    assert d['exposure']=='remote'
