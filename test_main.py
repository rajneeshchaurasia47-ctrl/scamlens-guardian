from main import analyze,respond

def test_otp():
    x=analyze('URGENT! Share your OTP now or account blocked! Pay a processing fee.')
    assert x['risk']=='High' and any(s['id']=='secret' for s in x['signals'])

def test_clean():
    x=analyze('Meeting is tomorrow at noon.')
    assert x['score']==0 and x['risk']=='Low'

def test_short_url():
    x=analyze('Open https://bit.ly/abc right now')
    assert any(s['id']=='shortened' for s in x['signals'])

def test_at_url():
    x=analyze('https://example.com@evil.test/login')
    assert any(s['id']=='at_symbol' for s in x['signals'])

def test_conversation():
    x=respond('Share your OTP now','Why was this flagged?')
    assert x['intent']=='why' and 'OTP' in x['answer'] or x['intent']=='why'

def test_hindi():
    assert respond('urgent otp','क्या करूँ?','hi')['language']=='hi'

if __name__=='__main__':
    for name,fn in list(globals().items()):
        if name.startswith('test_') and callable(fn):fn();print('PASS',name)
