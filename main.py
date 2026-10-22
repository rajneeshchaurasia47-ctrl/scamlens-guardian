from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from urllib.parse import urlsplit
from pathlib import Path
import re, ipaddress, os, json, urllib.request, urllib.error

ROOT=Path(__file__).resolve().parent
app=FastAPI(title='ScamLens Guardian',version='4.0.0')
app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')

class Message(BaseModel):
    message:str=Field(min_length=1,max_length=12000)

class Conversation(BaseModel):
    message:str=Field(min_length=1,max_length=12000)
    question:str=Field(min_length=1,max_length=1000)
    language:str='en'
    history:list[dict[str,str]]=Field(default_factory=list,max_length=12)
    exposure:str='none'

class Incident(BaseModel):
    exposure:str
    message:str=Field(default='',max_length=12000)
    country:str='IN'


RULES=[
 ('secret',r'\b(otp|one[ -]?time password|verification code|upi pin|cvv|password|pin number|ओटीपी|पासवर्ड)\b',28,'Asks for a secret or authentication credential','Never share an OTP, UPI PIN, CVV or password.'),
 ('urgency',r'\b(urgent|immediately|act now|within \d+ (minutes?|hours?)|last warning|suspended|blocked|today only|अभी|तुरंत)\b',17,'Creates urgency or threatens consequences','Pause. Independently verify the claim before acting.'),
 ('reward',r'\b(lottery|won|winner|prize|free gift|cashback|reward|इनाम|लॉटरी)\b',15,'Promises a reward or prize','Do not pay fees to collect an unexpected reward.'),
 ('identity',r'\b(kyc|aadhaar|pan card|verify your account|update your bank|bank account|customer care|केवाईसी)\b',17,'Requests identity or financial verification','Open your bank or service app directly instead of following the message.'),
 ('money',r'\b(processing fee|registration fee|transfer money|send money|pay now|deposit|payment required|pay a fee|भुगतान)\b',19,'Requests money or an upfront payment','Do not transfer funds until the recipient is independently verified.'),
 ('remote',r'\b(anydesk|teamviewer|remote access|screen share|screen sharing|install app)\b',28,'Requests remote access or screen sharing','Do not install remote-control apps at a stranger’s request.'),
 ('click',r'\b(click here|tap this link|open this link|visit the link|link below)\b',9,'Pushes you to open a link','Navigate to the official website yourself.'),
 ('impersonation',r'\b(rbi|income tax|police|customs|courier|delivery failed|amazon support|bank officer|digital arrest)\b',12,'Claims authority or impersonates a familiar organization','Verify through independently sourced official contact details.'),
]
SHORT={'bit.ly','tinyurl.com','t.co','cutt.ly','is.gd','rb.gy','shorturl.at','tiny.cc'}
URL_RE=re.compile(r'(?<!@)(?:https?://|www\.)[^\s<>"\']+|(?<![\w@])(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>"\']*)?',re.I)


def extract_urls(text):
    found=[]
    for match in URL_RE.finditer(text):
        raw=match.group(0).rstrip('.,;:!?)')
        url=raw if raw.lower().startswith(('http://','https://')) else 'https://'+raw
        try:
            p=urlsplit(url)
            host=(p.hostname or '').lower().rstrip('.')
            if not host or '.' not in host and not re.fullmatch(r'\d+\.\d+\.\d+\.\d+',host):continue
            if any(x['url']==raw for x in found):continue
            findings=[]
            if p.scheme=='http':findings.append(('no_https',10,'Uses an unencrypted HTTP link'))
            if host in SHORT:findings.append(('shortened',19,'Shortened link hides the destination'))
            if 'xn--' in host:findings.append(('punycode',16,'Internationalized domain needs closer inspection'))
            try:
                ipaddress.ip_address(host)
                findings.append(('ip_host',18,'Link uses an IP address instead of a domain'))
            except ValueError:pass
            if '@' in p.netloc:findings.append(('at_symbol',22,'URL contains @, which can disguise the actual host'))
            if len(host.split('.'))>=5:findings.append(('many_subdomains',8,'Unusually many domain segments'))
            found.append({'url':raw,'host':host,'findings':findings})
        except ValueError:continue
        if len(found)>=12:break
    return found


def analyze(message):
    signals=[];score=0
    for code,pattern,points,title,action in RULES:
        m=re.search(pattern,message,re.I)
        if m:
            signals.append({'id':code,'title':title,'evidence':m.group(0),'points':points,'action':action})
            score+=points
    links=extract_urls(message)
    for link in links:
        for code,points,title in link['findings']:
            signals.append({'id':code,'title':title,'evidence':link['url'],'points':points,'action':'Do not open the link. Find the official site independently.'})
            score+=points
    score=min(100,score)
    risk='High' if score>=55 else 'Medium' if score>=25 else 'Low'
    if any(s['id']=='secret' for s in signals):category='Credential theft / OTP phishing'
    elif any(s['id']=='remote' for s in signals):category='Remote-access scam'
    elif any(s['id']=='money' for s in signals):category='Payment / advance-fee scam'
    elif any(s['id']=='reward' for s in signals):category='Prize / reward scam'
    elif links:category='Suspicious-link review'
    else:category='General message review'
    steps=['Do not reply, click suspicious links, or transfer money until independently verified.',
           'Contact the claimed organization using its official app or a number you find yourself.',
           'Never share OTPs, passwords, UPI PINs, CVVs, or screen access.']
    if any(s['id']=='money' for s in signals):steps.insert(0,'If you already paid, contact your bank/payment provider immediately.')
    if any(s['id']=='remote' for s in signals):steps.insert(0,'If remote access was granted, disconnect the device and seek trusted technical help.')
    summary=(f'{risk} heuristic risk ({score}/100). '+('Detected '+str(len(signals))+' warning signal(s).' if signals else 'No common warning signals found; this does not establish safety.'))
    return {'risk':risk,'score':score,'category':category,'signals':signals,'links':links,
            'steps':steps,'summary':summary,'confidence_note':'This is an explainable, rule-based educational screening, not a verified fraud determination. A low score does not mean safe.',
            'privacy':'Analysis runs on this server. The app does not save submitted messages to a database.', 'url_verification':'not_performed' if links else 'not_applicable'}

EN={
 'safe':'Do not follow the message instructions yet. Use the official app or independently found contact information to verify.',
 'why':'Here are the specific signals: {signals}. These are warning indicators, not proof of fraud.',
 'otp':'Never share OTPs, passwords, UPI PINs or CVVs. Legitimate support should not ask you to reveal them.',
 'clicked':'If you clicked a link, do not enter more information. Close it, check device security, and change exposed passwords using the official service.',
 'paid':'If you sent money, immediately contact your bank or payment provider. In India you can report suspected cyber financial fraud through 1930 or cybercrime.gov.in.',
 'report':'Preserve screenshots and transaction IDs. In India, use cybercrime.gov.in or call 1930 for cyber financial fraud reporting. Outside India, contact your local authority.',
 'default':'I can explain the risk, tell you why it was flagged, suggest safe steps, or help if you clicked a link or sent money. What happened?'
}
HI={
 'safe':'अभी लिंक न खोलें और पैसे न भेजें। कंपनी के आधिकारिक ऐप या स्वयं खोजे गए नंबर से पुष्टि करें।',
 'why':'ये चेतावनी संकेत मिले: {signals}। ये धोखाधड़ी का पक्का प्रमाण नहीं हैं।',
 'otp':'OTP, पासवर्ड, UPI PIN या CVV किसी को न बताएं।',
 'clicked':'अगर लिंक खोला है तो उसमें और जानकारी न भरें। आधिकारिक ऐप से पासवर्ड बदलें और डिवाइस की सुरक्षा जांचें।',
 'paid':'अगर पैसे भेज दिए हैं तो तुरंत बैंक से संपर्क करें। भारत में साइबर वित्तीय धोखाधड़ी की रिपोर्ट 1930 या cybercrime.gov.in पर करें।',
 'report':'स्क्रीनशॉट और ट्रांजैक्शन आईडी सुरक्षित रखें। भारत में cybercrime.gov.in या 1930 पर रिपोर्ट करें।',
 'default':'मैं बता सकता हूँ कि संदेश संदिग्ध क्यों है, क्या सावधानी बरतें और लिंक खोलने या पैसे भेजने पर क्या करें।'
}
HI_SIGNAL={'secret':'OTP या पासवर्ड माँगा गया','urgency':'जल्दी करने का दबाव बनाया गया','reward':'इनाम का लालच दिया गया','identity':'बैंक या पहचान सत्यापन माँगा गया','money':'पैसे माँगे गए','remote':'रिमोट एक्सेस माँगा गया','click':'लिंक खोलने को कहा गया','impersonation':'किसी संस्था के नाम का इस्तेमाल किया गया','no_https':'असुरक्षित HTTP लिंक मिला','shortened':'छोटा किया गया लिंक मिला','punycode':'डोमेन की विशेष जाँच ज़रूरी है','ip_host':'IP पते वाला लिंक मिला','at_symbol':'लिंक में भ्रामक @ चिह्न है','many_subdomains':'डोमेन में बहुत सारे हिस्से हैं'}
HI_PLANS={
'none':['संदेश के लिंक न खोलें और जवाब न दें।','आधिकारिक ऐप या स्वयं खोजे गए नंबर से पुष्टि करें।','ज़रूरत हो तो सबूत सुरक्षित रखकर भेजने वाले को ब्लॉक करें।'],
'clicked':['संदिग्ध पेज बंद करें और कोई जानकारी न भरें।','अगर कोई फ़ाइल डाउनलोड हुई है तो उसे न खोलें; डिवाइस की सुरक्षा जाँचें।','आधिकारिक ऐप से अपने खाते की गतिविधि जाँचें।'],
'credentials':['अगर बैंकिंग OTP साझा किया है, तो तुरंत बैंक की आधिकारिक हेल्पलाइन पर संपर्क करें और खाते की सुरक्षा जाँच करवाएँ।','आधिकारिक ऐप या वेबसाइट से प्रभावित पासवर्ड बदलें और अन्य सत्रों से लॉग आउट करें।','जहाँ संभव हो, अतिरिक्त सुरक्षा चालू करें और किसी को नया OTP न दें।','अनधिकृत लेनदेन दिखे तो तुरंत 1930 या cybercrime.gov.in पर रिपोर्ट करें।'],
'paid':['तुरंत बैंक या भुगतान सेवा की आधिकारिक हेल्पलाइन पर संपर्क करें।','लेनदेन नंबर, स्क्रीनशॉट और समय सुरक्षित रखें।','भारत में 1930 या cybercrime.gov.in पर तुरंत रिपोर्ट करें।','रिकवरी के नाम पर किसी अनजान व्यक्ति को पैसे न दें।'],
'remote':['प्रभावित डिवाइस का इंटरनेट बंद करें।','किसी दूसरे सुरक्षित डिवाइस से ज़रूरी पासवर्ड बदलें और बैंक को सूचित करें।','भरोसेमंद तकनीकी सहायता से रिमोट-एक्सेस ऐप हटवाएँ।','अनधिकृत लेनदेन हो तो तुरंत रिपोर्ट करें।']}


def respond(message,question,language='en'):
    analysis=analyze(message)
    q=question.lower();lex=HI if language.lower().startswith('hi') else EN
    if re.search(r'\b(why|reason|flag|suspicious|क्यों|कारण)\b',q):key='why'
    elif re.search(r'\b(otp|pin|password|cvv|पासवर्ड)\b',q):key='otp'
    elif re.search(r'\b(clicked|opened|visited|link|खोल|क्लिक)\b',q):key='clicked'
    elif re.search(r'\b(paid|sent money|transferred|payment|पैसे|भुगतान)\b',q):key='paid'
    elif re.search(r'\b(report|complain|police|शिकायत|रिपोर्ट)\b',q):key='report'
    elif re.search(r'\b(safe|should i|what do|क्या कर|सुरक्षित)\b',q):key='safe'
    else:key='default'
    signals=', '.join((HI_SIGNAL.get(x['id'],x['title']) if lex is HI else x['title']) for x in analysis['signals'][:4]) or ('no common indicators' if lex is EN else 'कोई सामान्य संकेत नहीं')
    return {'answer':lex[key].format(signals=signals),'intent':key,'analysis':analysis,'language':'hi' if lex is HI else 'en','simulation':True}


# Demo scenarios are fictional; never enter live OTPs, passwords or financial details.
SCENARIOS={
 'bank':{'name':'Bank account takeover','message':'URGENT: Your bank KYC expires in 10 minutes. Verify at https://bit.ly/secure-kyc and share your OTP to avoid suspension.','challenge':'I entered my password on that website. What now?'},
 'delivery':{'name':'Fake courier delivery','message':'Delivery failed. Pay a ₹29 redelivery processing fee now at http://parcel-check.example/pay to receive your package.','challenge':'I already paid the fee using my card.'},
 'job':{'name':'Job task scam','message':'Congratulations! Earn ₹4000 daily from home. Pay a registration fee today to activate your account.','challenge':'They want me to send a deposit before I start.'},
 'remote':{'name':'Fake tech support','message':'Amazon support: your account is blocked. Install AnyDesk immediately and share your screen so we can fix it.','challenge':'I installed the remote access app.'},
 'safe':{'name':'Ordinary message','message':'Reminder: our class project meeting is at 4 PM in the library.','challenge':'Does a low risk score mean this is safe?'}
}

EXPOSURES={
 'none':{'label':'I have not interacted','severity':'Preventive','steps':['Do not click links or reply to the sender.','Verify the claim using an independently located official website or app.','Block or report the sender after saving evidence if needed.']},
 'clicked':{'label':'I clicked a link','severity':'Caution','steps':['Close the suspicious page; do not enter information or download anything.','If a file was downloaded, do not open it; run a trusted device security scan.','Check the official account directly for unusual activity.']},
 'credentials':{'label':'I entered a password or OTP','severity':'Urgent','steps':['If a banking OTP was exposed, immediately contact the bank through its official helpline and ask it to secure the account.','Change affected passwords through official apps or websites and sign out of other sessions.','Enable stronger authentication where available; never share another OTP or recovery code.','Report unauthorized transactions promptly to the bank and relevant authorities.']},
 'paid':{'label':'I sent money','severity':'Urgent','steps':['Immediately contact your bank or payment provider using an official number; ask about fraud reporting or reversal.','Preserve payment references, chat screenshots, timestamps and URLs.','Report the suspected fraud promptly to the relevant authorities.','Do not pay anyone who promises guaranteed recovery for a fee.']},
 'remote':{'label':'I granted remote access','severity':'Urgent','steps':['Disconnect the affected device from the internet to stop active remote access.','On a different trusted device, change important passwords and contact your bank if financial apps were exposed.','Remove remote access software and seek trusted technical assistance to inspect the device.','Preserve evidence and report any unauthorized transactions.']}
}

def incident_plan(exposure,country='IN'):
    entry=EXPOSURES.get(exposure)
    if not entry:raise ValueError('Unknown exposure')
    steps=list(entry['steps'])
    if country.upper()=='IN' and exposure in ('paid','credentials','remote'):
        steps.append('In India, suspected cyber financial fraud can be reported at 1930 or cybercrime.gov.in.')
    return {'exposure':exposure,'label':entry['label'],'severity':entry['severity'],'steps':steps,'disclaimer':'General safety information, not emergency or financial advice. Contact your bank and local authorities directly.'}

# Never send raw OTPs, card numbers or passwords to an external model.
def redact(text):
    text=re.sub(r'(?i)\b(otp|verification code|password|cvv|upi pin)\s*[:= -]+\S+',r'\1 [REDACTED]',text)
    text=re.sub(r'\b(?:\d[ -]*?){13,19}\b','[REDACTED_CARD]',text)
    text=re.sub(r'(?<!\d)\d{6}(?!\d)','[REDACTED_CODE]',text)
    return text

def optional_model_reply(req,analysis,plan):
    key=os.environ.get('OPENAI_API_KEY','').strip()
    if not key:return None
    model=os.environ.get('OPENAI_MODEL','gpt-4.1-mini')
    instruction=('You are Guardian, a calm scam-safety assistant in a simulated Alexa+ web experience. '
      'Never claim a message is definitively safe or fraudulent. Never ask for OTP, passwords, CVV, card details or other secrets. '
      'Do not tell users to visit unverified links. Give concise actionable advice. If money was sent or credentials leaked, '
      'prioritize contacting the bank through official channels. Use the provided evidence only; do not invent website verification. '
      'Do not imply you have contacted police, banks or external services. Reply in '+('Hindi.' if req.language.startswith('hi') else 'English.'))
    history=[]
    for turn in req.history[-6:]:
        role=turn.get('role','')
        if role in ('user','assistant'):
            history.append({'role':role,'content':redact(str(turn.get('content',''))[:900])})
    evidence={'risk':analysis['risk'],'signals':[s['title'] for s in analysis['signals'][:8]],'incident_steps':plan['steps']}
    payload={'model':model,'temperature':0.2,'max_tokens':260,'messages':[{'role':'system','content':instruction}, {'role':'system','content':'Analysis context: '+json.dumps(evidence)},*history,{'role':'user','content':redact(req.question)}]}
    request=urllib.request.Request('https://api.openai.com/v1/chat/completions',data=json.dumps(payload).encode(),headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'},method='POST')
    try:
        with urllib.request.urlopen(request,timeout=12) as r:
            response=json.load(r)
        return response['choices'][0]['message']['content'].strip()[:2200]
    except (urllib.error.URLError,TimeoutError,KeyError,IndexError,ValueError):
        return None

def agent_reply(req):
    analysis=analyze(req.message)
    exposure=req.exposure if req.exposure in EXPOSURES else 'none'
    q=req.question.lower()
    # Explicit user disclosure takes priority over an older selection.
    if re.search(r'\b(sent money|transferred|paid|lost money)\b|पैसे भेज',q):exposure='paid'
    elif re.search(r'\b(entered (my )?(otp|password|credentials)|shared (my )?otp)\b',q):exposure='credentials'
    elif re.search(r'\b(installed anydesk|granted remote|shared my screen)\b',q):exposure='remote'
    elif re.search(r'\b(clicked|opened the link|tapped the link)\b',q) and exposure=='none':exposure='clicked'
    plan=incident_plan(exposure)
    model_answer=optional_model_reply(req,analysis,plan)
    if model_answer:
        answer=model_answer;engine='optional-ai'
    else:
        fallback=respond(req.message,req.question,req.language)
        answer=fallback['answer'];engine='guided-fallback'
        if exposure!='none':
            localized_steps=HI_PLANS[exposure] if req.language.startswith('hi') else plan['steps']
            answer+=('\n\nYour next steps:\n' if not req.language.startswith('hi') else '\n\nअगले कदम:\n')+'\n'.join(f'{i+1}. {step}' for i,step in enumerate(localized_steps[:4]))
        if req.history and exposure=='none' and fallback['intent']=='default':
            answer+='\n\nYou can tell me whether you clicked a link, shared a password, paid, or only received the message.'
    return {'answer':answer,'engine':engine,'analysis':analysis,'incident':plan,'exposure':exposure,'simulation':True,'language':req.language}

@app.post('/api/analyze')
def analyze_api(req:Message):return analyze(req.message)

@app.post('/api/converse')
def converse_api(req:Conversation):
    return agent_reply(req)

@app.post('/api/incident')
def incident_api(req:Incident):
    
    if req.exposure not in EXPOSURES:raise HTTPException(status_code=422,detail='Unknown exposure')
    return incident_plan(req.exposure, req.country)

@app.get('/api/scenarios')
def scenarios_api():return {'scenarios':SCENARIOS}


@app.get('/api/health')
def health():return {'status':'ok','version':'4.0.0','mode':'simulated-alexa-experience'}

@app.get('/')
def home():return FileResponse(ROOT/'static'/'index.html')
