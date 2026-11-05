import secrets, string
from zxcvbn import zxcvbn
SYMBOLS='!@#$%^&*()-_=+[]{};:,.?/'; AMBIGUOUS='O0Il1|`\"\''
def generate_password(length=20, lower=True, upper=True, digits=True, symbols=True, avoid_ambiguous=False):
    if not 8 <= int(length) <= 128: raise ValueError('Length must be between 8 and 128.')
    pools=[]
    for enabled, chars in ((lower,string.ascii_lowercase),(upper,string.ascii_uppercase),(digits,string.digits),(symbols,SYMBOLS)):
        if enabled:
            pool=''.join(c for c in chars if not (avoid_ambiguous and c in AMBIGUOUS))
            if pool: pools.append(pool)
    if not pools: raise ValueError('Enable at least one character set.')
    if length < len(pools): raise ValueError('Length is too short for selected character sets.')
    alphabet=''.join(pools); result=[secrets.choice(p) for p in pools]
    result.extend(secrets.choice(alphabet) for _ in range(length-len(result))); secrets.SystemRandom().shuffle(result)
    return ''.join(result)
def generate_passphrase(words=5, separator='-'):
    vocabulary='amber anchor apple arch autumn badge bamboo beacon birch blossom breeze bronze cactus canyon cedar cherry cobalt comet coral cosmos cricket crystal delta drift dune echo ember falcon fern field fjord flame flora forest fossil galaxy garden glacier gold granite harbor hazel horizon indigo island ivory jade jungle kernel lagoon lantern lemon lilac maple meadow mercury mist moon moss nectar nova ocean olive orbit orchid otter pebble pepper phoenix pine planet plum pollen quartz quiet radar raven reef river robin rocket saffron sage salmon satin shadow silver skylark solar sparrow spruce star stone summit tiger timber topaz tulip valley velvet violet walnut willow winter xenon yellow zephyr'.split()
    if not 4 <= int(words) <= 10: raise ValueError('Choose between 4 and 10 words.')
    return separator.join(secrets.choice(vocabulary) for _ in range(words))
def analyze_password(password):
    if not password: raise ValueError('Enter a password to analyze.')
    r=zxcvbn(password); f=r.get('feedback',{})
    return {'score':r['score'],'label':['Very weak','Weak','Fair','Strong','Very strong'][r['score']],'guesses':r.get('guesses',0),'warning':f.get('warning',''),'suggestions':f.get('suggestions',[])}
