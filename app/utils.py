import base64
#for memcache
import memcache
client = memcache.Client([('127.0.0.1', 11211)])

def encode(key, string):
    encoded_chars = []
    for i in xrange(len(string)):
        key_c = key[i % len(key)]
        encoded_c = chr(ord(string[i]) + ord(key_c) % 256)
        encoded_chars.append(encoded_c)
    encoded_string = "".join(encoded_chars)
    return base64.urlsafe_b64encode(encoded_string)


def decode(key, string):	
    decoded_chars = []    
    string = base64.urlsafe_b64decode(string)
    for i in xrange(len(string)):
        key_c = key[i % len(key)]
        encoded_c = chr(abs(ord(string[i]) - ord(key_c) % 256))
        decoded_chars.append(encoded_c)
    decoded_string = "".join(decoded_chars)    
    return decoded_string

def fetch_from_cache(url):
	mydict =  client.get(url)
	if not mydict:
		#get fresh
		cobj = CompanyAdmin.query.filter_by(username=session['username']).first()			
		token = "Bearer " + cobj.apitoken			
		headers = {'authorization': token}
		response = requests.request("GET", url, headers=headers)
		ret = response.text		
		mydict = json.loads(ret)
		#save to cache
		client.set(url,mydict)
		return mydict
	else:
		return mydict