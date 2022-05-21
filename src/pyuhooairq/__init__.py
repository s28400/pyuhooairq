import requests, hashlib, sys
from urllib3.exceptions import InsecureRequestWarning
from Crypto.Cipher import AES

# Quiet urllib3 Unverified HTTPS warings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class Uhoo:
    BASE_URL_AUTH = "https://auth.uhooinc.com/"
    BASE_URL_API = "https://api.uhooinc.com/v1/"
    URL_LOGOUT = BASE_URL_API + "clearusersession"
    URL_GET_ALL_LATEST_DATA = BASE_URL_API + "getalllatestdata"
    URL_LOGIN = BASE_URL_AUTH + "login"
    URL_GET_UID = BASE_URL_AUTH + "user"
    URL_RENEW_TOKEN = BASE_URL_AUTH + "renewusertoken"
    URL_GET_CLIENT_CODE = BASE_URL_AUTH + "verifyemail"
    CLIENT_ID = "85E7D9B2-4876-4E2C-BFB5-87FB4918A0E42"
    USER_AGENT = "uHoo/9.1 (iPhone; XS; iOS 14.4; Scale/3.00)"

    UID_HEADER = "X-AIRQ-UID"
    CODE_HEADER = "X-AIRQ-CODE"
    TOKEN_HEADER = "X-AIRQ-TOKEN"

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = self._new_session()
        self.login()
    
    # Creates new request session with static headers
    def _new_session(self):
        session = requests.Session()
        session.verify = False
        session.headers = {
            "Accept": "*/*",
            "Host": "auth.uhooinc.com",
            "If-None-Match": 'W/"59-lnUAz2k+ZYhT0jjdJV1ylA"',
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": self.USER_AGENT,
            "Accept-Language": "en-UK;q=1.0",
            "Accept-Encoding": "gzip;q=1.0, compress;q=0.5",
            "Connection": "close",
        }
        return session

    # Fetches and updates UID session header
    def _get_uid(self):
        try:
            response = self.session.get(url=self.URL_GET_UID)
            if response.status_code == 200:
                self.session.headers.update(
                    {self.UID_HEADER: response.json()["uId"]}
                )
            else:
                print(f'Bad response: {response.status_code}, get_uid failed.')
                sys.exit(0)
        except requests.exceptions.RequestException as ex:
            print("HTTP Request failed: " + str(ex))
    
    # Fetches and updates code session header
    def _get_client_code(self):
        try:
            response = self.session.post(
                url=self.URL_GET_CLIENT_CODE,
                data={
                    "clientId": Uhoo.CLIENT_ID,
                    "username": self.username,
                },
            )
            if response.status_code == 200:
                self.session.headers.update(
                    {self.CODE_HEADER: response.json()["code"]}
                )
            else:
                print(f'Bad response: {response.status_code}, check creds')
                sys.exit(0)
        except requests.exceptions.RequestException as ex:
            print("HTTP Request failed: " + str(ex))

    # Fetches data of speicifed type
    def _get_data(self, datatype, retry=0):
        try:
            response = self.session.get(url=datatype)
            if ((response.status_code == 401 or response.status_code == 403) 
                    and retry < 2):
                print('Token expired, logging in')
                self.login()
                response = self._get_data(datatype, retry + 1)
            return response
        except requests.exceptions.RequestException as e:
            message = "HTTP Request failed: " + str(e)
            print(message)
            return message

    # Logs in using user credentials
    def login(self):
        self._get_uid()
        self._get_client_code()
        crypto = Crypto(self.session.headers.get(self.CODE_HEADER))
        pass_encrypted = crypto.encrypt(
            self.session.headers.get(self.UID_HEADER), self.password
        ).hex()
        try:
            response = self.session.post(
                url=self.URL_LOGIN,
                data={
                    "clientId": self.CLIENT_ID,
                    "username": self.username,
                    "password": pass_encrypted,
                }
            )
            if response.status_code == 200:
                data = response.json()
                self.session.headers.update(
                {
                    self.TOKEN_HEADER: data["token"],
                    "Authorization": "Bearer " + data["refreshToken"],
                }
            )
            else:
                print(f'Bad response: {response.status_code}, check creds')
                sys.exit(0)

        except requests.exceptions.RequestException as e:
            print("HTTP Request failed: " + str(e))

    # Gets all latest data and returns raw response in json format
    def get_all_latest_data(self):
        return self._get_data(self.URL_GET_ALL_LATEST_DATA).json()

    # Gets all latest data and returns device list with basic info
    def get_all_devices(self):
        response = self._get_data(self.URL_GET_ALL_LATEST_DATA).json()
        basic_info = {}
        device_list = []
        for device in response['devices']:
            basic_info['name'] = device['name']
            basic_info['serialNumber'] = device['serialNumber']
            basic_info['macAddress'] = device['macAddress']
            basic_info['ssid'] = device['ssid']
            device_list.append(basic_info.copy())
        return device_list

    # Gets latest data and returns data for specified device in json format
    def get_current_data(self, device_serial=None):
        response = self._get_data(self.URL_GET_ALL_LATEST_DATA).json()
        for device in response['data']:
            if device_serial == device['serialNumber']:
                return device
        print('Could not get data for specified device!')

    # Gets latest data and returns formatted air quality data
    def get_current_airq_data(self, device_serial=None):
        data = self.get_current_data(device_serial=device_serial)

        airq_data = {}
        airq_data['pm2.5'] = data['dust']['value']
        airq_data['temperature'] = data['temp']['value']
        airq_data['humidity'] = data['humidity']['value']
        airq_data['air_pressure'] = data['pressure']['value']
        airq_data['tvoc'] = data['voc']['value']
        airq_data['co2'] = data['co2']['value']
        airq_data['co'] = data['co']['value']
        airq_data['ozone'] = data['ozone']['value']
        airq_data['no2'] = data['no2']['value']
        airq_data['virus_score'] = data['virusScore']
        return airq_data


class Crypto:
    SALT = "@uhooinc.com"

    def __init__(self, clientCode):
        self.key = hashlib.md5(clientCode.encode("utf-8")).digest()
        self.length = AES.block_size
        self.aes = AES.new(self.key, AES.MODE_ECB)
        self.unpad = lambda date: date[0 : -ord(date[-1])]

    def pad(self, text):
        text = str(text, encoding="utf-8")
        count = len(text)
        add = self.length - (count % self.length)
        entext = text + (chr(add) * add)
        return bytes(entext, encoding="utf-8")

    def encrypt(self, uid, password):
        passwordSalted = uid + password + Crypto.SALT
        passwordHashed = (
            hashlib.sha256(passwordSalted.encode("utf-8")
            ).hexdigest().encode("utf-8"))
        return self.aes.encrypt(self.pad(passwordHashed))
