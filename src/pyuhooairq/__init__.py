import requests, hashlib
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
    # CACHE_FILE = "cache"
    USER_AGENT = "uHoo/9.1 (iPhone; XS; iOS 14.4; Scale/3.00)"

    # these are for storing session info
    UID_HEADER = "X-AIRQ-UID"
    CODE_HEADER = "X-AIRQ-CODE"
    TOKEN_HEADER = "X-AIRQ-TOKEN"

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = self._new_session()
        self.login()
        
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

    def _get_uid(self):
        try:
            response = self.session.get(url=self.URL_GET_UID)
            self.session.headers.update(
                {self.UID_HEADER: response.json()["uId"]}
            )
        except requests.exceptions.RequestException as ex:
            print("HTTP Request failed: " + str(ex))

    def _get_client_code(self):
        try:
            response = self.session.post(
                url=self.URL_GET_CLIENT_CODE,
                data={
                    "clientId": Uhoo.CLIENT_ID,
                    "username": self.username,
                },
            )
            self.session.headers.update(
                {self.CODE_HEADER: response.json()["code"]}
            )
        except requests.exceptions.RequestException as ex:
            print("HTTP Request failed: " + str(ex))

    def _renew_token(self):
        try:
            response = self.session.post(
                url=self.URL_RENEW_TOKEN,
                data={
                    "Token": self.session.headers.get(self.TOKEN_HEADER),
                    "userDeviceId": self.CLIENT_ID,
                },
            )
            if response.status_code == 401:
                self.login()
                return
            data = response.json()
            self.session.headers.update(
                {
                    self.TOKEN_HEADER: data["token"],
                    "Authorization": "Bearer " + data["refreshToken"],
                }
            )
        except requests.exceptions.RequestException as ex:
            print("HTTP Request failed: " + str(ex))

    def _get_data(self, datatype, retry=0):
        try:
            response = self.session.get(url=datatype)
            if (
                response.status_code == 401 or response.status_code == 403
            ) and retry < 2:
                print('Renewing token')
                self._renew_token()
                response = self._get_data(retry + 1)
            return response
        except requests.exceptions.RequestException as e:
            message = "HTTP Request failed: " + str(e)
            print(message)
            return message

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
            data = response.json()
            self.session.headers.update(
                {
                    self.TOKEN_HEADER: data["token"],
                    "Authorization": "Bearer " + data["refreshToken"],
                }
            )
        except requests.exceptions.RequestException as e:
            print("HTTP Request failed: " + str(e))

    # Gets all latest data and returns raw response in json format
    def get_all_latest_data(self):
        return self._get_data(self.URL_GET_ALL_LATEST_DATA).json()

    # Gets all latest data and returs device list with basic info
    def get_all_devices(self):
        response = self._get_data(self.URL_GET_ALL_LATEST_DATA).json()
        basic_info = {}
        device_list = []
        for device in response['devices']:
            basic_info['name'] = device['name']
            basic_info['serialNumber'] = device['serialNumber']
            basic_info['macAddress'] = device['macAddress']
            basic_info['ssid'] = device['ssid']
            device_list.append(basic_info)
        return device_list

    def get_current_data(self, device_serial=None):
        response = self._get_data(self.URL_GET_ALL_LATEST_DATA).json()
        for device in response['data']:
            if device_serial == device['serialNumber']:
                return device

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
        self.key = hashlib.md5(
            clientCode.encode("utf-8")
        ).digest()  # initialization key
        self.length = AES.block_size  # Initialize the block size
        self.aes = AES.new(
            self.key, AES.MODE_ECB
        )  # Initialize AES, an instance of ECB mode
        # Truncate function to remove padded characters
        self.unpad = lambda date: date[0 : -ord(date[-1])]

    def pad(self, text):
        """
        Fill the function so that the bytecode length of the encrypted data is an integer multiple of block_size
        """
        text = str(text, encoding="utf-8")
        count = len(text)
        add = self.length - (count % self.length)
        entext = text + (chr(add) * add)
        return bytes(entext, encoding="utf-8")

    def encrypt(self, uid, password):
        passwordSalted = uid + password + Crypto.SALT
        passwordHashed = (
            hashlib.sha256(passwordSalted.encode("utf-8")).hexdigest().encode("utf-8")
        )
        return self.aes.encrypt(self.pad(passwordHashed))
