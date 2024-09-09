import pathlib
import os
import json
import base64
import requests  # pip install requests
from Crypto.Cipher import AES  # pip install pycryptodome
from Crypto.Util import Padding
from ecdsa import ECDH, NIST256p, VerifyingKey, SigningKey  # pip install ecdsa
import pydantic
import logging
import dotenv

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)


HTTP_STATUS_OK = 200
SECURE_CHANNEL_MESSAGE = "ahnlabblockchaincompany"
WAAS_BASE_URL = "https://dev-api.waas.myabcwallet.com"


class SecureChannel(pydantic.BaseModel):
    channel_id: str
    bytes_secret: bytes

    def __str__(self):
        return f"channelid: {self.channel_id}, bytesSecret: {self.bytes_secret}"


class EmailLoginResult(pydantic.BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expire_in: int


def encrypt(secure_channel: SecureChannel, text: str) -> str:
    bytesKey = secure_channel.bytes_secret[0:16]
    bytesIV = secure_channel.bytes_secret[16:32]

    padded_txt = Padding.pad(text.encode("utf-8"), AES.block_size, "pkcs7")
    EncryptAES = AES.new(bytesKey, AES.MODE_CBC, bytesIV)
    enc_txt = EncryptAES.encrypt(padded_txt)
    base64_encode_txt = base64.b64encode(enc_txt).decode("utf-8")

    return base64_encode_txt


def create_secure_channel() -> SecureChannel:
    # PrivateKey, PublicKey 생성
    ECPrivateKey = SigningKey.generate(curve=NIST256p)
    ECPublicKey = ECPrivateKey.verifying_key

    # PublicKey hex값 변환
    strPublicKey = f"04{ECPublicKey.to_string().hex()}"
    log.debug(f"strPublicKey: {strPublicKey}")

    # Auth Server와 Secure Channel 생성
    response = requests.post(
        url=f"{WAAS_BASE_URL}/secure/channel/create",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"pubkey": strPublicKey, "plain": SECURE_CHANNEL_MESSAGE},
    )

    if HTTP_STATUS_OK != response.status_code:
        log.error(response.__dict__)
        raise Exception("Failed to create secure channel")

    dictResponse = json.loads(response.content)
    if (
        "publickey" not in dictResponse
        or "encrypted" not in dictResponse
        or "channelid" not in dictResponse
    ):
        log.error(f"Invalid auth server response. {dictResponse}")
        raise Exception("Failed to create secure channel")

    strServerPublicKey = dictResponse["publickey"]
    strEncryptedMessge = dictResponse["encrypted"]
    strChannelId = dictResponse["channelid"]

    # Auth 서버에서 받은 Public key와 위에서 생성한 Private Key로 ECDH 연산하여 shared secret 생성
    ECServerPublicKey = VerifyingKey.from_string(
        bytes.fromhex(strServerPublicKey), curve=NIST256p
    )
    clsECDH = ECDH(
        curve=NIST256p, private_key=ECPrivateKey, public_key=ECServerPublicKey
    )
    bytesSecret = clsECDH.generate_sharedsecret_bytes()

    # secret 32바이트 중 앞의 16바이트는 key, 뒤의 16바이트는 iv 로 AES 복호화를 수행한다.(AES/CBC/PKCS7Padding 사용)
    bytesKey = bytesSecret[0:16]
    bytesIV = bytesSecret[16:32]

    DecryptAES = AES.new(bytesKey, AES.MODE_CBC, bytesIV)
    strDecryptMessage = DecryptAES.decrypt(base64.b64decode(strEncryptedMessge))
    strUnpaddedDecMsg = Padding.unpad(
        strDecryptMessage, AES.block_size, "pkcs7"
    ).decode("utf-8")

    if SECURE_CHANNEL_MESSAGE == strUnpaddedDecMsg:
        log.debug(f"Channel id '{strChannelId}' is valid.")
    else:
        log.error(f"Channel id '{strChannelId}' is invalid.")
        log.error(
            f"SECURE_CHANNEL_MESSAGE: {SECURE_CHANNEL_MESSAGE} / strUnpaddedDecMsg: {strUnpaddedDecMsg}"
        )
        raise Exception("Failed to create secure channel")
    return SecureChannel(channel_id=strChannelId, bytes_secret=bytesSecret)


def email_login(
    email: str, encrypted_password: str, secure_channel_id: str, auth: str
) -> EmailLoginResult:
    r = requests.post(
        url=f"{WAAS_BASE_URL}/auth/auth-service/v2/login",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Secure-Channel": secure_channel_id,
            "Authorization": f"Basic {auth}",
        },
        data={
            "grant_type": "password",
            "username": email,
            "password": encrypted_password,
            "audience": "https://mw.myabcwallet.com",
        },
    )
    log.debug(r.text)
    r.raise_for_status()
    return EmailLoginResult.model_validate(r.json())


def main():

    dotenv.load_dotenv()

    email = os.getenv("USER_EMAIL2")
    password = os.getenv("USER_PASSWORD2")
    client_id = os.getenv("CLIENT_ID")
    client_secret = os.getenv("CLIENT_SECRET")

    log.info(f"email: {email}")
    log.info(f"password: {password}")

    # make basic auth header
    # base64({client_id}:{client_secret})

    auth_str = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    log.info(f"auth_str: {auth_str}")

    secure_channel = create_secure_channel()
    log.info(f"secure_channel_id: {secure_channel}")
    encrypted_text = encrypt(secure_channel, password)
    log.info(f"encrypted_text: {encrypted_text}")

    login_result = email_login(
        email, encrypted_text, secure_channel.channel_id, auth_str
    )
    log.info(f"login_result: {login_result.access_token}")


if __name__ == "__main__":
    main()
