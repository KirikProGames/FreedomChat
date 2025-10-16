import requests
from dotenv import load_dotenv
import os

load_dotenv()

CLIENT_ID = os.environ.get('YOOMONEY_CLIENT_ID')
CLIENT_SECRET = os.environ.get('YOOMONEY_CLIENT_SECRET')
REDIRECT_URI = 'http://localhost:5000/payment_callback'  # Для теста

def get_auth_url():
    return (f"https://yoomoney.ru/oauth/authorize?"
            f"client_id={CLIENT_ID}&"
            f"response_type=code&"
            f"redirect_uri={REDIRECT_URI}&"
            f"scope=account-info operation-history payment-p2p")

def get_access_token(auth_code):
    response = requests.post('https://yoomoney.ru/oauth/token', data={
        'code': auth_code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'
    })
    
    if response.status_code == 200:
        token_data = response.json()
        print(f"✅ Access Token: {token_data.get('access_token')}")
        print(f"✅ Token Type: {token_data.get('token_type')}")
        return token_data
    else:
        print(f"❌ Ошибка: {response.text}")
        return None

if __name__ == '__main__':
    print("1. Перейдите по ссылке для авторизации:")
    print(get_auth_url())
    print("\n2. После авторизации вы получите код в URL")
    print("3. Введите этот код ниже:")
    
    auth_code = input("Код авторизации: ").strip()
    get_access_token(auth_code)
