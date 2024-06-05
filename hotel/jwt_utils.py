import jwt 
from datetime import timedelta,datetime
from django.conf import settings

def generate_jwt_token(user_id,expiration_time_hours=1):
    payload={
        'user_id':user_id,
        'exp':datetime.utcnow() + timedelta(hours=expiration_time_hours)
    }
    return jwt.encode(payload,settings.SECRET_KEY,algorithm='HS256')