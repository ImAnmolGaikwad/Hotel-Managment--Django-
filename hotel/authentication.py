from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
import jwt
from .models import Hotel
from django.conf import settings


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None 
        token = auth_header.split()[1]
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = payload['user_id']
            user = Hotel.objects.get(id=user_id)

            return (user, None)  
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except jwt.DecodeError:
            raise AuthenticationFailed('Token is invalid')
        except Hotel.DoesNotExist:
            raise AuthenticationFailed('User not found')
        
