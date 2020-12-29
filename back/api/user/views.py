from rest_framework import viewsets
from rest_framework.permissions import AllowAny
from .serializers import UserSerializer
from .models import CustomUser
from django.http import JsonResponse, HttpResponse
from django.contrib.auth import get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login, logout
import random
import re
# Create your views here.

def generate_session_token(length=10):
    # choose a in a-z and 0-9. And repeat 10 times.
    return ''.join(random.SystemRandom().choice([chr(i) for i in range(97, 123)] + [str(i) for i in range(10)]) for _ in range(length))

# This decorator below is needs for removing csrf function.
@csrf_exempt
def signin(request):
    if request.method == 'POST':
        return JsonResponse({'error': 'Send a post request with valid parameter only'})

    username = request.POST['email']
    password = request.POST['password']

    # validation part
    if not re.match('^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$', username):
        return JsonResponse({'error': 'Enter a valid email'})

    if len(password) < 3:
        JsonResponse({'error': 'Password needs to be at least of 3 char'})

    UserModel = get_user_model()
    # you can get CustomUser Model using settings.AUTH_USER_MODEL or get_user_model

    try:
        user = UserModel.objects.get(email=username)
        # get method can get values of the key(email)
        if user.check_password(password):
            usr_dict = UserModel.objects.filter(email=username).values().first()
            usr_dict.pop('password')

            if user.session_token(password) != '0':
                user.session_token = '0'
                user.save()
                return JsonResponse({'error': 'Previous session exists!'})

            token = generate_session_token()
            user.session_token = token
            user.save()
            login(request, user)
            return JsonResponse({'token': token, 'user': usr_dict})
        else:
            return JsonResponse({'error': 'Invalid password'})

    except UserModel.DoesNotExist:
        # UserModel.DoesNotExist means that you couldn't have get email.
        return JsonResponse({'error': 'Invalid Email'})

def signout(request, id):
    logout(request)

    UserModel = get_user_model()

    try:
        user = UserModel.objects.get(pk=id)
        user.session_token = "0"
        user.save()

    except UserModel.DoesNotExist:
        return JsonResponse({'error': 'Invalid user ID'})

    return JsonResponse({'success': 'Logout success'})

class UserViewSet(viewsets.ModelViewSet):
    permission_classes_by_action = {'create': [AllowAny]}

    queryset = CustomUser.objects.all().order_by('id')
    serializer_class = UserSerializer

    def get_permissions(self):
        try:
            # It may work empty list
            return [permission() for permission in self.permission_classes_by_action[self.action]]
        except KeyError:
            return [permission() for permission in self.permission_classes]

