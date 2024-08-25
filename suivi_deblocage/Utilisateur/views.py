from django.shortcuts import render
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions importnIsAuthentificated
from rest_framework.views import APIView
from rest_framework.response import response
from rest_framework import status
from serializers import PasswordResetSerializer
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.utils.http import urlsafe_based64_decode
from django.utils.encoding import force_str

Class LogoutView(APIView):
    permission_classes = (IsAuthenticated)

    def post (self, request):
        try:
            refresh_token = request.data ["refresh_token"]
            token = RefreshToken(refresh_token)
token.blacklist ()           
    return
Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return
Response(status=status.HTTP_400_BAD_REQUEST)            

Class PasswordResetView(APIView):
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if 
          serializer.is_valid()

          serializer.save()
          return
          response({"message"; "un lien de réinitialisation de mot de passe a été envoyé à votre email."},status=status.HTTP_200_OK)
          return(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

Class PasswordResetConfirmView(APIView):
    def post(self,request,uidb64, token):
        uid = force_str(urlsafe_based64_decode(uidb64))
        user = User.Objects.get(pk=uid)
        
        if default_token_generator(user,token):
            new_password = request.data.get("password")
            user.set_password(new_password)
            user.save()
            return
Response({"message": "mot de passe réinitialisé avec succès."},status=status.HTTP_200_OK)
         else:
            return
Response({"message": "le lien de réinitialisation n'est pas validé."},status=status.HTTP_400_BAD_REQUEST)
