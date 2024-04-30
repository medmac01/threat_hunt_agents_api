from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .crew import HunterCrew
from . import investigator

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def answer(request):
    # Check if the request method is POST
    if request.method == 'POST':
        # Get the data from the request body
        data = request.data
        
        # Perform your processing based on the received data
        # For example, you can access the data and perform some calculations
        # Here, we'll just echo back the received data

        results = HunterCrew(data).run()

        processed_data = {
            'input': data,
            'output': results
        }
        
        # Return the processed data as a JSON response
        return Response(processed_data, status=status.HTTP_200_OK)
    
    # If the request method is not POST, return a 405 Method Not Allowed response
    return Response({'error': 'Method Not Allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def answer_v2(request):
    # Check if the request method is POST
    if request.method == 'POST':
        # Get the data from the request body
        data = request.data
        
        # Perform your processing based on the received data
        # For example, you can access the data and perform some calculations
        # Here, we'll just echo back the received data

        results = investigator.invoke(data["query"])

        processed_data = {
            'input': data,
            'output': results
        }
        
        # Return the processed data as a JSON response
        return Response(processed_data, status=status.HTTP_200_OK)
    
    # If the request method is not POST, return a 405 Method Not Allowed response
    return Response({'error': 'Method Not Allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


class ObtainAuthToken(APIView):
    """
    Obtain authentication token
    """
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)
        if user:
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key})
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
