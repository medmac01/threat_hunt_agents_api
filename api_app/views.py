from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

# from .crew import HunterCrew
from . import router

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


        processed_data = {
            'input': data,
            'output': "This endpoint is deprecated, please use answer_v2 instead."
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
        llm = data.get('llm', 'codestral')
        # Perform your processing based on the received data
        # For example, you can access the data and perform some calculations
        # Here, we'll just echo back the received data

        results = router.invoke(data["query"], llm=llm)

        processed_data = {
            'input': data,
            'title': "New Chat" if results['title'] is None else results['title'],
            'output': results['output']
        }
        
        # Return the processed data as a JSON response
        return Response(processed_data, status=status.HTTP_200_OK)
    
    # If the request method is not POST, return a 405 Method Not Allowed response
    return Response({'error': 'Method Not Allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def clear_chat(request):
    # Check if the request method is POST
    if request.method == 'POST':
        
        op = router.clear_chat()

        result = {
            "operation": "clear_chat",
            "status": "success" if op else "failed"
        }
        
        # Return the processed data as a JSON response
        return Response(result, status=status.HTTP_200_OK)
    
    # If the request method is not POST, return a 405 Method Not Allowed response
    return Response({'error': 'Method Not Allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@api_view(['GET'])
def get_models(request):
    # Check if the request method is GET
    if request.method != 'GET':
        return Response({'error': 'Method Not Allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    

    # Get the list of available models
    models = router.get_models()
    
    return Response(models, status=status.HTTP_200_OK)


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
