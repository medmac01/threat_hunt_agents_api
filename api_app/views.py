from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import time
from .agents import router, utils

from django.http import StreamingHttpResponse

def stream_response(data):
    """
    Streams the response of the agent.
    Parameters:
    data: (str) The input text to be processed by the agent.
    """
    streamer_agent = router.stream()
    print(type(streamer_agent))
    for token in streamer_agent.run(data):
        time.sleep(0.02)
        yield token


@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def answer_v2(request):

    # Check if the request method is POST
    if request.method == 'POST':
        # Get the data from the request body
        data = request.data
        llm = data.get('llm', 'codestral')
        new_chat = data.get('new_chat', False)

        # Perform the processing based on the received data
        results = router.invoke(data["query"], llm=llm, new_chat=new_chat)

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
def answer_v2_stream(request):

    # Check if the request method is POST
    if request.method == 'POST':
        # Get the data from the request body
        data = request.data

        return StreamingHttpResponse(stream_response(data["query"]), content_type='text/event-stream')
    
    # If the request method is not POST, return a 405 Method Not Allowed response
    return Response({'error': 'Method Not Allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)



@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def clear_chat(request):
    # Check if the request method is POST
    if request.method == 'POST':
        
        result = {
            "operation": "clear_chat",
            "status": "success" if router.clear() else "failed"
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
    models = utils.get_models()
    
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
