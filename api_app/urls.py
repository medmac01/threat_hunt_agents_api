from django.urls import path, include
from django.views.generic import RedirectView
from .views import ObtainAuthToken, answer_v2, clear_chat, answer_v2_stream, get_models

urlpatterns = [
    path('token/', ObtainAuthToken.as_view(), name='api-token'),
    path('get_models/', get_models, name='get_models'),
    path('answer_v2/', answer_v2, name='answer_v2'),
    path('answer_v2_stream/', answer_v2_stream, name='answer_v2_stream'),
    path('clear_chat/', clear_chat, name='clear_chat'),

    # Catch-all URL pattern
    path('api/', RedirectView.as_view(url='token/')),  # Redirect to example endpoint
]
