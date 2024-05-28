from django.urls import path, include
from django.views.generic import RedirectView
from .views import ObtainAuthToken, answer, answer_v2, clear_chat

urlpatterns = [
    path('token/', ObtainAuthToken.as_view(), name='api-token'),
    path('answer/', answer, name='answer'),
    path('answer_v2/', answer_v2, name='answer_v2'),
    path('clear/', clear_chat, name='clear_chat'),

    # Catch-all URL pattern
    path('api/', RedirectView.as_view(url='token/')),  # Redirect to example endpoint
]
