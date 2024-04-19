from django.urls import path, include
from django.views.generic import RedirectView
from .views import ObtainAuthToken, answer

urlpatterns = [
    path('token/', ObtainAuthToken.as_view(), name='api-token'),
    path('answer/', answer, name='answer'),

    # Catch-all URL pattern
    path('api/', RedirectView.as_view(url='token/')),  # Redirect to example endpoint
]
