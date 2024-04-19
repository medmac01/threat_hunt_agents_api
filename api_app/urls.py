from django.urls import path, include
from django.views.generic import RedirectView
from .views import ObtainAuthToken

urlpatterns = [
    path('token/', ObtainAuthToken.as_view(), name='api-token'),

    # Catch-all URL pattern
    path('api/', RedirectView.as_view(url='token/')),  # Redirect to example endpoint
]
