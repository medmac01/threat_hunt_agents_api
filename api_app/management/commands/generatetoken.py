from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from api_app.models import Token

class Command(BaseCommand):
    help = 'Generate authentication tokens for users'

    def handle(self, *args, **options):
        users = User.objects.all()
        for user in users:
            token, created = Token.objects.get_or_create(user=user)
            self.stdout.write(self.style.SUCCESS(f'Token generated for {user.username}: {token.key}'))