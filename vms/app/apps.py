from django.apps import AppConfig
from django.core.signals import setting_changed


class AppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app'

    def ready(self):
      import app.signals