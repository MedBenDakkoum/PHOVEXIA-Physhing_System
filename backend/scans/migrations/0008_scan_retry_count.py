from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scans", "0007_scan_collected_at_scan_final_url_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="retry_count",
            field=models.PositiveSmallIntegerField(default=0, verbose_name="Retry count"),
        ),
    ]
