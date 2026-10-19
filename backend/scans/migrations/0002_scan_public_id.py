# Step 8a: public UUID on Scan (anti-enumeration, ISO-6.6).
# 1) add the column nullable, 2) fill every existing row, 3) make it unique.
import uuid

from django.db import migrations, models


def generate_public_ids(apps, schema_editor):
    """Fill public_id for every pre-existing scan (batched, no table rebuild).

    QuerySet.update() does NOT evaluate callables, so we assign uuid4()
    per row then bulk_update() in batches.
    """
    Scan = apps.get_model("scans", "Scan")
    scans = list(Scan.objects.filter(public_id__isnull=True))
    for scan in scans:
        scan.public_id = uuid.uuid4()
    if scans:
        Scan.objects.bulk_update(scans, ["public_id"], batch_size=500)


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="public_id",
            field=models.UUIDField(null=True, editable=False),
        ),
        migrations.RunPython(generate_public_ids, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="scan",
            name="public_id",
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
    ]
