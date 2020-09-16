import json
from room_summarize import summary_builder
from insite_plugin import InsitePlugin


class Plugin(InsitePlugin):
    def can_group(self):
        return False

    def fetch(self, hosts):

        try:

            self.collector

        except Exception:

            from ThirtyRock_PROD_edge_def import ROOM_COLLECTION

            params = {"insite": "100.103.224.9", "annotate_db": ROOM_COLLECTION}

            self.collector = summary_builder(**params)

        return json.dumps(self.collector.process_summary())
