import os
import unittest

os.environ["PAX_MEMORY_PATH"] = "/tmp/pax_test_memory.json"
os.environ["MONGO_URI"] = ""
os.environ["ENABLE_OMNISTATUS"] = "0"
os.environ["ENABLE_TELEGRAM"] = "0"

import server


FEATURE_PAYLOAD = {
    "prox": 70,
    "rssi": -51,
    "ies": "01-32-2D-7F-BF-DD",
    "rates": "82848B960C121824",
    "xrates": "3048606C",
    "vendors": "0050F2;506F9A",
    "extcaps": "00000880000000000000",
    "htcaps": "6F0113FF00000000",
    "vhtcaps": "31718003FEFF",
    "rsn": "0100000FAC040100000FAC04",
    "extids": "23",
    "probes": 5,
    "wildcards": 5,
    "channel": 6,
    "observed_channels": "1,6,11",
}


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        server.agente_memory = server.build_empty_memory()
        server.radar_data = {
            "pax": 0,
            "objetivos": [],
            "recent": [],
            "status": {},
        }
        self.client = server.app.test_client()

    def report(self, identifier):
        objective = dict(FEATURE_PAYLOAD, id=identifier)
        response = self.client.post(
            "/api/report",
            json={"pax": 1, "objetivos": [objective]},
        )
        self.assertEqual(response.status_code, 200)
        return server.radar_data["objetivos"][0]

    def test_version_is_exposed_by_status_api(self):
        response = self.client.get("/api/status")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["version"], "2.0.0")
        with open("VERSION", encoding="utf-8") as version_file:
            self.assertEqual(version_file.read().strip(), server.APP_VERSION)

    def test_known_alias_matches_immediately(self):
        first = self.report("001122334455")
        second = self.report("001122334455")

        self.assertEqual(first["pattern_id"], second["pattern_id"])
        self.assertTrue(second["recurrent"])
        self.assertEqual(second["score_pct"], 100)

    def test_new_global_mac_is_not_merged_by_fingerprint(self):
        first = self.report("001122334455")
        second = self.report("041122334455")

        self.assertNotEqual(first["pattern_id"], second["pattern_id"])
        self.assertEqual(len(server.agente_memory["entities"]), 2)

    def test_random_mac_requires_two_matching_reports(self):
        original = self.report("001122334455")
        pending = self.report("021122334455")

        self.assertEqual(original["pattern_id"], pending["pattern_id"])
        self.assertTrue(pending["association_pending"])
        self.assertNotIn(
            "021122334455",
            server.agente_memory["entities"][original["pattern_id"]]["aliases"],
        )

        confirmed = self.report("021122334455")
        self.assertFalse(confirmed["association_pending"])
        self.assertTrue(confirmed["rotated"])
        self.assertIn(
            "021122334455",
            server.agente_memory["entities"][original["pattern_id"]]["aliases"],
        )

    def test_ambiguous_fingerprint_is_not_associated(self):
        self.report("001122334455")
        self.report("041122334455")
        ambiguous = self.report("021122334455")

        self.assertFalse(ambiguous["association_pending"])
        self.assertEqual(len(server.agente_memory["entities"]), 3)

    def test_consensus_resists_one_outlier(self):
        sample_a = {"ies": "01-32", "rates": "8284"}
        sample_b = {"ies": "01-7F", "rates": "0C12"}

        consensus = server.consensus_features([sample_a, sample_a, sample_b])

        self.assertEqual(consensus["ies"], "01-32")
        self.assertEqual(consensus["rates"], "8284")

    def test_schema_two_memory_is_upgraded(self):
        upgraded = server.upgrade_memory({
            "schema_version": 2,
            "next_entity_seq": 2,
            "entities": {
                "PT-0001": {
                    "entity_id": "PT-0001",
                    "features": {"ies": "01-32", "rates": "8284"},
                }
            },
        })

        self.assertEqual(upgraded["schema_version"], 3)
        self.assertEqual(len(upgraded["entities"]["PT-0001"]["feature_samples"]), 1)
        self.assertEqual(upgraded["entities"]["PT-0001"]["features"]["ies"], "01-32")


if __name__ == "__main__":
    unittest.main()
