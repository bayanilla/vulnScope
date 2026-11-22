"""model.sql and the correlator agree: every query asked for exists, none is left unused, every
fragment is filled, and each one is SQL that DuckDB can parse."""
import os
import re
import tempfile
import unittest

from vulnflow import correlate, db, sqlfile

HERE = os.path.dirname(__file__)


class ModelFile(unittest.TestCase):
    def test_used_and_defined_names_match(self):
        with open(correlate.__file__, encoding="utf-8") as fh:
            used = set(re.findall(r'MODEL\("([a-z0-9_]+)"\)', fh.read()))
        self.assertEqual(used, set(correlate.MODEL.names()))
        self.assertGreater(len(used), 10)

    def test_every_query_fills_and_parses(self):
        con = db.connect()
        for name in correlate.MODEL.names():
            sql = correlate.MODEL(name)
            self.assertNotIn("$", sql, name)
            self.assertEqual(len(con.extract_statements(sql)), 1, name)

    def test_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "m.sql")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("-- header, ignored\n\n-- name: one\n-- what it does\nSELECT $n AS n;\n\n-- name: two\nSELECT 2\n")
            self.assertEqual(sqlfile.load(path), {"one": "-- what it does\nSELECT $n AS n", "two": "SELECT 2"})
            model = sqlfile.Model(path, {"n": "7"})
            self.assertEqual(db.connect().execute(model("one")).fetchone(), (7,))
            with self.assertRaises(KeyError):
                model("three")
            with self.assertRaises(KeyError):
                sqlfile.Model(path, {})("one")
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("-- name: one\nSELECT 3\n")
            with self.assertRaises(ValueError):
                sqlfile.load(path)


if __name__ == "__main__":
    unittest.main()
