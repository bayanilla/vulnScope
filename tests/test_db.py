"""The DuckDB connection rules: no extension downloads, known-bad versions refused."""
import unittest

from vulnflow import db
from vulnflow.errors import UserError


class ConnectionRules(unittest.TestCase):
    def test_extensions_are_never_fetched(self):
        con = db.connect()
        settings = dict(con.execute(
            "SELECT name, value FROM duckdb_settings() WHERE name IN "
            "('autoinstall_known_extensions', 'autoload_known_extensions')").fetchall())
        self.assertEqual(settings, {"autoinstall_known_extensions": "false",
                                    "autoload_known_extensions": "false"})

    def test_an_extension_function_fails_instead_of_downloading(self):
        con = db.connect()
        with self.assertRaises(Exception):
            con.execute("SELECT host('10.0.0.1'::INET)")      # inet is not built in

    def test_bad_versions_are_refused(self):
        for bad in ("1.1.3", "1.3.0", "0.10.2"):
            with self.assertRaises(UserError, msg=bad):
                db.check_version(bad)
        for good in ("1.2.0", "1.3.1", "1.4.1", "1.5.6"):
            db.check_version(good)


if __name__ == "__main__":
    unittest.main()
