package com.cloudtrace.store;

import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.sql.Connection;
import java.sql.Statement;

/** Runs when CLOUDTRACE_TEST_MYSQL_URL is set (CI provides a MySQL 8 service container). */
@EnabledIfEnvironmentVariable(named = "CLOUDTRACE_TEST_MYSQL_URL", matches = ".+")
class MySqlRepositoryTest extends RepositoryContract {
    @Override
    protected Database database() throws Exception {
        Database db = new Database(System.getenv("CLOUDTRACE_TEST_MYSQL_URL"),
                System.getenv().getOrDefault("CLOUDTRACE_TEST_MYSQL_USER", "root"),
                System.getenv().getOrDefault("CLOUDTRACE_TEST_MYSQL_PASSWORD", "root"));
        try (Connection c = db.connect(); Statement st = c.createStatement()) {
            for (String t : new String[]{"custody_log", "findings", "evidence", "cases"}) st.execute("DROP TABLE IF EXISTS " + t);
        }
        return db;
    }
}
