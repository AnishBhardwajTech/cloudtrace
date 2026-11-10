package com.cloudtrace.store;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

/** Opens JDBC connections and creates the schema. */
public class Database {
    private final String url;
    private final String user;
    private final String password;

    public Database(String url, String user, String password) {
        this.url = url;
        this.user = user;
        this.password = password;
    }

    /** Reads CLOUDTRACE_DB_URL / _USER / _PASSWORD. */
    public static Database fromEnv() {
        String url = System.getenv().getOrDefault("CLOUDTRACE_DB_URL",
                "jdbc:mysql://localhost:3306/cloudtrace?serverTimezone=UTC");
        return new Database(url, System.getenv().getOrDefault("CLOUDTRACE_DB_USER", "cloudtrace"),
                System.getenv().getOrDefault("CLOUDTRACE_DB_PASSWORD", "cloudtrace"));
    }

    public Connection connect() throws SQLException {
        return DriverManager.getConnection(url, user, password);
    }

    public void initSchema() throws SQLException {
        String ddl;
        try (InputStream in = Database.class.getResourceAsStream("/schema.sql")) {
            ddl = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException | NullPointerException e) {
            throw new SQLException("schema.sql not found on classpath", e);
        }
        try (Connection c = connect(); Statement st = c.createStatement()) {
            for (String sql : ddl.replaceAll("(?m)^--.*$", "").split(";")) {
                if (sql.isBlank()) continue;
                try {
                    st.execute(sql);
                } catch (SQLException e) {
                    // CREATE INDEX has no IF NOT EXISTS in MySQL; ignore "already exists" on re-run
                    String m = String.valueOf(e.getMessage()).toLowerCase();
                    if (!(sql.trim().toUpperCase().startsWith("CREATE INDEX") && (m.contains("duplicate") || m.contains("exists")))) throw e;
                }
            }
        }
    }
}
