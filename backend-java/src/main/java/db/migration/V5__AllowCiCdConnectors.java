package db.migration;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

/** Expand connector type checks without editing applied SQL migrations. */
public final class V5__AllowCiCdConnectors extends BaseJavaMigration {
    private static final List<String> TABLES = List.of(
            "pathguard_connector_enrollments", "pathguard_connectors", "pathguard_evidence_bundle");

    @Override
    public void migrate(Context context) throws Exception {
        Connection connection = context.getConnection();
        for (String table : TABLES) {
            List<String> existing = connectorTypeChecks(connection, table);
            if (existing.isEmpty()) {
                throw new SQLException("Connector type check was not found for " + table);
            }
            try (Statement statement = connection.createStatement()) {
                for (String constraint : existing) {
                    if (!constraint.matches("[A-Za-z0-9_]+")) {
                        throw new SQLException("Unexpected check constraint identifier");
                    }
                    statement.execute("ALTER TABLE " + table + " DROP CONSTRAINT \"" + constraint + "\"");
                }
                statement.execute("ALTER TABLE " + table + " ADD CONSTRAINT " + table
                        + "_connector_type_v5_check CHECK (connector_type IN ('AWS', 'ON_PREM', 'CI_CD'))");
            }
        }
    }

    private static List<String> connectorTypeChecks(Connection connection, String table) throws SQLException {
        if (connection.getMetaData().getDatabaseProductName().toLowerCase(java.util.Locale.ROOT)
                .contains("postgresql")) {
            return postgresChecks(connection, table);
        }
        String sql = """
                SELECT tc.constraint_name, cc.check_clause
                  FROM information_schema.table_constraints tc
                  JOIN information_schema.check_constraints cc
                    ON cc.constraint_catalog = tc.constraint_catalog
                   AND cc.constraint_schema = tc.constraint_schema
                   AND cc.constraint_name = tc.constraint_name
                 WHERE LOWER(tc.table_name) = ? AND tc.constraint_type = 'CHECK'
                """;
        List<String> result = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, table);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    if (rows.getString("check_clause").toLowerCase(java.util.Locale.ROOT)
                            .contains("connector_type")) {
                        result.add(rows.getString("constraint_name"));
                    }
                }
            }
        }
        return result;
    }

    private static List<String> postgresChecks(Connection connection, String table) throws SQLException {
        String sql = """
                SELECT c.conname, pg_get_constraintdef(c.oid) AS definition
                  FROM pg_constraint c
                 WHERE c.conrelid = CAST(? AS regclass) AND c.contype = 'c'
                """;
        List<String> result = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, table);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    if (rows.getString("definition").toLowerCase(java.util.Locale.ROOT)
                            .contains("connector_type")) {
                        result.add(rows.getString("conname"));
                    }
                }
            }
        }
        return result;
    }
}
