package com.cloudtrace.model;

public enum Severity {
    CRITICAL(4), HIGH(3), MEDIUM(2), LOW(1);

    private final int rank;
    Severity(int rank) { this.rank = rank; }
    public int rank() { return rank; }
}
