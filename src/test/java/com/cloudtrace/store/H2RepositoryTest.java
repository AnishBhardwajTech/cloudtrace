package com.cloudtrace.store;

import com.cloudtrace.TestData;

class H2RepositoryTest extends RepositoryContract {
    @Override
    protected Database database() {
        return TestData.h2();
    }
}
