#include "KWay3SortTestTemplate.h"

using Fixture = KWay3SortTest<243>;

TEST_F(Fixture, SortTest) {
    RunKWay3SortTest<243>(this);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
